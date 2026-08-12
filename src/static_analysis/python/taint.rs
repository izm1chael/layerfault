use super::calls::ExecutionContext;
use super::limits::PythonAnalysisLimits;
use super::parser::LineIndex;
use super::symbols::SymbolTable;
use rustpython_parser::ast::{self, Constant, Expr, Ranged, Stmt, Suite};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TaintSourceKind {
    CredentialEnv { var_name: Option<String> },
    CredentialFile { file_path: String },
    SensitiveFile { file_path: String },
    UntrustedParameter { param_name: String },
    ModelMetadata { key: String },
    NetworkInput { target: String },
}

impl TaintSourceKind {
    pub fn is_high_confidence_secret(&self) -> bool {
        match self {
            Self::CredentialEnv { .. }
            | Self::CredentialFile { .. }
            | Self::SensitiveFile { .. } => true,
            Self::UntrustedParameter { .. }
            | Self::ModelMetadata { .. }
            | Self::NetworkInput { .. } => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TaintSinkKind {
    NetworkBodyQueryHeader { target: String, param: String },
    SocketSend { target: String },
    SubprocessCommand { target: String },
    DynamicCodeEval { target: String },
    NativeLibraryLoad { target: String },
    SensitiveFilesystemWrite { target: String },
    LoggingOutputLeak { target: String },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaintLabel {
    pub id: usize,
    pub source_kind: TaintSourceKind,
    pub source_expr: String,
    pub line: usize,
    pub column: usize,
    pub transformations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaintTransferStep {
    pub line: usize,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaintFlowFinding {
    pub source_kind: TaintSourceKind,
    pub source_expr: String,
    pub source_line: usize,
    pub transfer_steps: Vec<TaintTransferStep>,
    pub sink_kind: TaintSinkKind,
    pub sink_expr: String,
    pub sink_line: usize,
    pub execution_context: ExecutionContext,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaintAnalysisResult {
    pub flows: Vec<TaintFlowFinding>,
    pub incomplete: bool,
    pub incomplete_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TaintState {
    pub vars: BTreeMap<String, Vec<TaintLabel>>,
}

impl TaintState {
    pub fn get(&self, var_name: &str) -> Option<&Vec<TaintLabel>> {
        self.vars.get(var_name)
    }

    pub fn set(&mut self, var_name: String, labels: Vec<TaintLabel>, limit_per_val: usize) {
        if labels.is_empty() {
            self.vars.remove(&var_name);
        } else {
            let mut dedupped: Vec<TaintLabel> = Vec::new();
            for l in labels {
                if !dedupped.iter().any(|d| d.id == l.id) {
                    dedupped.push(l);
                }
            }
            dedupped.truncate(limit_per_val);
            self.vars.insert(var_name, dedupped);
        }
    }

    pub fn clear(&mut self, var_name: &str) {
        self.vars.remove(var_name);
    }

    pub fn merge(&mut self, other: &TaintState, limit_per_val: usize) {
        for (var, labels) in &other.vars {
            let mut combined = self.vars.get(var).cloned().unwrap_or_default();
            for l in labels {
                if !combined.iter().any(|d| d.id == l.id) {
                    combined.push(l.clone());
                }
            }
            combined.truncate(limit_per_val);
            self.vars.insert(var.clone(), combined);
        }
    }
}

pub struct TaintEngine<'a> {
    pub symbol_table: &'a SymbolTable,
    pub limits: &'a PythonAnalysisLimits,
    pub line_index: &'a LineIndex,
    pub is_auto_mapped: bool,
    next_label_id: usize,
    pub flows: Vec<TaintFlowFinding>,
    pub incomplete: bool,
    pub incomplete_reason: Option<String>,
    functions_visited: usize,
    state_merges: usize,
}

impl<'a> TaintEngine<'a> {
    pub fn new(
        symbol_table: &'a SymbolTable,
        limits: &'a PythonAnalysisLimits,
        line_index: &'a LineIndex,
        is_auto_mapped: bool,
    ) -> Self {
        Self {
            symbol_table,
            limits,
            line_index,
            is_auto_mapped,
            next_label_id: 1,
            flows: Vec::new(),
            incomplete: false,
            incomplete_reason: None,
            functions_visited: 0,
            state_merges: 0,
        }
    }

    pub fn analyze_suite(&mut self, suite: &Suite) -> TaintAnalysisResult {
        let mut global_state = TaintState::default();
        let call_stack = BTreeSet::new();
        self.process_suite(
            suite,
            &mut global_state,
            ExecutionContext::ModuleScope,
            &call_stack,
            0,
        );

        TaintAnalysisResult {
            flows: self.flows.clone(),
            incomplete: self.incomplete,
            incomplete_reason: self.incomplete_reason.clone(),
        }
    }

    fn mark_incomplete(&mut self, reason: impl Into<String>) {
        if !self.incomplete {
            self.incomplete = true;
            self.incomplete_reason = Some(reason.into());
        }
    }

    fn process_suite(
        &mut self,
        suite: &Suite,
        state: &mut TaintState,
        context: ExecutionContext,
        call_stack: &BTreeSet<String>,
        call_depth: usize,
    ) {
        for stmt in suite {
            if self.flows.len() >= self.limits.max_taint_flows_per_file {
                self.mark_incomplete("Max taint flows per file reached");
                break;
            }
            self.process_stmt(stmt, state, context, call_stack, call_depth);
        }
    }

    fn process_stmt(
        &mut self,
        stmt: &Stmt,
        state: &mut TaintState,
        context: ExecutionContext,
        call_stack: &BTreeSet<String>,
        call_depth: usize,
    ) {
        match stmt {
            Stmt::FunctionDef(f) => {
                let fn_name = f.name.as_str();
                let is_constructor = fn_name == "__init__" || fn_name == "__new__";
                let is_from_pretrained =
                    fn_name == "from_pretrained" || fn_name.contains("from_config");
                let is_model_init = fn_name == "forward" || fn_name == "__call__";

                let fn_context = if is_constructor {
                    ExecutionContext::Constructor
                } else if is_from_pretrained {
                    ExecutionContext::FromPretrainedLike
                } else if is_model_init {
                    ExecutionContext::ModelInitLike
                } else {
                    ExecutionContext::FunctionBody
                };

                self.functions_visited += 1;
                if self.functions_visited > self.limits.max_taint_functions_visited {
                    self.mark_incomplete("Max taint functions visited limit exceeded");
                }

                let mut fn_state = state.clone();
                let line = self.line_index.line_number(usize::from(f.range.start()));

                for arg in f
                    .args
                    .args
                    .iter()
                    .chain(f.args.posonlyargs.iter())
                    .chain(f.args.kwonlyargs.iter())
                {
                    let param_name = arg.def.arg.as_str().to_owned();
                    if param_name != "self" && param_name != "cls" {
                        let label = TaintLabel {
                            id: self.next_label_id,
                            source_kind: TaintSourceKind::UntrustedParameter {
                                param_name: param_name.clone(),
                            },
                            source_expr: format!("parameter '{}'", param_name),
                            line,
                            column: 1,
                            transformations: Vec::new(),
                        };
                        self.next_label_id += 1;
                        fn_state.set(
                            param_name,
                            vec![label],
                            self.limits.max_taint_labels_per_value,
                        );
                    }
                }

                self.process_suite(&f.body, &mut fn_state, fn_context, call_stack, call_depth);
            }
            Stmt::AsyncFunctionDef(f) => {
                let mut fn_state = state.clone();
                self.process_suite(
                    &f.body,
                    &mut fn_state,
                    ExecutionContext::FunctionBody,
                    call_stack,
                    call_depth,
                );
            }
            Stmt::ClassDef(c) => {
                self.process_suite(
                    &c.body,
                    state,
                    ExecutionContext::ClassBody,
                    call_stack,
                    call_depth,
                );
            }
            Stmt::Assign(a) => {
                let (rhs_labels, rhs_sinks) =
                    self.eval_expr(&a.value, state, context, call_stack, call_depth);
                self.check_and_record_sinks(&rhs_sinks, &a.value, context);

                let is_constant_clean = is_clean_constant(&a.value);
                let line = self.line_index.line_number(usize::from(a.range.start()));

                for target in &a.targets {
                    self.assign_to_target(
                        target,
                        rhs_labels.clone(),
                        is_constant_clean,
                        line,
                        state,
                    );
                }
            }
            Stmt::AugAssign(a) => {
                let (rhs_labels, rhs_sinks) =
                    self.eval_expr(&a.value, state, context, call_stack, call_depth);
                self.check_and_record_sinks(&rhs_sinks, &a.value, context);

                let line = self.line_index.line_number(usize::from(a.range.start()));
                if let Expr::Name(n) = &*a.target {
                    let var_name = n.id.as_str().to_owned();
                    let mut existing = state.get(&var_name).cloned().unwrap_or_default();
                    for l in rhs_labels {
                        if !existing.iter().any(|e| e.id == l.id) {
                            existing.push(l);
                        }
                    }
                    existing.truncate(self.limits.max_taint_labels_per_value);
                    state.set(var_name, existing, self.limits.max_taint_labels_per_value);
                } else {
                    self.assign_to_target(&a.target, rhs_labels, false, line, state);
                }
            }
            Stmt::AnnAssign(a) => {
                if let Some(val) = &a.value {
                    let (rhs_labels, rhs_sinks) =
                        self.eval_expr(val, state, context, call_stack, call_depth);
                    self.check_and_record_sinks(&rhs_sinks, val, context);

                    let is_constant_clean = is_clean_constant(val);
                    let line = self.line_index.line_number(usize::from(a.range.start()));
                    self.assign_to_target(&a.target, rhs_labels, is_constant_clean, line, state);
                }
            }
            Stmt::Expr(e) => {
                let (_, sinks) = self.eval_expr(&e.value, state, context, call_stack, call_depth);
                self.check_and_record_sinks(&sinks, &e.value, context);
            }
            Stmt::If(i) => {
                let (_, test_sinks) =
                    self.eval_expr(&i.test, state, context, call_stack, call_depth);
                self.check_and_record_sinks(&test_sinks, &i.test, context);

                let mut then_state = state.clone();
                let mut else_state = state.clone();

                self.process_suite(&i.body, &mut then_state, context, call_stack, call_depth);
                self.process_suite(&i.orelse, &mut else_state, context, call_stack, call_depth);

                self.state_merges += 1;
                if self.state_merges > self.limits.max_taint_state_merges {
                    self.mark_incomplete("Max taint state merges exceeded");
                }

                *state = then_state;
                state.merge(&else_state, self.limits.max_taint_labels_per_value);
            }
            Stmt::For(f) => {
                let (iter_labels, iter_sinks) =
                    self.eval_expr(&f.iter, state, context, call_stack, call_depth);
                self.check_and_record_sinks(&iter_sinks, &f.iter, context);

                let line = self.line_index.line_number(usize::from(f.range.start()));
                let mut loop_state = state.clone();
                self.assign_to_target(&f.target, iter_labels, false, line, &mut loop_state);
                self.process_suite(&f.body, &mut loop_state, context, call_stack, call_depth);
                self.process_suite(&f.orelse, &mut loop_state, context, call_stack, call_depth);

                state.merge(&loop_state, self.limits.max_taint_labels_per_value);
            }
            Stmt::While(w) => {
                let (_, test_sinks) =
                    self.eval_expr(&w.test, state, context, call_stack, call_depth);
                self.check_and_record_sinks(&test_sinks, &w.test, context);

                let mut loop_state = state.clone();
                self.process_suite(&w.body, &mut loop_state, context, call_stack, call_depth);
                self.process_suite(&w.orelse, &mut loop_state, context, call_stack, call_depth);

                state.merge(&loop_state, self.limits.max_taint_labels_per_value);
            }
            Stmt::With(w) => {
                for item in &w.items {
                    let (ctx_labels, ctx_sinks) =
                        self.eval_expr(&item.context_expr, state, context, call_stack, call_depth);
                    self.check_and_record_sinks(&ctx_sinks, &item.context_expr, context);

                    if let Some(vars) = &item.optional_vars {
                        let line = self
                            .line_index
                            .line_number(usize::from(item.context_expr.range().start()));
                        self.assign_to_target(vars, ctx_labels, false, line, state);
                    }
                }
                self.process_suite(&w.body, state, context, call_stack, call_depth);
            }
            Stmt::Try(t) => {
                let mut body_state = state.clone();
                self.process_suite(&t.body, &mut body_state, context, call_stack, call_depth);

                for handler in &t.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    let mut h_state = state.clone();
                    if let Some(name) = &h.name {
                        h_state.set(
                            name.as_str().to_owned(),
                            Vec::new(),
                            self.limits.max_taint_labels_per_value,
                        );
                    }
                    self.process_suite(&h.body, &mut h_state, context, call_stack, call_depth);
                    body_state.merge(&h_state, self.limits.max_taint_labels_per_value);
                }

                self.process_suite(&t.orelse, &mut body_state, context, call_stack, call_depth);
                self.process_suite(
                    &t.finalbody,
                    &mut body_state,
                    context,
                    call_stack,
                    call_depth,
                );

                *state = body_state;
            }
            Stmt::Return(r) => {
                if let Some(val) = &r.value {
                    let (ret_labels, ret_sinks) =
                        self.eval_expr(val, state, context, call_stack, call_depth);
                    self.check_and_record_sinks(&ret_sinks, val, context);
                    state.set(
                        "<return>".to_owned(),
                        ret_labels,
                        self.limits.max_taint_labels_per_value,
                    );
                }
            }
            _ => {}
        }
    }

    fn assign_to_target(
        &mut self,
        target: &Expr,
        labels: Vec<TaintLabel>,
        is_clean_constant: bool,
        line: usize,
        state: &mut TaintState,
    ) {
        match target {
            Expr::Name(n) => {
                let var_name = n.id.as_str().to_owned();
                if is_clean_constant {
                    state.clear(&var_name);
                } else {
                    let updated_labels: Vec<TaintLabel> = labels
                        .into_iter()
                        .map(|mut l| {
                            l.transformations
                                .push(format!("assigned to '{}' at L{}", var_name, line));
                            l
                        })
                        .collect();
                    state.set(
                        var_name,
                        updated_labels,
                        self.limits.max_taint_labels_per_value,
                    );
                }
            }
            Expr::Tuple(t) => {
                for el in &t.elts {
                    self.assign_to_target(el, labels.clone(), is_clean_constant, line, state);
                }
            }
            Expr::List(l) => {
                for el in &l.elts {
                    self.assign_to_target(el, labels.clone(), is_clean_constant, line, state);
                }
            }
            Expr::Subscript(s) => {
                if let Expr::Name(n) = &*s.value {
                    let var_name = n.id.as_str().to_owned();
                    if !is_clean_constant {
                        let mut existing = state.get(&var_name).cloned().unwrap_or_default();
                        for l in labels {
                            if !existing.iter().any(|e| e.id == l.id) {
                                existing.push(l);
                            }
                        }
                        existing.truncate(self.limits.max_taint_labels_per_value);
                        state.set(var_name, existing, self.limits.max_taint_labels_per_value);
                    }
                }
            }
            Expr::Attribute(a) => {
                if let Expr::Name(n) = &*a.value {
                    let var_name = n.id.as_str().to_owned();
                    if !is_clean_constant {
                        let mut existing = state.get(&var_name).cloned().unwrap_or_default();
                        for l in labels {
                            if !existing.iter().any(|e| e.id == l.id) {
                                existing.push(l);
                            }
                        }
                        existing.truncate(self.limits.max_taint_labels_per_value);
                        state.set(var_name, existing, self.limits.max_taint_labels_per_value);
                    }
                }
            }
            _ => {}
        }
    }

    fn eval_expr(
        &mut self,
        expr: &Expr,
        state: &TaintState,
        context: ExecutionContext,
        call_stack: &BTreeSet<String>,
        call_depth: usize,
    ) -> (Vec<TaintLabel>, Vec<(SinkCandidate, Vec<TaintLabel>)>) {
        let mut labels = Vec::new();
        let mut sinks = Vec::new();
        let line = self
            .line_index
            .line_number(usize::from(expr.range().start()));
        let col = 1;

        match expr {
            Expr::Name(n) => {
                if let Some(var_labels) = state.get(n.id.as_str()) {
                    labels.extend(var_labels.clone());
                }
            }
            Expr::Constant(_) => {
                // Constants carry no taint
            }
            Expr::JoinedStr(j) => {
                for val in &j.values {
                    let (v_labels, v_sinks) =
                        self.eval_expr(val, state, context, call_stack, call_depth);
                    sinks.extend(v_sinks);
                    for mut l in v_labels {
                        l.transformations
                            .push(format!("f-string interpolation at L{}", line));
                        labels.push(l);
                    }
                }
            }
            Expr::FormattedValue(f) => {
                let (v_labels, v_sinks) =
                    self.eval_expr(&f.value, state, context, call_stack, call_depth);
                sinks.extend(v_sinks);
                labels.extend(v_labels);
            }
            Expr::BinOp(b) => {
                let (l_labels, l_sinks) =
                    self.eval_expr(&b.left, state, context, call_stack, call_depth);
                let (r_labels, r_sinks) =
                    self.eval_expr(&b.right, state, context, call_stack, call_depth);
                sinks.extend(l_sinks);
                sinks.extend(r_sinks);

                for mut l in l_labels {
                    l.transformations.push(format!("binary op at L{}", line));
                    labels.push(l);
                }
                for mut l in r_labels {
                    l.transformations.push(format!("binary op at L{}", line));
                    labels.push(l);
                }
            }
            Expr::List(l) => {
                for el in &l.elts {
                    let (e_labels, e_sinks) =
                        self.eval_expr(el, state, context, call_stack, call_depth);
                    sinks.extend(e_sinks);
                    for mut lbl in e_labels {
                        lbl.transformations
                            .push(format!("list propagation at L{}", line));
                        labels.push(lbl);
                    }
                }
            }
            Expr::Tuple(t) => {
                for el in &t.elts {
                    let (e_labels, e_sinks) =
                        self.eval_expr(el, state, context, call_stack, call_depth);
                    sinks.extend(e_sinks);
                    for mut lbl in e_labels {
                        lbl.transformations
                            .push(format!("tuple propagation at L{}", line));
                        labels.push(lbl);
                    }
                }
            }
            Expr::Dict(d) => {
                for val in &d.values {
                    let (v_labels, v_sinks) =
                        self.eval_expr(val, state, context, call_stack, call_depth);
                    sinks.extend(v_sinks);
                    for mut lbl in v_labels {
                        lbl.transformations
                            .push(format!("dict propagation at L{}", line));
                        labels.push(lbl);
                    }
                }
            }
            Expr::Subscript(s) => {
                let (v_labels, v_sinks) =
                    self.eval_expr(&s.value, state, context, call_stack, call_depth);
                sinks.extend(v_sinks);

                if let Some(src_kind) = self.check_subscript_source(s) {
                    let src_expr = sanitize_expr_for_evidence(&expr_to_string(expr));
                    let label = TaintLabel {
                        id: self.next_label_id,
                        source_kind: src_kind,
                        source_expr: src_expr,
                        line,
                        column: col,
                        transformations: Vec::new(),
                    };
                    self.next_label_id += 1;
                    labels.push(label);
                } else {
                    labels.extend(v_labels);
                }
            }
            Expr::IfExp(i) => {
                let (_, test_sinks) =
                    self.eval_expr(&i.test, state, context, call_stack, call_depth);
                sinks.extend(test_sinks);
                let (b_labels, b_sinks) =
                    self.eval_expr(&i.body, state, context, call_stack, call_depth);
                sinks.extend(b_sinks);
                let (o_labels, o_sinks) =
                    self.eval_expr(&i.orelse, state, context, call_stack, call_depth);
                sinks.extend(o_sinks);

                labels.extend(b_labels);
                labels.extend(o_labels);
            }
            Expr::Attribute(a) => {
                let (v_labels, v_sinks) =
                    self.eval_expr(&a.value, state, context, call_stack, call_depth);
                sinks.extend(v_sinks);
                labels.extend(v_labels);
            }
            Expr::Call(c) => {
                let (call_labels, call_sinks) =
                    self.eval_call(c, state, context, call_stack, call_depth, line, col);
                labels.extend(call_labels);
                sinks.extend(call_sinks);
            }
            _ => {}
        }

        labels.truncate(self.limits.max_taint_labels_per_value);
        (labels, sinks)
    }

    fn check_subscript_source(&self, s: &ast::ExprSubscript) -> Option<TaintSourceKind> {
        let base = expr_to_string(&s.value);
        let resolved = self
            .symbol_table
            .resolve_full_target(&base)
            .unwrap_or(base.clone());

        if resolved == "os.environ" || base == "os.environ" {
            let key = match &*s.slice {
                Expr::Constant(c) => match &c.value {
                    Constant::Str(s) => Some(s.as_str().to_owned()),
                    _ => None,
                },
                _ => None,
            };
            return Some(TaintSourceKind::CredentialEnv { var_name: key });
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_call(
        &mut self,
        c: &ast::ExprCall,
        state: &TaintState,
        context: ExecutionContext,
        call_stack: &BTreeSet<String>,
        call_depth: usize,
        line: usize,
        col: usize,
    ) -> (Vec<TaintLabel>, Vec<(SinkCandidate, Vec<TaintLabel>)>) {
        let mut labels = Vec::new();
        let mut sinks = Vec::new();

        let func_str = expr_to_string(&c.func);
        let resolved_target = self
            .symbol_table
            .resolve_full_target(&func_str)
            .unwrap_or_else(|| func_str.clone());

        let (func_labels, func_sinks) =
            self.eval_expr(&c.func, state, context, call_stack, call_depth);
        sinks.extend(func_sinks);

        let mut arg_labels_list = Vec::new();
        for arg in &c.args {
            let (a_labels, a_sinks) = self.eval_expr(arg, state, context, call_stack, call_depth);
            sinks.extend(a_sinks);
            arg_labels_list.push(a_labels);
        }

        let mut kw_labels_map = BTreeMap::new();
        for kw in &c.keywords {
            let (k_labels, k_sinks) =
                self.eval_expr(&kw.value, state, context, call_stack, call_depth);
            sinks.extend(k_sinks);
            if let Some(arg_name) = &kw.arg {
                kw_labels_map.insert(arg_name.as_str().to_owned(), k_labels);
            }
        }

        let all_arg_labels: Vec<TaintLabel> = func_labels
            .iter()
            .chain(arg_labels_list.iter().flatten())
            .chain(kw_labels_map.values().flatten())
            .cloned()
            .collect();

        // Method call on a tainted receiver object propagates taint
        for mut l in func_labels {
            l.transformations
                .push(format!("method call '{}' at L{}", func_str, line));
            labels.push(l);
        }

        // 1. Check if call is a Taint Source
        if let Some(source_kind) =
            self.check_call_source(&func_str, &resolved_target, c, &all_arg_labels)
        {
            let label = TaintLabel {
                id: self.next_label_id,
                source_kind,
                source_expr: sanitize_expr_for_evidence(&format!("{}(...)", resolved_target)),
                line,
                column: col,
                transformations: Vec::new(),
            };
            self.next_label_id += 1;
            labels.push(label);
        }

        // 2. Check if call is a Taint Sink candidate
        if let Some(sink_candidate) = self.check_call_sink(&func_str, &resolved_target, c) {
            if !all_arg_labels.is_empty() {
                sinks.push((sink_candidate, all_arg_labels.clone()));
            }
        }

        // 3. Transformations / Sanitizers (e.g. hashlib, base64, str.format)
        if resolved_target.contains("hashlib")
            || resolved_target.contains("b64encode")
            || resolved_target.contains("sha256")
        {
            for mut l in all_arg_labels.clone() {
                l.transformations
                    .push(format!("transformation '{}' at L{}", resolved_target, line));
                labels.push(l);
            }
        } else if func_str == "format" || resolved_target.ends_with(".format") {
            for mut l in all_arg_labels.clone() {
                l.transformations.push(format!("format call at L{}", line));
                labels.push(l);
            }
        }

        // 4. Inter-procedural propagation limit checks
        let is_known = self.symbol_table.imports.contains_key(&func_str)
            || self
                .symbol_table
                .definitions
                .iter()
                .any(|d| d.name == func_str)
            || is_builtin_func(&func_str, &resolved_target);

        let is_dynamic = !is_known
            || func_str.contains("(")
            || func_str.contains("getattr")
            || func_str.contains("self.");

        if call_depth < self.limits.max_taint_call_depth
            && !all_arg_labels.is_empty()
            && !call_stack.contains(&func_str)
        {
            if is_dynamic {
                self.mark_incomplete(format!(
                    "Dynamic function dispatch '{}' at line {}",
                    func_str, line
                ));
            }
        } else if call_stack.contains(&func_str) {
            self.mark_incomplete(format!(
                "Recursion cycle detected for '{}' at line {}",
                func_str, line
            ));
        } else if call_depth >= self.limits.max_taint_call_depth && !all_arg_labels.is_empty() {
            self.mark_incomplete(format!(
                "Max taint call depth ({}) exceeded at line {}",
                self.limits.max_taint_call_depth, line
            ));
        }

        (labels, sinks)
    }

    fn check_call_source(
        &self,
        func_str: &str,
        resolved_target: &str,
        c: &ast::ExprCall,
        arg_labels: &[TaintLabel],
    ) -> Option<TaintSourceKind> {
        if resolved_target == "os.getenv"
            || resolved_target == "os.environ.get"
            || func_str == "os.getenv"
        {
            let var_name = c.args.first().and_then(|a| match a {
                Expr::Constant(c) => match &c.value {
                    Constant::Str(s) => Some(s.as_str().to_owned()),
                    _ => None,
                },
                _ => None,
            });
            return Some(TaintSourceKind::CredentialEnv { var_name });
        }

        if resolved_target == "open"
            || func_str == "open"
            || resolved_target.ends_with(".read_text")
            || resolved_target.ends_with(".read_bytes")
        {
            if let Some(Expr::Constant(cnst)) = c.args.first() {
                if let Constant::Str(s) = &cnst.value {
                    let path = s.as_str();
                    if path.contains(".ssh/")
                        || path.contains(".aws/")
                        || path.ends_with(".env")
                        || path.contains("id_rsa")
                        || path.contains("credentials")
                    {
                        return Some(TaintSourceKind::CredentialFile {
                            file_path: path.to_owned(),
                        });
                    } else if path.starts_with("/etc/passwd") || path.starts_with("/etc/shadow") {
                        return Some(TaintSourceKind::SensitiveFile {
                            file_path: path.to_owned(),
                        });
                    }
                }
            }
        }

        if (resolved_target.starts_with("requests.")
            || resolved_target.starts_with("urllib.request.")
            || resolved_target.starts_with("httpx.")
            || resolved_target.contains("socket.recv"))
            && arg_labels.is_empty()
            && (resolved_target.contains("get")
                || resolved_target.contains("recv")
                || resolved_target.contains("urlopen"))
        {
            return Some(TaintSourceKind::NetworkInput {
                target: resolved_target.to_owned(),
            });
        }

        None
    }

    fn check_call_sink(
        &self,
        func_str: &str,
        resolved_target: &str,
        c: &ast::ExprCall,
    ) -> Option<SinkCandidate> {
        let line = self.line_index.line_number(usize::from(c.range.start()));

        if resolved_target.starts_with("requests.post")
            || resolved_target.starts_with("requests.get")
            || resolved_target.starts_with("requests.put")
            || resolved_target.starts_with("requests.request")
            || resolved_target.starts_with("urllib.request.urlopen")
            || resolved_target.starts_with("httpx.post")
            || resolved_target.starts_with("httpx.get")
            || resolved_target.starts_with("aiohttp.")
        {
            return Some(SinkCandidate {
                kind: TaintSinkKind::NetworkBodyQueryHeader {
                    target: resolved_target.to_owned(),
                    param: "data/headers".to_owned(),
                },
                expr: sanitize_expr_for_evidence(&format!("{}(...)", resolved_target)),
                line,
            });
        }

        if resolved_target.contains("socket.send")
            || resolved_target.ends_with(".send")
            || resolved_target.contains("sendall")
            || resolved_target.contains("sendto")
        {
            return Some(SinkCandidate {
                kind: TaintSinkKind::SocketSend {
                    target: resolved_target.to_owned(),
                },
                expr: sanitize_expr_for_evidence(&format!("{}(...)", resolved_target)),
                line,
            });
        }

        if resolved_target.starts_with("subprocess.")
            || resolved_target == "os.system"
            || resolved_target == "os.popen"
            || resolved_target.starts_with("os.exec")
        {
            return Some(SinkCandidate {
                kind: TaintSinkKind::SubprocessCommand {
                    target: resolved_target.to_owned(),
                },
                expr: sanitize_expr_for_evidence(&format!("{}(...)", resolved_target)),
                line,
            });
        }

        if resolved_target == "eval"
            || resolved_target == "exec"
            || resolved_target == "compile"
            || func_str == "eval"
            || func_str == "exec"
        {
            return Some(SinkCandidate {
                kind: TaintSinkKind::DynamicCodeEval {
                    target: resolved_target.to_owned(),
                },
                expr: sanitize_expr_for_evidence(&format!("{}(...)", resolved_target)),
                line,
            });
        }

        if resolved_target.starts_with("ctypes.")
            || resolved_target.contains("CDLL")
            || resolved_target.contains("dlopen")
        {
            return Some(SinkCandidate {
                kind: TaintSinkKind::NativeLibraryLoad {
                    target: resolved_target.to_owned(),
                },
                expr: sanitize_expr_for_evidence(&format!("{}(...)", resolved_target)),
                line,
            });
        }

        if resolved_target.ends_with(".write")
            || resolved_target.ends_with(".write_text")
            || resolved_target.ends_with(".write_bytes")
        {
            return Some(SinkCandidate {
                kind: TaintSinkKind::SensitiveFilesystemWrite {
                    target: resolved_target.to_owned(),
                },
                expr: sanitize_expr_for_evidence(&format!("{}(...)", resolved_target)),
                line,
            });
        }

        None
    }

    fn check_and_record_sinks(
        &mut self,
        sinks: &[(SinkCandidate, Vec<TaintLabel>)],
        _expr: &Expr,
        context: ExecutionContext,
    ) {
        for (candidate, labels) in sinks {
            for label in labels {
                let flow = TaintFlowFinding {
                    source_kind: label.source_kind.clone(),
                    source_expr: label.source_expr.clone(),
                    source_line: label.line,
                    transfer_steps: label
                        .transformations
                        .iter()
                        .map(|t| TaintTransferStep {
                            line: label.line,
                            description: t.clone(),
                        })
                        .collect(),
                    sink_kind: candidate.kind.clone(),
                    sink_expr: candidate.expr.clone(),
                    sink_line: candidate.line,
                    execution_context: context,
                };

                if !self.flows.iter().any(|f| {
                    f.source_line == flow.source_line
                        && f.sink_line == flow.sink_line
                        && f.sink_expr == flow.sink_expr
                }) {
                    self.flows.push(flow);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct SinkCandidate {
    kind: TaintSinkKind,
    expr: String,
    line: usize,
}

fn is_clean_constant(expr: &Expr) -> bool {
    match expr {
        Expr::Constant(c) => matches!(
            &c.value,
            Constant::Str(_)
                | Constant::Int(_)
                | Constant::Float(_)
                | Constant::Bool(_)
                | Constant::None
        ),
        _ => false,
    }
}

fn expr_to_string(expr: &Expr) -> String {
    match expr {
        Expr::Name(n) => n.id.as_str().to_owned(),
        Expr::Attribute(a) => format!("{}.{}", expr_to_string(&a.value), a.attr.as_str()),
        Expr::Constant(c) => match &c.value {
            Constant::Str(s) => format!("\"{}\"", s.as_str()),
            Constant::Int(i) => i.to_string(),
            Constant::Bool(b) => b.to_string(),
            _ => "<const>".to_owned(),
        },
        Expr::Call(c) => format!("{}(...)", expr_to_string(&c.func)),
        Expr::Subscript(s) => format!("{}[...]", expr_to_string(&s.value)),
        _ => "<expr>".to_owned(),
    }
}

fn sanitize_expr_for_evidence(expr: &str) -> String {
    let redacted = expr
        .replace("Bearer ", "Bearer [REDACTED]")
        .replace("sk-", "[REDACTED_KEY]-");
    if redacted.len() > 256 {
        format!("{}...", &redacted[..256])
    } else {
        redacted
    }
}

fn is_builtin_func(func_str: &str, resolved_target: &str) -> bool {
    let known = [
        "open",
        "eval",
        "exec",
        "compile",
        "print",
        "len",
        "str",
        "int",
        "float",
        "dict",
        "list",
        "set",
        "tuple",
        "bytes",
        "range",
        "type",
        "isinstance",
        "super",
        "hasattr",
        "getattr",
        "setattr",
        "read",
        "read_text",
        "read_bytes",
        "write",
        "write_text",
        "write_bytes",
        "format",
    ];
    if known.contains(&func_str) || known.contains(&resolved_target) {
        return true;
    }
    resolved_target.starts_with("os.")
        || resolved_target.starts_with("requests.")
        || resolved_target.starts_with("socket.")
        || resolved_target.starts_with("subprocess.")
        || resolved_target.starts_with("urllib.")
        || resolved_target.starts_with("httpx.")
        || resolved_target.starts_with("ctypes.")
        || resolved_target.starts_with("hashlib.")
}
