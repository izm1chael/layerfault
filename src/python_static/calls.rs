use super::limits::PythonAnalysisLimits;
use super::parser::LineIndex;
use super::symbols::SymbolTable;
use rustpython_parser::ast::{self, Expr, ExprCall, Stmt, Suite};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PythonCapabilityCategory {
    ProcessExecution,
    DynamicCodeEvaluation,
    NativeLibraryLoading,
    NetworkAccess,
    CredentialEnvironmentAccess,
    FilesystemMutation,
    PackageInstallationCodeAcquisition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExecutionContext {
    ModuleScope,
    ClassBody,
    FunctionBody,
    Constructor,
    FromPretrainedLike,
    ModelInitLike,
    ImportHook,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CallSite {
    pub raw_target: String,
    pub resolved_target: String,
    pub category: PythonCapabilityCategory,
    pub execution_context: ExecutionContext,
    pub line: Option<usize>,
    pub executable_name: Option<String>,
    pub shell_mode: bool,
    pub literal_arg_evidence: Option<String>,
    pub reflection_resolved: bool,
}

pub struct CallSiteExtractor<'a> {
    pub symbol_table: &'a SymbolTable,
    pub limits: &'a PythonAnalysisLimits,
    pub line_index: &'a LineIndex,
    pub call_sites: Vec<CallSite>,
}

impl<'a> CallSiteExtractor<'a> {
    pub fn new(
        symbol_table: &'a SymbolTable,
        limits: &'a PythonAnalysisLimits,
        line_index: &'a LineIndex,
    ) -> Self {
        Self {
            symbol_table,
            limits,
            line_index,
            call_sites: Vec::new(),
        }
    }

    pub fn extract_suite(&mut self, suite: &Suite, context: ExecutionContext) {
        for stmt in suite {
            self.extract_stmt(stmt, context);
            if self.call_sites.len() >= self.limits.max_call_sites {
                break;
            }
        }
    }

    pub fn extract_stmt(&mut self, stmt: &Stmt, context: ExecutionContext) {
        if self.call_sites.len() >= self.limits.max_call_sites {
            return;
        }

        match stmt {
            Stmt::FunctionDef(f) => {
                let is_constructor = f.name.as_str() == "__init__" || f.name.as_str() == "__new__";
                let is_from_pretrained =
                    f.name.as_str() == "from_pretrained" || f.name.as_str().contains("from_config");
                let is_model_init = f.name.as_str() == "forward" || f.name.as_str() == "__call__";

                let fn_context = if is_constructor {
                    ExecutionContext::Constructor
                } else if is_from_pretrained {
                    ExecutionContext::FromPretrainedLike
                } else if is_model_init {
                    ExecutionContext::ModelInitLike
                } else {
                    ExecutionContext::FunctionBody
                };

                self.extract_suite(&f.body, fn_context);
            }
            Stmt::AsyncFunctionDef(f) => {
                self.extract_suite(&f.body, ExecutionContext::FunctionBody);
            }
            Stmt::ClassDef(c) => {
                self.extract_suite(&c.body, ExecutionContext::ClassBody);
            }
            Stmt::Expr(e) => {
                self.extract_expr(&e.value, context);
            }
            Stmt::Assign(a) => {
                self.extract_expr(&a.value, context);
            }
            Stmt::AugAssign(a) => {
                self.extract_expr(&a.value, context);
            }
            Stmt::AnnAssign(a) => {
                if let Some(val) = &a.value {
                    self.extract_expr(val, context);
                }
            }
            Stmt::If(i) => {
                self.extract_expr(&i.test, context);
                self.extract_suite(&i.body, context);
                self.extract_suite(&i.orelse, context);
            }
            Stmt::For(f) => {
                self.extract_expr(&f.iter, context);
                self.extract_suite(&f.body, context);
                self.extract_suite(&f.orelse, context);
            }
            Stmt::While(w) => {
                self.extract_expr(&w.test, context);
                self.extract_suite(&w.body, context);
                self.extract_suite(&w.orelse, context);
            }
            Stmt::With(w) => {
                for item in &w.items {
                    self.extract_expr(&item.context_expr, context);
                }
                self.extract_suite(&w.body, context);
            }
            Stmt::Try(t) => {
                self.extract_suite(&t.body, context);
                for handler in &t.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    self.extract_suite(&h.body, context);
                }
                self.extract_suite(&t.orelse, context);
                self.extract_suite(&t.finalbody, context);
            }
            Stmt::Return(r) => {
                if let Some(val) = &r.value {
                    self.extract_expr(val, context);
                }
            }
            _ => {}
        }
    }

    pub fn extract_expr(&mut self, expr: &Expr, context: ExecutionContext) {
        if self.call_sites.len() >= self.limits.max_call_sites {
            return;
        }

        match expr {
            Expr::Call(c) => {
                self.inspect_call(c, context);
                self.extract_expr(&c.func, context);
                for arg in &c.args {
                    self.extract_expr(arg, context);
                }
                for kw in &c.keywords {
                    self.extract_expr(&kw.value, context);
                }
            }
            Expr::Attribute(a) => {
                self.extract_expr(&a.value, context);
            }
            Expr::Subscript(s) => {
                self.extract_expr(&s.value, context);
                self.extract_expr(&s.slice, context);
            }
            Expr::BoolOp(b) => {
                for val in &b.values {
                    self.extract_expr(val, context);
                }
            }
            Expr::BinOp(b) => {
                self.extract_expr(&b.left, context);
                self.extract_expr(&b.right, context);
            }
            Expr::UnaryOp(u) => {
                self.extract_expr(&u.operand, context);
            }
            Expr::IfExp(i) => {
                self.extract_expr(&i.test, context);
                self.extract_expr(&i.body, context);
                self.extract_expr(&i.orelse, context);
            }
            Expr::Dict(d) => {
                for key in d.keys.iter().flatten() {
                    self.extract_expr(key, context);
                }
                for val in &d.values {
                    self.extract_expr(val, context);
                }
            }
            Expr::List(l) => {
                for el in &l.elts {
                    self.extract_expr(el, context);
                }
            }
            Expr::Tuple(t) => {
                for el in &t.elts {
                    self.extract_expr(el, context);
                }
            }
            _ => {}
        }
    }

    fn inspect_call(&mut self, call: &ExprCall, context: ExecutionContext) {
        let (raw_target, resolved_target, reflection_resolved) =
            self.resolve_call_target(&call.func);
        if raw_target.is_empty() && resolved_target.is_empty() {
            return;
        }

        let target_to_check = if !resolved_target.is_empty() {
            &resolved_target
        } else {
            &raw_target
        };

        if let Some(category) = classify_target_capability(target_to_check) {
            let line = self.line_index.line_number(usize::from(call.range.start()));
            let (executable_name, shell_mode, literal_arg_evidence) =
                extract_call_evidence(call, self.limits.max_string_literal_bytes);

            let category = if let Some(ref exe) = executable_name {
                if is_install_tool(exe) {
                    PythonCapabilityCategory::PackageInstallationCodeAcquisition
                } else {
                    category
                }
            } else {
                category
            };

            self.call_sites.push(CallSite {
                raw_target,
                resolved_target,
                category,
                execution_context: context,
                line: Some(line),
                executable_name,
                shell_mode,
                literal_arg_evidence,
                reflection_resolved,
            });
        }
    }

    fn resolve_call_target(&self, func: &Expr) -> (String, String, bool) {
        match func {
            Expr::Name(n) => {
                let name = n.id.as_str().to_owned();
                let resolved = self
                    .symbol_table
                    .resolve_full_target(&name)
                    .unwrap_or_default();
                (name, resolved, false)
            }
            Expr::Attribute(_) => {
                if let Some(path) = format_attribute_path(func) {
                    let resolved = self
                        .symbol_table
                        .resolve_full_target(&path)
                        .unwrap_or_default();
                    (path, resolved, false)
                } else {
                    (String::new(), String::new(), false)
                }
            }
            Expr::Call(inner_call) => {
                if let Some((obj_str, attr_str)) = inspect_getattr_pattern(inner_call) {
                    let raw = format!("getattr({}, \"{}\")", obj_str, attr_str);
                    let resolved_base = self
                        .symbol_table
                        .resolve_full_target(&obj_str)
                        .unwrap_or(obj_str);
                    let resolved = format!("{}.{}", resolved_base, attr_str);
                    (raw, resolved, true)
                } else {
                    (String::new(), String::new(), false)
                }
            }
            _ => (String::new(), String::new(), false),
        }
    }
}

fn format_attribute_path(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(n) => Some(n.id.as_str().to_owned()),
        Expr::Attribute(a) => {
            let base = format_attribute_path(&a.value)?;
            Some(format!("{}.{}", base, a.attr.as_str()))
        }
        _ => None,
    }
}

fn inspect_getattr_pattern(call: &ExprCall) -> Option<(String, String)> {
    let target = format_attribute_path(&call.func)?;
    if (target == "getattr" || target == "builtins.getattr") && call.args.len() >= 2 {
        let obj_str = format_attribute_path(&call.args[0]).or_else(|| match &call.args[0] {
            Expr::Name(n) => Some(n.id.as_str().to_owned()),
            _ => None,
        })?;
        let attr_str = match &call.args[1] {
            Expr::Constant(c) => match &c.value {
                ast::Constant::Str(s) => Some(s.as_str().to_owned()),
                _ => None,
            },
            _ => None,
        }?;
        return Some((obj_str, attr_str));
    }
    None
}

pub fn classify_target_capability(target: &str) -> Option<PythonCapabilityCategory> {
    let lower = target.to_ascii_lowercase();

    // Process execution
    if lower == "subprocess.run"
        || lower == "subprocess.popen"
        || lower == "subprocess.call"
        || lower == "subprocess.check_call"
        || lower == "subprocess.check_output"
        || lower == "os.system"
        || lower == "os.popen"
        || lower == "os.spawnve"
        || lower == "os.execve"
        || lower == "pty.spawn"
    {
        return Some(PythonCapabilityCategory::ProcessExecution);
    }

    // Dynamic code evaluation
    if lower == "eval"
        || lower == "exec"
        || lower == "compile"
        || lower == "__import__"
        || lower == "importlib.import_module"
    {
        return Some(PythonCapabilityCategory::DynamicCodeEvaluation);
    }

    // Native library loading
    if lower == "ctypes.cdll"
        || lower == "ctypes.pydll"
        || lower == "ctypes.windll"
        || lower == "ctypes.oledll"
        || lower.starts_with("ctypes.cdll.")
        || lower == "cffi.ffi"
        || lower == "torch.ops.load_library"
    {
        return Some(PythonCapabilityCategory::NativeLibraryLoading);
    }

    // Network
    if lower.starts_with("requests.")
        || lower.starts_with("urllib.request.")
        || lower.starts_with("http.client.")
        || lower == "socket.socket"
        || lower == "socket.create_connection"
        || lower.starts_with("aiohttp.")
        || lower.starts_with("httpx.")
    {
        return Some(PythonCapabilityCategory::NetworkAccess);
    }

    // Credential / environment access
    if lower == "os.getenv"
        || lower == "os.environ"
        || lower.starts_with("os.environ.")
        || lower.starts_with("keyring.")
    {
        return Some(PythonCapabilityCategory::CredentialEnvironmentAccess);
    }

    // Filesystem mutation
    if lower == "shutil.rmtree"
        || lower == "os.remove"
        || lower == "os.unlink"
        || lower == "os.rename"
        || lower == "os.chmod"
        || lower.ends_with(".write_text")
        || lower.ends_with(".write_bytes")
        || lower.ends_with(".unlink")
    {
        return Some(PythonCapabilityCategory::FilesystemMutation);
    }

    None
}

fn is_install_tool(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "pip" | "uv" | "conda" | "poetry" | "npm" | "git" | "curl" | "wget"
    )
}

fn extract_call_evidence(
    call: &ExprCall,
    max_literal_bytes: usize,
) -> (Option<String>, bool, Option<String>) {
    let mut shell_mode = false;
    for kw in &call.keywords {
        if let Some(name) = &kw.arg {
            if name.as_str() == "shell" {
                if let Expr::Constant(c) = &kw.value {
                    if let ast::Constant::Bool(b) = c.value {
                        shell_mode = b;
                    }
                }
            }
        }
    }

    let mut executable_name = None;
    let mut literal_evidence = None;

    if let Some(first_arg) = call.args.first() {
        match first_arg {
            Expr::Constant(c) => {
                if let ast::Constant::Str(s) = &c.value {
                    let parts: Vec<&str> = s.split_whitespace().collect();
                    if let Some(exe) = parts.first() {
                        executable_name = Some((*exe).to_owned());
                    }
                    let truncated = sanitize_and_truncate(s.as_str(), max_literal_bytes);
                    literal_evidence = Some(truncated);
                }
            }
            Expr::List(l) => {
                let mut string_parts = Vec::new();
                for (idx, el) in l.elts.iter().enumerate() {
                    if let Expr::Constant(c) = el {
                        if let ast::Constant::Str(s) = &c.value {
                            if idx == 0 {
                                executable_name = Some(s.as_str().to_owned());
                            }
                            string_parts.push(s.as_str());
                        } else {
                            string_parts.push("<dynamic>");
                        }
                    } else {
                        string_parts.push("<dynamic>");
                    }
                }
                if !string_parts.is_empty() {
                    let joined = string_parts.join(" ");
                    let truncated = sanitize_and_truncate(&joined, max_literal_bytes);
                    literal_evidence = Some(truncated);
                }
            }
            _ => {}
        }
    }

    (executable_name, shell_mode, literal_evidence)
}

fn sanitize_and_truncate(s: &str, max_bytes: usize) -> String {
    let sanitized: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();

    if sanitized.len() > max_bytes {
        let mut truncated = sanitized.chars().take(max_bytes).collect::<String>();
        truncated.push_str("...[truncated]");
        truncated
    } else {
        sanitized
    }
}
