use layerfault::template_static::analyzer::TargetClassification;
use layerfault::template_static::{analyze_template, TemplateLimits};

#[test]
fn test_object_traversal_whitespace_and_parentheses_variations() {
    let template = "Hello {{ self . ( __class__ ) . __mro__ [ 1 ] . __subclasses__ ( ) }}";
    let limits = TemplateLimits::default();
    let analysis = analyze_template(template, "chat_template.jinja", &limits);

    assert_eq!(analysis.findings.len(), 2);
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.rule.rule_id() == "LF-TEMPLATE-SSTI"));
    assert!(analysis
        .findings
        .iter()
        .any(|f| f.rule.rule_id() == "LF-TEMPLATE-INTROSPECTION"));
}

#[test]
fn test_introspection_only_traversal() {
    let template = "Hello {{ self . __class__ . __mro__ }}";
    let limits = TemplateLimits::default();
    let analysis = analyze_template(template, "chat_template.jinja", &limits);

    assert_eq!(analysis.findings.len(), 1);
    let finding = &analysis.findings[0];
    assert_eq!(finding.rule.rule_id(), "LF-TEMPLATE-INTROSPECTION");
}

#[test]
fn test_dynamic_include_target_expression() {
    let template = "{% include dynamic_var %}";
    let limits = TemplateLimits::default();
    let analysis = analyze_template(template, "chat_template.jinja", &limits);

    assert_eq!(analysis.findings.len(), 1);
    let finding = &analysis.findings[0];
    assert_eq!(finding.rule.rule_id(), "LF-TEMPLATE-DYNAMIC-INCLUDE");
    assert_eq!(
        finding.classification,
        TargetClassification::DynamicExpression
    );
}

#[test]
fn test_static_benign_include() {
    let template = "{% include \"header.html\" %}";
    let limits = TemplateLimits::default();
    let analysis = analyze_template(template, "chat_template.jinja", &limits);

    assert!(analysis
        .findings
        .iter()
        .all(|f| f.classification == TargetClassification::StaticLiteral));
}

#[test]
fn test_path_traversal_include_literal() {
    let template = "{% include \"../secret.jinja\" %}";
    let limits = TemplateLimits::default();
    let analysis = analyze_template(template, "chat_template.jinja", &limits);

    assert_eq!(analysis.findings.len(), 1);
    let finding = &analysis.findings[0];
    assert_eq!(finding.rule.rule_id(), "LF-TEMPLATE-DYNAMIC-INCLUDE");
    assert_eq!(
        finding.classification,
        TargetClassification::PathTraversalLiteral
    );
}

#[test]
fn test_ordinary_template_loops_and_filters() {
    let template = "{% for msg in messages %}{{ msg.content | lower }}{% endfor %}";
    let limits = TemplateLimits::default();
    let analysis = analyze_template(template, "chat_template.jinja", &limits);

    assert!(analysis.findings.is_empty());
}

#[test]
fn test_dunder_text_inside_comments_and_string_literals() {
    // Comments must be ignored
    let comment_template = "{# __class__ __mro__ __subclasses__() __globals__ #}";
    let limits = TemplateLimits::default();
    let analysis = analyze_template(comment_template, "chat_template.jinja", &limits);
    assert!(analysis.findings.is_empty());

    // String literals without attribute access must not trigger false findings
    let literal_template = "{{ \"Documentation on __class__ and __globals__\" }}";
    let analysis2 = analyze_template(literal_template, "chat_template.jinja", &limits);
    assert!(analysis2.findings.is_empty());
}

#[test]
fn test_malformed_template_fallback() {
    let template = "{{ self.__class__.__subclasses__() unclosed_tag";
    let limits = TemplateLimits::default();
    let analysis = analyze_template(template, "chat_template.jinja", &limits);

    assert!(analysis.metrics.incomplete_coverage);
    assert!(!analysis.findings.is_empty());
    assert_eq!(
        analysis.findings[0].classification,
        TargetClassification::IncompleteCoverageFallback
    );
}

#[test]
fn test_deep_nesting_limit_overrun() {
    // Construct deeply nested expression exceeding max_expression_depth
    let mut template = String::from("{{ ");
    for _ in 0..50 {
        template.push_str("( ");
    }
    template.push_str("x ");
    for _ in 0..50 {
        template.push_str(") ");
    }
    template.push_str("}}");

    let limits = TemplateLimits {
        max_expression_depth: 10,
        ..Default::default()
    };
    let analysis = analyze_template(&template, "chat_template.jinja", &limits);

    assert!(analysis.metrics.incomplete_coverage);
}

#[test]
fn test_source_span_evidence_across_contexts() {
    let template = "Line 1\nLine 2: {{ self.__class__.__subclasses__() }}";
    let limits = TemplateLimits::default();
    let analysis = analyze_template(template, "tokenizer_config.json:chat_template", &limits);

    assert!(!analysis.findings.is_empty());
    let finding = &analysis.findings[0];
    assert_eq!(finding.span.line, 2);
    assert!(finding.span.offset > 0);
}
