use std::path::PathBuf;

#[test]
fn legacy_evidence_v1_deserializes() {
    let bytes = include_bytes!("contracts/evidence-v1-legacy.json");
    let envelope: layerfault::evidence::EvidenceEnvelope = serde_json::from_slice(bytes).unwrap();
    assert_eq!(envelope.payload.version, 1);
    assert!(envelope.payload.admission_receipt.is_none());
    assert!(envelope.payload.intelligence_sha256.is_none());
}

#[test]
fn legacy_advisory_database_v1_loads() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/contracts/advisory-db-v1-legacy.json");
    let (database, _) = layerfault::advisory::load_database(Some(&path)).unwrap();
    assert_eq!(database.version, 1);
    assert_eq!(database.advisories.len(), 1);
    assert!(database.advisories[0].preconditions.is_empty());
}

#[test]
fn legacy_policy_v1_loads_with_legacy_semantics() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts/policy-v1-legacy.json");
    let document = layerfault::policy::PolicyDocument::load(&path).unwrap();
    assert_eq!(
        document.profile,
        layerfault::policy::PolicyProfile::Workstation
    );
    let effective = document.effective();
    assert!(!effective.require_complete_coverage);
    assert!(effective.allow_custom_code);
    assert_eq!(
        effective.backdoor_signal_action,
        layerfault::policy::BackdoorSignalAction::Ignore
    );
}
