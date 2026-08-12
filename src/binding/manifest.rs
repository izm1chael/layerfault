use super::types::{BindingKind, ComponentBinding, ExecutionManifest};

pub fn build_compound_manifest(
    components: Vec<ComponentBinding>,
    runtime_sha256: Option<String>,
) -> ExecutionManifest {
    ExecutionManifest {
        version: 1,
        components,
        runtime_sha256,
        binding: BindingKind::PackageStagedRehashed,
    }
}
