use layerfault::formats::artifact::{self, ArtifactScanMode};
use layerfault::formats::{mlx, ArtifactFormat};
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use zip::write::FileOptions;
use zip::ZipWriter;

#[test]
fn test_pytorch_zip_and_torchscript_distinction() {
    let dir = tempdir().unwrap();
    let options = FileOptions::<()>::default();

    // 1. PyTorch ZIP fixture with data.pkl
    let pt_path = dir.path().join("model.pt");
    {
        let file = File::create(&pt_path).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.start_file("archive/data.pkl", options).unwrap();
        zip.write_all(b"\x80\x04}\x94.").unwrap(); // empty dict pickle
        zip.finish().unwrap();
    }

    let report = artifact::inspect(&pt_path, ArtifactScanMode::StructureOnly).unwrap();
    assert_eq!(report.format, ArtifactFormat::PyTorchZip);
    assert!(!report.blocking());

    // 2. TorchScript fixture with archive/code/__torch__/model.py
    let ts_path = dir.path().join("torchscript.pt");
    {
        let file = File::create(&ts_path).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.start_file("archive/code/__torch__/model.py", options)
            .unwrap();
        zip.write_all(b"def forward(x):\n    return x\n").unwrap();
        zip.finish().unwrap();
    }

    let report = artifact::inspect(&ts_path, ArtifactScanMode::StructureOnly).unwrap();
    assert_eq!(report.format, ArtifactFormat::PyTorchZip);
    assert!(report.results.iter().any(|r| r
        .matches
        .iter()
        .any(|m| m.contains("LF-TORCHSCRIPT-STRUCTURAL"))));

    // 3. TorchScript with dangerous code call
    let dangerous_ts_path = dir.path().join("dangerous_ts.pt");
    {
        let file = File::create(&dangerous_ts_path).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.start_file("archive/code/__torch__/model.py", options)
            .unwrap();
        zip.write_all(b"import os\nos.system('echo pwned')\n")
            .unwrap();
        zip.finish().unwrap();
    }

    let report = artifact::inspect(&dangerous_ts_path, ArtifactScanMode::StructureOnly).unwrap();
    assert!(report.blocking());
    assert!(report
        .results
        .iter()
        .any(|r| r.matches.iter().any(|m| m.contains("LF-TORCHSCRIPT-CODE"))));
}

#[test]
fn test_torch_package_inspection() {
    let dir = tempdir().unwrap();
    let options = FileOptions::<()>::default();

    let pkg_path = dir.path().join("model.pkg");
    {
        let file = File::create(&pkg_path).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.start_file("package_importer/main.py", options).unwrap();
        zip.write_all(b"import subprocess\nsubprocess.run(['id'])\n")
            .unwrap();
        zip.finish().unwrap();
    }

    let report = artifact::inspect(&pkg_path, ArtifactScanMode::StructureOnly).unwrap();
    assert_eq!(report.format, ArtifactFormat::TorchPackage);
    assert!(report.blocking());
    assert!(report
        .results
        .iter()
        .any(|r| r.matches.iter().any(|m| m.contains("LF-TORCHPACKAGE-EXEC"))));
}

#[test]
fn test_executorch_inspection() {
    let dir = tempdir().unwrap();

    // 1. Valid ExecuTorch header
    let et_path = dir.path().join("model.pte");
    {
        let mut f = File::create(&et_path).unwrap();
        f.write_all(b"\x18\x00\x00\x00ET12\x00\x00\x00\x00")
            .unwrap();
    }

    let report = artifact::inspect(&et_path, ArtifactScanMode::StructureOnly).unwrap();
    assert_eq!(report.format, ArtifactFormat::ExecuTorch);

    // 2. Truncated ExecuTorch
    let trunc_path = dir.path().join("trunc.pte");
    {
        let mut f = File::create(&trunc_path).unwrap();
        f.write_all(b"ET").unwrap();
    }

    let report = artifact::inspect(&trunc_path, ArtifactScanMode::StructureOnly).unwrap();
    assert!(report.blocking());
    assert!(report.results.iter().any(|r| r
        .matches
        .iter()
        .any(|m| m.contains("LF-EXECUTORCH-TRUNCATED"))));

    // 3. Out of bounds root table
    let oob_path = dir.path().join("oob.pte");
    {
        let mut f = File::create(&oob_path).unwrap();
        f.write_all(b"\xff\xff\xff\x7fET12\x00\x00\x00\x00")
            .unwrap();
    }

    let report = artifact::inspect(&oob_path, ArtifactScanMode::StructureOnly).unwrap();
    assert!(report.blocking());
    assert!(report
        .results
        .iter()
        .any(|r| r.matches.iter().any(|m| m.contains("LF-EXECUTORCH-BOUNDS"))));
}

#[test]
fn test_openvino_inspection() {
    let dir = tempdir().unwrap();

    // 1. Valid OpenVINO IR XML + sidecar .bin
    let xml_path = dir.path().join("model.xml");
    let bin_path = dir.path().join("model.bin");
    {
        let mut f_xml = File::create(&xml_path).unwrap();
        f_xml
            .write_all(b"<net name=\"test_model\" version=\"10\"><layers></layers></net>")
            .unwrap();
        let mut f_bin = File::create(&bin_path).unwrap();
        f_bin.write_all(&[0u8; 1024]).unwrap();
    }

    let report = artifact::inspect(&xml_path, ArtifactScanMode::StructureOnly).unwrap();
    assert_eq!(report.format, ArtifactFormat::OpenVinoIr);
    assert!(!report.blocking());
    assert!(report.results.iter().any(|r| r
        .matches
        .iter()
        .any(|m| m.contains("LF-OPENVINO-SIDECAR-VALID"))));

    // 2. OpenVINO XXE vulnerability attempt
    let xxe_path = dir.path().join("xxe.xml");
    {
        let mut f = File::create(&xxe_path).unwrap();
        f.write_all(b"<!DOCTYPE net [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><net name=\"test\">&xxe;</net>").unwrap();
    }

    let report = artifact::inspect(&xxe_path, ArtifactScanMode::StructureOnly).unwrap();
    assert!(report.blocking());
    assert!(report
        .results
        .iter()
        .any(|r| r.matches.iter().any(|m| m.contains("LF-OPENVINO-XXE"))));
}

#[test]
fn test_tensorrt_inspection() {
    let dir = tempdir().unwrap();

    // 1. Valid TensorRT engine fixture
    let trt_path = dir.path().join("model.engine");
    {
        let mut f = File::create(&trt_path).unwrap();
        f.write_all(b"TRT\x00\x00\x00\x00\x08dummy_engine_bytes")
            .unwrap();
    }

    let report = artifact::inspect(&trt_path, ArtifactScanMode::StructureOnly).unwrap();
    assert_eq!(report.format, ArtifactFormat::TensorRtEngine);
    assert!(!report.blocking());
    assert!(report
        .results
        .iter()
        .any(|r| r.matches.iter().any(|m| m.contains("LF-TENSORRT-OPAQUE"))));
}

#[test]
fn test_coreml_inspection() {
    let dir = tempdir().unwrap();

    // 1. Valid Core ML .mlmodel
    let mlmodel_path = dir.path().join("model.mlmodel");
    {
        let mut f = File::create(&mlmodel_path).unwrap();
        f.write_all(b"\x0a\x07test_id").unwrap();
    }

    let report = artifact::inspect(&mlmodel_path, ArtifactScanMode::StructureOnly).unwrap();
    assert_eq!(report.format, ArtifactFormat::CoreMlModel);
    assert!(!report.blocking());

    // 2. Core ML with path traversal
    let bad_mlmodel_path = dir.path().join("bad.mlmodel");
    {
        let mut f = File::create(&bad_mlmodel_path).unwrap();
        f.write_all(b"\x12\x10../../etc/passwd").unwrap();
    }

    let report = artifact::inspect(&bad_mlmodel_path, ArtifactScanMode::StructureOnly).unwrap();
    assert!(report.blocking());
    assert!(report.results.iter().any(|r| r
        .matches
        .iter()
        .any(|m| m.contains("LF-COREML-PATH-TRAVERSAL"))));
}

#[test]
fn test_coreml_package_inspection() {
    let dir = tempdir().unwrap();

    // 1. Valid .mlpackage
    let valid_pkg = dir.path().join("model.mlpackage");
    std::fs::create_dir_all(valid_pkg.join("Data/com.apple.CoreML")).unwrap();
    File::create(valid_pkg.join("Data/com.apple.CoreML/model.mlmodel")).unwrap();
    {
        let mut f = File::create(valid_pkg.join("Manifest.json")).unwrap();
        f.write_all(
            br#"{
            "fileFormatVersion": "1.0.0",
            "itemInfoEntries": {
                "com.apple.CoreML/model.mlmodel": {
                    "path": "Data/com.apple.CoreML/model.mlmodel"
                }
            }
        }"#,
        )
        .unwrap();
    }

    let results = layerfault::formats::coreml::scan_package(
        &valid_pkg,
        "test-digest",
        "application/vnd.layerfault.package",
    )
    .unwrap();
    assert!(results.iter().any(|r| r
        .matches
        .iter()
        .any(|m| m.contains("LF-COREML-PACKAGE-VALID"))));
    assert!(!results.iter().any(|r| r
        .matches
        .iter()
        .any(|m| m.contains("LF-COREML-PACKAGE-UNSAFE"))));

    // 2. .mlpackage with escaping symlink (coreml-mlpackage-symlink-lfi-poc)
    #[cfg(unix)]
    {
        let poc_pkg = dir.path().join("poc.mlpackage");
        std::fs::create_dir_all(poc_pkg.join("weights")).unwrap();
        {
            let mut f = File::create(poc_pkg.join("Manifest.json")).unwrap();
            f.write_all(
                br#"{
                "fileFormatVersion": "1.0.0",
                "itemInfoEntries": {
                    "weights": {
                        "path": "weights/copied_host_marker.txt"
                    }
                }
            }"#,
            )
            .unwrap();
        }
        std::os::unix::fs::symlink(
            "../../../../reviewer_host_marker.txt",
            poc_pkg.join("weights/copied_host_marker.txt"),
        )
        .unwrap();

        let results = layerfault::formats::coreml::scan_package(
            &poc_pkg,
            "test-digest",
            "application/vnd.layerfault.package",
        )
        .unwrap();
        assert!(results.iter().any(|r| r
            .matches
            .iter()
            .any(|m| m.contains("LF-COREML-PACKAGE-UNSAFE"))));
        assert!(!results.iter().any(|r| r
            .matches
            .iter()
            .any(|m| m.contains("LF-COREML-PACKAGE-VALID"))));

        // Test full package::inspect on the poc mlpackage
        let report = layerfault::package::inspect(&poc_pkg).unwrap();
        assert!(report.blocking());
        assert!(report.findings.iter().any(|r| r
            .matches
            .iter()
            .any(|m| m.contains("LF-COREML-PACKAGE-UNSAFE"))));
        assert!(report
            .findings
            .iter()
            .any(|r| r.matches.iter().any(|m| m.contains("LF-PACKAGE-SYMLINK"))));
        assert!(!report.findings.iter().any(|r| r
            .matches
            .iter()
            .any(|m| m.contains("LF-COREML-PACKAGE-VALID"))));
    }

    // 3. .mlpackage with path traversal in Manifest.json
    let traversal_pkg = dir.path().join("traversal.mlpackage");
    std::fs::create_dir_all(&traversal_pkg).unwrap();
    {
        let mut f = File::create(traversal_pkg.join("Manifest.json")).unwrap();
        f.write_all(
            br#"{
            "fileFormatVersion": "1.0.0",
            "itemInfoEntries": {
                "weights": {
                    "path": "../../../../etc/passwd"
                }
            }
        }"#,
        )
        .unwrap();
    }

    let results = layerfault::formats::coreml::scan_package(
        &traversal_pkg,
        "test-digest",
        "application/vnd.layerfault.package",
    )
    .unwrap();
    assert!(results.iter().any(|r| r
        .matches
        .iter()
        .any(|m| m.contains("LF-COREML-PACKAGE-UNSAFE"))));
    assert!(!results.iter().any(|r| r
        .matches
        .iter()
        .any(|m| m.contains("LF-COREML-PACKAGE-VALID"))));
}

#[test]
fn test_mlx_inspection() {
    let dir = tempdir().unwrap();

    let mlx_dir = dir.path().join("mlx_model");
    std::fs::create_dir(&mlx_dir).unwrap();
    File::create(mlx_dir.join("config.json")).unwrap();
    File::create(mlx_dir.join("model.safetensors")).unwrap();
    File::create(mlx_dir.join("modeling_custom.py")).unwrap();

    let results =
        mlx::scan_package(&mlx_dir, "mlx-test-digest", "application/x-mlx-package").unwrap();
    assert!(results
        .iter()
        .any(|r| r.matches.iter().any(|m| m.contains("LF-MLX-PROFILE-VALID"))));
    assert!(results
        .iter()
        .any(|r| r.matches.iter().any(|m| m.contains("LF-MLX-CUSTOM-CODE"))));
}
