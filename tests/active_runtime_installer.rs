use std::fs;

#[test]
fn managed_runtime_pins_and_checks_tokenizer_dependencies() {
    let requirements = fs::read_to_string("packaging/active-requirements.txt").unwrap();
    for pin in ["sentencepiece==0.2.2", "tiktoken==0.13.0"] {
        assert!(
            requirements.lines().any(|line| line == pin),
            "missing exact pin {pin}"
        );
    }

    let installer = fs::read_to_string("scripts/install/active-runtime.sh").unwrap();
    for pin in ["'sentencepiece==0.2.2'", "'tiktoken==0.13.0'"] {
        assert!(installer.contains(pin), "fallback installer missing {pin}");
    }
    assert!(
        installer.contains("safetensors, sentencepiece, tiktoken"),
        "installer import verification is missing tokenizer dependencies"
    );

    let doctor = fs::read_to_string("src/doctor.rs").unwrap();
    let lab_host = fs::read_to_string("scripts/setup-lab-host.sh").unwrap();
    for module in ["sentencepiece", "tiktoken"] {
        assert!(
            doctor.contains(module),
            "doctor import check missing {module}"
        );
        assert!(
            lab_host.contains(module),
            "lab-host import check missing {module}"
        );
    }
}
