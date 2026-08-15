#!/usr/bin/env python3
import json
import os
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[2] / "tests" / "detector_quality" / "fixtures"

def make_dirs(path: pathlib.Path):
    path.mkdir(parents=True, exist_ok=True)

# 1. positive_block / malicious_pickle_eval
dir_pb_pickle = ROOT / "positive_block" / "malicious_pickle_eval"
make_dirs(dir_pb_pickle)
pickle_eval_data = b"cos\nsystem\n(S'echo malicious'\ntR."
(dir_pb_pickle / "model.pkl").write_bytes(pickle_eval_data)
(dir_pb_pickle / "config.json").write_text(json.dumps({"architectures": ["PickleModel"]}))

# 1. positive_block / safetensors_out_of_bounds
dir_pb_st = ROOT / "positive_block" / "safetensors_out_of_bounds"
make_dirs(dir_pb_st)
header = json.dumps({"w": {"dtype": "U8", "shape": [4], "data_offsets": [100, 104]}}, separators=(",", ":"))
header_bytes = header.encode("utf-8")
bad_st_bytes = struct.pack("<Q", len(header_bytes)) + header_bytes + b"1234"
(dir_pb_st / "bad.safetensors").write_bytes(bad_st_bytes)

# 2. positive_warn / python_subprocess
dir_pw_sub = ROOT / "positive_warn" / "python_subprocess"
make_dirs(dir_pw_sub)
(dir_pw_sub / "config.json").write_text(json.dumps({
    "architectures": ["SubprocessModel"],
    "auto_map": {"AutoModel": "modeling.SubprocessModel"}
}))
(dir_pw_sub / "modeling.py").write_text("""import subprocess

class SubprocessModel:
    def __init__(self):
        subprocess.Popen(["echo", "executing"])
""")

# 2. positive_warn / jinja_introspection
dir_pw_jinja = ROOT / "positive_warn" / "jinja_introspection"
make_dirs(dir_pw_jinja)
(dir_pw_jinja / "config.json").write_text(json.dumps({"tokenizer_config": {"chat_template": "{{ self.__class__.__mro__[1].__subclasses__() }}"}}))

# 3. negative_benign / subprocess_in_docstring
dir_nb_doc = ROOT / "negative_benign" / "subprocess_in_docstring"
make_dirs(dir_nb_doc)
(dir_nb_doc / "config.json").write_text(json.dumps({"architectures": ["SafeDocModel"]}))
(dir_nb_doc / "modeling.py").write_text('''# This module is for formatting documentation.
# Note: subprocess and os.system are not used here.

def format_docstring(text: str) -> str:
    """Mentioning subprocess in docstring for educational reference."""
    return text.strip()
''')

# 3. negative_benign / tokenizer_vocab
dir_nb_tok = ROOT / "negative_benign" / "tokenizer_vocab"
make_dirs(dir_nb_tok)
(dir_nb_tok / "tokenizer.json").write_text(json.dumps({
    "version": "1.0",
    "model": {
        "vocab": {
            "eval": 1,
            "exec": 2,
            "subprocess": 3,
            "socket": 4,
            "system": 5,
            "Popen": 6
        }
    }
}))

# 3. negative_benign / eval_doc_markdown
dir_nb_md = ROOT / "negative_benign" / "eval_doc_markdown"
make_dirs(dir_nb_md)
(dir_nb_md / "README.md").write_text("""# Model Evaluation Guide
Use the loss evaluation metric during training.
Do not call Python built-in eval() function directly on unvalidated inputs.
""")

# 3. negative_benign / benign_jinja
dir_nb_jinja = ROOT / "negative_benign" / "benign_jinja"
make_dirs(dir_nb_jinja)
(dir_nb_jinja / "chat_template.jinja").write_text("{% for message in messages %}{{ message.content }}{% endfor %}")

# 3. negative_benign / dependency_manifests
dir_nb_deps = ROOT / "negative_benign" / "dependency_manifests"
make_dirs(dir_nb_deps)
(dir_nb_deps / "pyproject.toml").write_text("""[build-system]
requires = ["setuptools==83.0.0"]
build-backend = "setuptools.build_meta"

[project]
name = "safe-package"
version = "0.1.0"
dependencies = [
    "torch==2.13.0",
    "numpy==1.24.3"
]
""")
(dir_nb_deps / "requirements.txt").write_text("torch==2.13.0\nnumpy==1.24.3\n")

# 3. negative_benign / allowlisted_pickle
dir_nb_pkl = ROOT / "negative_benign" / "allowlisted_pickle"
make_dirs(dir_nb_pkl)
(dir_nb_pkl / "model.pkl").write_bytes(b"\x80\x04cnumpy.core.multiarray\n_reconstruct\nq\x00.")

# 3. negative_benign / numeric_numpy_safetensors
dir_nb_st = ROOT / "negative_benign" / "numeric_numpy_safetensors"
make_dirs(dir_nb_st)
st_header = json.dumps({"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}, separators=(",", ":"))
st_header_bytes = st_header.encode("utf-8")
st_payload = struct.pack("<Q", len(st_header_bytes)) + st_header_bytes + struct.pack("<ff", 1.0, 2.0)
(dir_nb_st / "model.safetensors").write_bytes(st_payload)

# 3. negative_benign / imported_network_uncalled
dir_nb_net = ROOT / "negative_benign" / "imported_network_uncalled"
make_dirs(dir_nb_net)
(dir_nb_net / "config.json").write_text(json.dumps({"architectures": ["NetImportModel"]}))
(dir_nb_net / "modeling.py").write_text("""import requests
import socket

def compute_embeddings(x):
    # Network libraries are imported but never called or connected.
    return [len(x)]
""")

# 4. ambiguous_expected_warn / custom_code_automap
dir_aew = ROOT / "ambiguous_expected_warn" / "custom_code_automap"
make_dirs(dir_aew)
(dir_aew / "config.json").write_text(json.dumps({
    "architectures": ["CustomHelperModel"],
    "auto_map": {"AutoModel": "modeling_helper.CustomHelperModel"}
}))
(dir_aew / "modeling_helper.py").write_text("""class CustomHelperModel:
    def __init__(self, config):
        self.config = config
""")

# 5. correlation_positive / automap_subprocess
dir_cp = ROOT / "correlation_positive" / "automap_subprocess"
make_dirs(dir_cp)
(dir_cp / "config.json").write_text(json.dumps({
    "architectures": ["CorrelatedModel"],
    "auto_map": {"AutoModel": "modeling_corr.CorrelatedModel"}
}))
(dir_cp / "modeling_corr.py").write_text("""import subprocess

class CorrelatedModel:
    def __init__(self):
        subprocess.run(["echo", "correlated execution"])
""")

# 6. evasion_variant / alias_import
dir_ev_alias = ROOT / "evasion_variant" / "alias_import"
make_dirs(dir_ev_alias)
(dir_ev_alias / "config.json").write_text(json.dumps({
    "architectures": ["AliasModel"],
    "auto_map": {"AutoModel": "modeling_alias.AliasModel"}
}))
(dir_ev_alias / "modeling_alias.py").write_text("""import subprocess as sp

class AliasModel:
    def __init__(self):
        sp.Popen(["whoami"])
""")

# 6. evasion_variant / direct_from_import
dir_ev_direct = ROOT / "evasion_variant" / "direct_from_import"
make_dirs(dir_ev_direct)
(dir_ev_direct / "config.json").write_text(json.dumps({
    "architectures": ["DirectModel"],
    "auto_map": {"AutoModel": "modeling_direct.DirectModel"}
}))
(dir_ev_direct / "modeling_direct.py").write_text("""from subprocess import Popen

class DirectModel:
    def __init__(self):
        Popen(["whoami"])
""")

# 6. evasion_variant / whitespace_obfuscation
dir_ev_ws = ROOT / "evasion_variant" / "whitespace_obfuscation"
make_dirs(dir_ev_ws)
(dir_ev_ws / "config.json").write_text(json.dumps({
    "architectures": ["WhitespaceModel"],
    "auto_map": {"AutoModel": "modeling_ws.WhitespaceModel"}
}))
(dir_ev_ws / "modeling_ws.py").write_text("""class WhitespaceModel:
    def compute(self):
        import \\
            subprocess \\
            as proc
        proc.call(
            ["id"]
        )
""")

# 6. evasion_variant / misleading_extension
dir_ev_ext = ROOT / "evasion_variant" / "misleading_extension"
make_dirs(dir_ev_ext)
(dir_ev_ext / "config.json").write_text(json.dumps({
    "architectures": ["MisleadingModel"],
    "auto_map": {"AutoModel": "helper.txt"}
}))
(dir_ev_ext / "helper.txt").write_text("""import subprocess
subprocess.Popen(["uname", "-a"])
""")

# 7. redaction / secret_in_code
dir_red = ROOT / "redaction" / "secret_in_code"
make_dirs(dir_red)
(dir_red / "config.json").write_text(json.dumps({
    "architectures": ["SecretModel"],
    "auto_map": {"AutoModel": "modeling_secret.SecretModel"}
}))
(dir_red / "modeling_secret.py").write_text("""import subprocess

# Secret key embedded in source code:
API_KEY = "sk_" + "live_12345678901234567890123456789012"

class SecretModel:
    def __init__(self):
        subprocess.run(["echo", API_KEY])
""")

# 8. coverage_incomplete / truncated_or_unparseable
dir_cov = ROOT / "coverage_incomplete" / "unparseable_python"
make_dirs(dir_cov)
(dir_cov / "config.json").write_text(json.dumps({
    "architectures": ["UnparseableModel"],
    "auto_map": {"AutoModel": "modeling_broken.UnparseableModel"}
}))
(dir_cov / "modeling_broken.py").write_text("""def unclosed_syntax_error(
    import subprocess
    subprocess.call(["ls"])
""")

print("Successfully regenerated synthetic fixtures.")
