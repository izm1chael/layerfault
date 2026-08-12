#!/usr/bin/env python3
"""Generate Layerfault's local non-secret differential parser test corpus and manifest."""

import hashlib
import json
import os
import pathlib
import struct
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
CORPUS_DIR = ROOT / "tests" / "corpus"


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def generate_safetensors():
    safetensors_dir = CORPUS_DIR / "safetensors"
    safetensors_dir.mkdir(parents=True, exist_ok=True)

    # 1. u8_vector.safetensors
    header = json.dumps({"w": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}, separators=(",", ":")).encode("utf-8")
    data = struct.pack("<Q", len(header)) + header + b"abcd"
    p1 = safetensors_dir / "u8_vector.safetensors"
    p1.write_bytes(data)

    # 2. multi_tensor.safetensors
    header2 = json.dumps({
        "__metadata__": {"format": "pt"},
        "a": {"dtype": "U8", "shape": [2], "data_offsets": [0, 2]},
        "b": {"dtype": "F32", "shape": [1], "data_offsets": [2, 6]}
    }, separators=(",", ":")).encode("utf-8")
    data2 = struct.pack("<Q", len(header2)) + header2 + b"xy" + struct.pack("<f", 1.25)
    p2 = safetensors_dir / "multi_tensor.safetensors"
    p2.write_bytes(data2)


def generate_gguf():
    gguf_dir = CORPUS_DIR / "gguf"
    gguf_dir.mkdir(parents=True, exist_ok=True)

    def gguf_str(s: str) -> bytes:
        b = s.encode("utf-8")
        return struct.pack("<Q", len(b)) + b

    buf = bytearray()
    buf.extend(b"GGUF")
    buf.extend(struct.pack("<I", 3))  # Version 3
    buf.extend(struct.pack("<Q", 1))  # Tensor count = 1
    buf.extend(struct.pack("<Q", 2))  # Metadata count = 2

    # Metadata 1: general.architecture = "llama"
    buf.extend(gguf_str("general.architecture"))
    buf.extend(struct.pack("<I", 8))
    buf.extend(gguf_str("llama"))

    # Metadata 2: general.alignment = 32
    buf.extend(gguf_str("general.alignment"))
    buf.extend(struct.pack("<I", 4))
    buf.extend(struct.pack("<I", 32))

    # Tensor 1: "token_embd.weight"
    buf.extend(gguf_str("token_embd.weight"))
    buf.extend(struct.pack("<I", 1))
    buf.extend(struct.pack("<Q", 16))
    buf.extend(struct.pack("<I", 0))
    buf.extend(struct.pack("<Q", 0))

    pad_len = (32 - (len(buf) % 32)) % 32
    buf.extend(b"\x00" * pad_len)
    buf.extend(struct.pack("<16f", *[0.1 * i for i in range(16)]))

    p = gguf_dir / "v3_basic.gguf"
    p.write_bytes(bytes(buf))


def generate_onnx():
    onnx_dir = CORPUS_DIR / "onnx"
    onnx_dir.mkdir(parents=True, exist_ok=True)

    buf = bytearray()
    buf.extend(bytes([0x08, 0x07]))  # ir_version = 7
    buf.extend(bytes([0x12, 0x0a]) + b"layerfault")  # producer_name = "layerfault"
    
    graph_buf = bytearray()
    graph_buf.extend(bytes([0x12, 0x0a]) + b"test-graph")
    buf.extend(bytes([0x3a, len(graph_buf)]) + graph_buf)

    p = onnx_dir / "basic.onnx"
    p.write_bytes(bytes(buf))


def generate_pickle():
    pickle_dir = CORPUS_DIR / "pickle"
    pickle_dir.mkdir(parents=True, exist_ok=True)

    data = b"\x80\x04ctorch\nFloatStorage\nq\x00)\x81."
    p = pickle_dir / "benign_opcodes.pkl"
    p.write_bytes(data)


def generate_tflite():
    tflite_dir = CORPUS_DIR / "tflite"
    tflite_dir.mkdir(parents=True, exist_ok=True)

    # Offset 0: root table offset = 16
    # Offset 4: identifier = TFL3
    # Offset 8: vtable (vt_len=6, obj_len=8, field0_offset=4)
    # Offset 14: padding 0x00 0x00
    # Offset 16: table (back_offset=8, version=3)
    buf = bytearray()
    buf.extend(struct.pack("<I", 16))      # root table offset
    buf.extend(b"TFL3")                    # identifier
    buf.extend(struct.pack("<HHH", 6, 8, 4)) # vtable: vt_len, obj_len, field 0 off
    buf.extend(b"\x00\x00")                # padding to align offset 16
    buf.extend(struct.pack("<i", 8))       # back offset to vtable (16 - 8 = 8)
    buf.extend(struct.pack("<I", 3))       # schema version = 3

    p = tflite_dir / "basic.tflite"
    p.write_bytes(bytes(buf))


def generate_tensorflow():
    tf_dir = CORPUS_DIR / "tensorflow"
    tf_dir.mkdir(parents=True, exist_ok=True)

    data = b"\x0a\x0bSavedModel\x12\x05Graph"
    p = tf_dir / "saved_model.pb"
    p.write_bytes(data)


def generate_keras():
    keras_dir = CORPUS_DIR / "keras"
    keras_dir.mkdir(parents=True, exist_ok=True)

    p = keras_dir / "model.keras"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {}}))
        z.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n")


def build_manifest():
    fixtures = [
        {
            "id": "safetensors-v1-u8",
            "format": "safetensors",
            "path": "safetensors/u8_vector.safetensors",
            "sha256": sha256_file(CORPUS_DIR / "safetensors" / "u8_vector.safetensors"),
            "expected": {
                "tensor_count": 1,
                "metadata_count": 0
            }
        },
        {
            "id": "safetensors-v1-multi",
            "format": "safetensors",
            "path": "safetensors/multi_tensor.safetensors",
            "sha256": sha256_file(CORPUS_DIR / "safetensors" / "multi_tensor.safetensors"),
            "expected": {
                "tensor_count": 2,
                "metadata_count": 1
            }
        },
        {
            "id": "gguf-v3-basic",
            "format": "gguf",
            "path": "gguf/v3_basic.gguf",
            "sha256": sha256_file(CORPUS_DIR / "gguf" / "v3_basic.gguf"),
            "expected": {
                "tensor_count": 1,
                "metadata_count": 2
            }
        },
        {
            "id": "onnx-v1-basic",
            "format": "onnx",
            "path": "onnx/basic.onnx",
            "sha256": sha256_file(CORPUS_DIR / "onnx" / "basic.onnx"),
            "expected": {
                "metadata_count": 2
            }
        },
        {
            "id": "pickle-opcode-benign",
            "format": "pickle",
            "path": "pickle/benign_opcodes.pkl",
            "sha256": sha256_file(CORPUS_DIR / "pickle" / "benign_opcodes.pkl"),
            "expected": {
                "global_refs": ["torch.FloatStorage"]
            }
        },
        {
            "id": "tflite-basic",
            "format": "tflite",
            "path": "tflite/basic.tflite",
            "sha256": sha256_file(CORPUS_DIR / "tflite" / "basic.tflite"),
            "expected": {
                "schema_version": 3
            }
        },
        {
            "id": "tensorflow-saved-model",
            "format": "tensorflow",
            "path": "tensorflow/saved_model.pb",
            "sha256": sha256_file(CORPUS_DIR / "tensorflow" / "saved_model.pb"),
            "expected": {
                "kind": "SavedModel"
            }
        },
        {
            "id": "keras-archive-basic",
            "format": "keras",
            "path": "keras/model.keras",
            "sha256": sha256_file(CORPUS_DIR / "keras" / "model.keras"),
            "expected": {
                "has_config": True
            }
        }
    ]

    manifest = {
        "version": 1,
        "fixtures": fixtures
    }

    manifest_path = CORPUS_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"Generated manifest with {len(fixtures)} fixtures at {manifest_path}")


def main():
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    generate_safetensors()
    generate_gguf()
    generate_onnx()
    generate_pickle()
    generate_tflite()
    generate_tensorflow()
    generate_keras()
    build_manifest()


if __name__ == "__main__":
    main()
