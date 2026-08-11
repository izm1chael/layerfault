#!/usr/bin/env python3
"""Reference adapter runner for differential parser validation.

Outputs normalized model structural facts matching Layerfault's NormalizedModel schema.
Reference tooling is strictly test-only and never loaded by Layerfault at runtime.
Pickle handling uses opcode parsing (pickletools.genops) only: NEVER pickle.load.
"""

import json
import pickletools
import sys
import struct
import pathlib

def parse_safetensors(path: str) -> dict:
    data = pathlib.Path(path).read_bytes()
    header_len = struct.unpack("<Q", data[:8])[0]
    header_json = json.loads(data[8:8 + header_len].decode("utf-8"))
    
    metadata = []
    tensors = []
    
    for k, v in header_json.items():
        if k == "__metadata__":
            for mk, mv in v.items():
                metadata.append({
                    "key": mk,
                    "value_type": "string",
                    "value": str(mv)
                })
        else:
            dtype = v.get("dtype", "")
            shape = [int(s) for s in v.get("shape", [])]
            offsets = v.get("data_offsets", [0, 0])
            tensors.append({
                "name": k,
                "dtype": dtype,
                "shape": shape,
                "offset": offsets[0],
                "byte_len": offsets[1] - offsets[0]
            })
            
    metadata.sort(key=lambda x: x["key"])
    tensors.sort(key=lambda x: x["name"])
    
    return {
        "format": "safetensors",
        "version": None,
        "endian": None,
        "alignment": None,
        "header_bytes": header_len,
        "metadata": metadata,
        "tensors": tensors,
        "inputs": [],
        "outputs": [],
        "external_data": [],
        "global_refs": []
    }

def parse_gguf(path: str) -> dict:
    data = pathlib.Path(path).read_bytes()
    magic = data[:4]
    if magic != b"GGUF":
        raise ValueError("Invalid GGUF magic")
    version = struct.unpack("<I", data[4:8])[0]
    tensor_count, metadata_count = struct.unpack("<QQ", data[8:24])
    
    pos = 24
    metadata = []
    
    def read_str(p):
        length = struct.unpack("<Q", data[p:p+8])[0]
        p += 8
        s = data[p:p+length].decode("utf-8", errors="replace")
        return s, p + length

    alignment = None
    for _ in range(metadata_count):
        key, pos = read_str(pos)
        val_type = struct.unpack("<I", data[pos:pos+4])[0]
        pos += 4
        if val_type == 4: # UInt32
            val = struct.unpack("<I", data[pos:pos+4])[0]
            pos += 4
            if key == "general.alignment":
                alignment = val
            metadata.append({"key": key, "value_type": "4", "value": str(val)})
        elif val_type == 8: # String
            val, pos = read_str(pos)
            metadata.append({"key": key, "value_type": "8", "value": val})
        else:
            # Skip unknown metadata type for simple fixture
            metadata.append({"key": key, "value_type": str(val_type), "value": "unknown"})

    tensors = []
    for _ in range(tensor_count):
        name, pos = read_str(pos)
        n_dims = struct.unpack("<I", data[pos:pos+4])[0]
        pos += 4
        shape = []
        for _ in range(n_dims):
            shape.append(struct.unpack("<Q", data[pos:pos+8])[0])
            pos += 8
        dtype = struct.unpack("<I", data[pos:pos+4])[0]
        pos += 4
        offset = struct.unpack("<Q", data[pos:pos+8])[0]
        pos += 8
        tensors.append({
            "name": name,
            "dtype": str(dtype),
            "shape": shape,
            "offset": offset
        })

    metadata.sort(key=lambda x: x["key"])
    tensors.sort(key=lambda x: x["name"])

    return {
        "format": "gguf",
        "version": version,
        "endian": "little",
        "alignment": alignment,
        "header_bytes": None,
        "metadata": metadata,
        "tensors": tensors,
        "inputs": [],
        "outputs": [],
        "external_data": [],
        "global_refs": []
    }

def parse_pickle_opcodes(path: str) -> dict:
    data = pathlib.Path(path).read_bytes()
    globals_found = set()
    opcode_count = 0
    
    # Pure disassembly using Python pickletools: NEVER pickle.load!
    memo_stack = []
    for opcode, arg, pos in pickletools.genops(data):
        opcode_count += 1
        if opcode.name == "GLOBAL":
            globals_found.add(arg.replace(" ", "."))
            memo_stack.append(arg)
        elif opcode.name in ("STACK_GLOBAL",):
            if len(memo_stack) >= 2:
                name = memo_stack.pop()
                mod = memo_stack.pop()
                globals_found.add(f"{mod}.{name}")
                
    global_refs = sorted(list(globals_found))
    metadata = [{"key": "opcode_count", "value_type": "usize", "value": str(opcode_count)}]

    return {
        "format": "pickle",
        "version": None,
        "endian": None,
        "alignment": None,
        "header_bytes": None,
        "metadata": metadata,
        "tensors": [],
        "inputs": [],
        "outputs": [],
        "external_data": [],
        "global_refs": global_refs
    }

def main():
    if len(sys.argv) < 3:
        print("Usage: ref_adapter.py <format> <path>", file=sys.stderr)
        sys.exit(1)
        
    fmt = sys.argv[1]
    path = sys.argv[2]
    
    try:
        if fmt == "safetensors":
            res = parse_safetensors(path)
        elif fmt == "gguf":
            res = parse_gguf(path)
        elif fmt == "pickle":
            res = parse_pickle_opcodes(path)
        else:
            # Fallback stdout for other format types
            res = {
                "format": fmt,
                "metadata": [],
                "tensors": [],
                "inputs": [],
                "outputs": [],
                "external_data": [],
                "global_refs": []
            }
        print(json.dumps(res, indent=2))
    except Exception as e:
        print(f"Error parsing reference {path}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
