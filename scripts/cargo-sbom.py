#!/usr/bin/env python3
"""Create a deterministic CycloneDX 1.7 SBOM from Cargo.lock using stdlib only."""
from __future__ import annotations
import hashlib, json, pathlib, sys
try:
    import tomllib
except ImportError as exc:
    raise SystemExit("Python 3.11+ is required for tomllib") from exc
root=pathlib.Path(__file__).resolve().parents[1]
lock=tomllib.loads((root/"Cargo.lock").read_text())
manifest=tomllib.loads((root/"Cargo.toml").read_text())
pkg=manifest["package"]
components=[]
for p in sorted(lock.get("package",[]), key=lambda x:(x.get("name",""),x.get("version",""))):
    if p.get("name")==pkg["name"] and p.get("version")==pkg["version"]: continue
    item={"type":"library","name":p["name"],"version":p["version"],"purl":f"pkg:cargo/{p['name']}@{p['version']}"}
    if p.get("checksum"): item["hashes"]=[{"alg":"SHA-256","content":p["checksum"]}]
    components.append(item)
seed=json.dumps(components,sort_keys=True,separators=(",",":")).encode(); digest=hashlib.sha256(seed).hexdigest()
bom={
 "bomFormat":"CycloneDX","specVersion":"1.7","serialNumber":f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}","version":1,
 "metadata":{"component":{"type":"application","name":pkg["name"],"version":pkg["version"]}},
 "components":components
}
out=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else root/"dist"/"layerfault-sbom.cdx.json"
out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(bom,indent=2)+"\n")
print(out)
