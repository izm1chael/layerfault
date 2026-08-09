# Corpus release gates

Layerfault's corpus harness is useful only if it checks expected security semantics as well as command execution. The RC gate files in `tests/` make those expectations machine-readable.

## Semantic contract

Run the normal master harness, then point the checker at its run directory:

```bash
python3 scripts/corpus/check-contract.py /lab/runs/<run-id>
```

The checker reads `summary.tsv` and, where present, `semantic-summary.tsv`, then classifies failures as:

- `SEMANTIC_MISMATCH`: the JSON decision is correct but the process exit code does not match it;
- `DETECTION_REGRESSION`: actual severity is lower than the expected corpus verdict;
- `FALSE_POSITIVE_REGRESSION`: actual severity is higher than the expected clean/control verdict;
- `MISSING_OPERATION`: an expected corpus operation did not run or was not recorded.

Update `tests/corpus-expectations.json` only when the fixture contract intentionally changes; do not weaken it merely to make a regression green.

## Performance contract

```bash
python3 scripts/corpus/check-performance.py /lab/runs/<run-id>
```

`tests/corpus-performance.json` deliberately uses broad ratios between a cold identity operation and later warm operations. It does not pin exact milliseconds because filesystem cache, CPU scheduling and VPS storage vary. The purpose is to catch accidental reintroduction of whole-model rereads after the cache/fused-streaming improvements.

## Behaviour corpus

Behavioural and differential-backdoor testing requires an explicit local runtime and therefore is separate from the non-executing static corpus gate. Copy `tests/behaviour-corpus-template.tsv`, fill in the exact trusted base/derived paths available in the lab, and run:

```bash
LAYERFAULT_BIN=/usr/local/bin/layerfault \
LAYERFAULT_LLAMA_RUNTIME=/path/to/llama-cli \
bash scripts/corpus/behaviour-gate.sh /path/to/behaviour-corpus.tsv
```

Run the clean control alongside malicious/research derivatives. Behavioural evidence can demonstrate a tested regression or trigger under the recorded runtime/probes; it cannot prove that no unknown backdoor exists.

## Active sandbox corpus gate

Active execution is deliberately separate from the static master harness. Create a lab-specific copy of `tests/active-sandbox-corpus-template.tsv`, point it at local model/base directories, then run:

```bash
export LAYERFAULT_BIN=/usr/local/bin/layerfault
export LAYERFAULT_PYTHON_RUNTIME=/usr/bin/python3
export LAYERFAULT_LLAMA_RUNTIME=/opt/llama/llama-cli
bash scripts/lab/prepare-active-fixtures.sh
bash scripts/corpus/active-sandbox-gate.sh /lab/active-sandbox-corpus.tsv
```

The active gate validates not only expected process exit codes but the sandbox contract in emitted JSON. External reports must show filesystem/home/environment/network/PID/IPC/UTS isolation and dropped capabilities. Rows that request `allow-static-blocked` or `execute-custom-code` additionally require syscall tracing, resource limits, and a reported address-space ceiling.

The manifest supports `behaviour` and `compare` modes plus `llama-cpp` and `transformers` runtimes. A Transformers comparison can point `base` at a local base-model package and `model` at a PEFT/LoRA adapter package. Keep clean controls next to research/backdoored derivatives. Do not change an expected malicious verdict merely because a probe suite failed to reproduce a trigger; improve/record the fixture and probe evidence instead.

Downloaded archives/snapshots cannot preserve an external ONNX hardlink relationship. To test `LF-ONNX-EXTERNAL-HARDLINK` end-to-end, explicitly recreate the alias after download with `scripts/lab/prepare-active-fixtures.sh --onnx-model ... --onnx-sidecar ...` before the static harness.
