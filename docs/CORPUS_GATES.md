# Corpus release gates

Layerfault's corpus harness is useful only if it checks expected security semantics as well as command execution. The RC gate files in `tests/` make those expectations machine-readable.

## Semantic contract

Run the normal master harness, then point the checker at its run directory:

```bash
python3 scripts/check-corpus-contract.py /lab/runs/<run-id>
```

The checker reads `summary.tsv` and, where present, `semantic-summary.tsv`, then classifies failures as:

- `SEMANTIC_MISMATCH`: the JSON decision is correct but the process exit code does not match it;
- `DETECTION_REGRESSION`: actual severity is lower than the expected corpus verdict;
- `FALSE_POSITIVE_REGRESSION`: actual severity is higher than the expected clean/control verdict;
- `MISSING_OPERATION`: an expected corpus operation did not run or was not recorded.

Update `tests/corpus-expectations.json` only when the fixture contract intentionally changes; do not weaken it merely to make a regression green.

## Performance contract

```bash
python3 scripts/check-corpus-performance.py /lab/runs/<run-id>
```

`tests/corpus-performance.json` deliberately uses broad ratios between a cold identity operation and later warm operations. It does not pin exact milliseconds because filesystem cache, CPU scheduling and VPS storage vary. The purpose is to catch accidental reintroduction of whole-model rereads after the cache/fused-streaming improvements.

## Behaviour corpus

Behavioural and differential-backdoor testing requires an explicit local runtime and therefore is separate from the non-executing static corpus gate. Copy `tests/behaviour-corpus-template.tsv`, fill in the exact trusted base/derived paths available in the lab, and run:

```bash
LAYERFAULT_BIN=/usr/local/bin/layerfault \
LAYERFAULT_LLAMA_RUNTIME=/path/to/llama-cli \
bash scripts/behaviour-corpus-gate.sh /path/to/behaviour-corpus.tsv
```

Run the clean control alongside malicious/research derivatives. Behavioural evidence can demonstrate a tested regression or trigger under the recorded runtime/probes; it cannot prove that no unknown backdoor exists.
