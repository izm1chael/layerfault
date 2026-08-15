# Persistent Inventory and Drift Watch

Layerfault can persist a bounded local model inventory, compare snapshots, attach trusted admission receipts to entries, and watch for subsequent drift. Inventory entries use stable keys while diffing also reconciles source/path changes so mutation at an existing model location is represented as modification rather than a misleading remove/add pair.

Approval state is `unknown`, `approved`, `stale`, or `blocked`. A receipt is only accepted when its signature is trusted/authorized and its artifact/package identity matches the inventory entry. Ruleset or identity drift can make a prior approval stale.

```text
layerfault inventory snapshot --state inventory.json --dir ./models
layerfault inventory diff --previous inventory.json --scan
layerfault inventory approve --state inventory.json --identity <id> --receipt admission.json
layerfault inventory watch --state inventory.json --interval 60 --jsonl
```

The minimum watch interval is 30 seconds.
