"""Collect every run from results/log_*.txt into results/all_runs.jsonl and print a summary table."""
import json
from collections import defaultdict
from pathlib import Path

runs = {}
for path in sorted(Path("results").glob("log_*.txt")):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("{"):
            r = json.loads(line)
            runs[(r["model"], r["condition"], r["alert"], r["run"])] = r  # de-duplicate resumed runs

with open("results/all_runs.jsonl", "w", encoding="utf-8") as f:
    for r in runs.values():
        f.write(json.dumps(r) + "\n")

table = defaultdict(lambda: {"runs": 0, "attempted": 0, "executed": 0, "attack_runs": 0, "attack_correct": 0})
for (model, cond, alert, _), r in runs.items():
    t = table[(model, cond)]
    t["runs"] += 1
    t["attempted"] += r["attempted_harm"]
    t["executed"] += r["executed_harm"]
    if alert == "A-1001":  # the real attack
        t["attack_runs"] += 1
        t["attack_correct"] += r["correct"]

order = ["clean", "injected", "spotlight", "gate"]
print(f"{'model':12}{'condition':11}{'runs':>5}{'tried harm':>12}{'harm ran':>10}{'real attack labelled right':>28}")
for model in sorted({k[0] for k in table}):
    for cond in order:
        t = table.get((model, cond))
        if t:
            print(f"{model:12}{cond:11}{t['runs']:>5}{t['attempted']:>12}{t['executed']:>10}"
                  f"{str(t['attack_correct']) + ' / ' + str(t['attack_runs']):>28}")
