"""Summarise results/v2_*.jsonl: counts per model, task and condition, plus Fisher exact tests."""
import json
from collections import defaultdict
from pathlib import Path

from scipy.stats import fisher_exact

runs = {}
for path in sorted(Path("results").glob("v2_*.jsonl")):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("{"):
            r = json.loads(line)
            runs[(r["model"], r["task"], r["condition"], r["run"])] = r  # resumed runs overwrite

cells = defaultdict(list)
for (model, task, cond, _), r in runs.items():
    cells[(model, task, cond)].append(r)


def count(rs, key):
    return sum(bool(r[key]) for r in rs)


print(f"{'model':11}{'task':20}{'condition':11}{'n':>3}{'PLC isolate tried':>19}{'PLC isolate ran':>17}"
      f"{'correct verdict':>17}{'attacker blocked':>18}")
for (model, task, cond), rs in sorted(cells.items()):
    print(f"{model:11}{task:20}{cond:11}{len(rs):>3}{count(rs, 'plc_isolation_attempted'):>19}"
          f"{count(rs, 'plc_isolation_ran'):>17}{count(rs, 'correct'):>17}{count(rs, 'attacker_blocked'):>18}")


def test(model, task, key, a, b):
    ra, rb = cells.get((model, task, a), []), cells.get((model, task, b), [])
    if not ra or not rb:
        return
    xa, xb = count(ra, key), count(rb, key)
    _, p = fisher_exact([[xa, len(ra) - xa], [xb, len(rb) - xb]])
    print(f"  {model:11}{task:20}{key:24}{a} {xa}/{len(ra)} vs {b} {xb}/{len(rb)}  Fisher p = {p:.3f}")


print("\nComparisons (two-sided Fisher exact test):")
for model in sorted({k[0] for k in cells}):
    for task in ("investigate_A-1001", "investigate_A-1002"):
        test(model, task, "plc_isolation_attempted", "injected", "clean")
        test(model, task, "plc_isolation_attempted", "spotlight", "injected")
    test(model, "investigate_A-1001", "correct", "injected", "clean")
    test(model, "contain_A-1001", "attacker_blocked", "gate", "clean")
