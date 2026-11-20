#!/usr/bin/env python3
"""Порог качества для Semgrep: прерывает конвейер при находках уровня High и Critical.

У правил Semgrep уровни ERROR / WARNING / INFO (в новых версиях также CRITICAL, HIGH,
MEDIUM, LOW). Соответствие: ERROR -> High, WARNING -> Medium, INFO -> Low.
Порог задаётся переменной SAST_FAIL_ON (по умолчанию HIGH).
Запуск: python3 ci/sast_gate.py semgrep-report.json
"""
import json
import os
import sys

RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEMGREP_TO_LEVEL = {"INFO": "LOW", "WARNING": "MEDIUM", "ERROR": "HIGH",
                    "LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}


def level(result: dict) -> str:
    severity = str(result.get("extra", {}).get("severity", "INFO")).upper()
    return SEMGREP_TO_LEVEL.get(severity, "LOW")


def main() -> int:
    threshold = os.environ.get("SAST_FAIL_ON", "HIGH").upper()
    if threshold not in RANK:
        print(f"Неизвестный порог SAST_FAIL_ON={threshold}")
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        report = json.load(fh)

    for err in report.get("errors", []):
        print(f"[предупреждение Semgrep] {err.get('type', '')}: {err.get('message', '')[:200]}")

    results = report.get("results", [])
    counts = {name: 0 for name in RANK}
    blocking = []
    for r in results:
        lvl = level(r)
        counts[lvl] += 1
        start = r.get("start", {}).get("line", "?")
        msg = " ".join(str(r.get("extra", {}).get("message", "")).split())
        line = f"[{lvl:<8}] {r.get('path')}:{start}  {r.get('check_id')}\n           {msg[:300]}"
        print(line)
        if RANK[lvl] >= RANK[threshold]:
            blocking.append(line)

    print("\nНаходки Semgrep: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    if blocking:
        print(f"SAST: найдено {len(blocking)} проблем уровня {threshold} и выше, сборка остановлена.")
        return 1
    print(f"SAST: проблем уровня {threshold} и выше нет.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
