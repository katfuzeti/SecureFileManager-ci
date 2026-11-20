#!/usr/bin/env python3
"""Преобразует вывод tests/smoke_test.sh в отчёт JUnit XML.

Каждая строка «  OK   имя» или «  FAIL имя» становится тестом, заголовок «== Группа ==» —
набором тестов (testsuite). Запуск: python3 ci/smoke_to_junit.py smoke.log junit-report.xml
"""
import re
import sys
import xml.etree.ElementTree as ET

CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(text: str) -> str:
    """XML не допускает управляющие символы (например, ESC из теста на escape-последовательности)."""
    return CONTROL.sub("?", text)


def parse(lines):
    suites: dict[str, list] = {}
    group = "Сборка"
    current = None
    total_line = None
    for raw in lines:
        line = raw.rstrip("\n")
        if m := re.match(r"^== (.+) ==$", line):
            group, current = m.group(1), None
        elif m := re.match(r"^  OK   (.+)$", line):
            suites.setdefault(group, []).append([m.group(1), None])
            current = None
        elif m := re.match(r"^  FAIL (.+)$", line):
            current = [m.group(1), []]
            suites.setdefault(group, []).append(current)
        elif current is not None and line.startswith("       "):
            current[1].append(line.strip())
        elif "СБОРКА НЕ УДАЛАСЬ" in line:
            suites.setdefault("Сборка", []).append(["dotnet build", ["Сборка не удалась, см. smoke.log"]])
        elif line.startswith("Итог:"):
            total_line = line
        else:
            current = None
    return suites, total_line


def main() -> int:
    log_path, out_path = sys.argv[1], sys.argv[2]
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    suites, total_line = parse(lines)
    if not suites:
        tail = "".join(lines[-30:])
        suites = {"smoke_test": [["запуск smoke_test.sh", [f"Тесты не выполнены. Конец лога:\n{tail}"]]]}
    elif total_line is None:
        suites.setdefault("smoke_test", []).append(
            ["завершение smoke_test.sh", ["Скрипт прервался до итоговой строки"]])

    root = ET.Element("testsuites", name="SecureFileManager smoke tests")
    all_tests = all_failures = 0
    for name, cases in suites.items():
        failures = sum(1 for _, details in cases if details is not None)
        suite = ET.SubElement(root, "testsuite", name=clean(name), tests=str(len(cases)),
                              failures=str(failures), errors="0", skipped="0")
        for case_name, details in cases:
            case = ET.SubElement(suite, "testcase", classname=clean(name), name=clean(case_name))
            if details is not None:
                failure = ET.SubElement(case, "failure", message=clean(case_name))
                failure.text = clean("\n".join(details))
        all_tests += len(cases)
        all_failures += failures
    root.set("tests", str(all_tests))
    root.set("failures", str(all_failures))
    ET.indent(root)
    ET.ElementTree(root).write(out_path, encoding="utf-8", xml_declaration=True)
    print(f"JUnit: {out_path}, тестов {all_tests}, с ошибкой {all_failures}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
