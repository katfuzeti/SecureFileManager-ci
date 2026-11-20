#!/usr/bin/env python3
"""Локальный CI/CD-раннер для SecureFileManager.

Читает конвейер из .gitlab-ci.yml (поддерживается подмножество синтаксиса GitLab CI:
stages, variables, image, before_script, script, dependencies, artifacts, cache,
allow_failure, timeout) и выполняет каждую джобу в отдельном Docker-контейнере.

Запуск:
    python3 ci/runner.py                 # весь конвейер
    python3 ci/runner.py --list          # показать стадии и джобы
    python3 ci/runner.py --stages build,test
    python3 ci/runner.py --dry-run       # только показать команды docker

Настройки раннера (лимиты, секреты, доступ к Docker-сокету) лежат в ci/runner.yml,
отдельно от описания конвейера, как config.toml у gitlab-runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Нужен модуль PyYAML: sudo apt install python3-yaml")

ROOT = Path(__file__).resolve().parent.parent
RUNNER_CONFIG = ROOT / "ci" / "runner.yml"

# Ключи верхнего уровня .gitlab-ci.yml, которые не являются джобами.
RESERVED_KEYS = {"stages", "variables", "default", "include", "workflow", "image",
                 "services", "cache", "before_script", "after_script"}

# Что никогда не попадает в рабочую копию джобы.
SNAPSHOT_EXCLUDE = {".git", ".local-ci", "bin", "obj", "publish", ".nuget", ".ci-home",
                    ".trivy-cache"}
SNAPSHOT_EXCLUDE_FILES = {"ci/secrets.env"}

USE_COLOR = sys.stdout.isatty()


def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def info(msg: str) -> None:
    print(color(msg, "36"), flush=True)


def warn(msg: str) -> None:
    print(color(f"[!] {msg}", "33"), flush=True)


def fail(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(color(f"[X] {msg}", "31"), file=sys.stderr, flush=True)
    sys.exit(2)


# ---------------------------------------------------------------- конфигурация

@dataclass
class Job:
    name: str
    stage: str
    image: str
    script: list[str]
    before_script: list[str] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)
    dependencies: list[str] | None = None
    artifacts: dict = field(default_factory=dict)
    cache: dict | None = None
    allow_failure: bool = False
    timeout: int = 1800


def parse_duration(value, default: int) -> int:
    """'30m', '1h 10m', '90s', 600 -> секунды."""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    total = 0
    for number, unit in re.findall(r"(\d+)\s*([hms]?)", str(value)):
        total += int(number) * {"h": 3600, "m": 60, "s": 1, "": 60}[unit]
    return total or default


def as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def load_yaml(path: Path) -> dict:
    if not path.is_file():
        fail(f"Не найден файл {path.relative_to(ROOT)}")
    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as e:
        fail(f"Ошибка синтаксиса в {path.name}:\n{e}")
    if not isinstance(data, dict):
        fail(f"{path.name}: ожидался словарь верхнего уровня")
    return data


def load_pipeline(path: Path, default_timeout: int) -> tuple[list[str], dict, list[Job]]:
    data = load_yaml(path)
    stages = as_list(data.get("stages")) or ["build", "test", "deploy"]
    global_vars = {k: str(v) for k, v in (data.get("variables") or {}).items()}
    default = data.get("default") or {}
    default_image = default.get("image") or data.get("image")

    jobs: list[Job] = []
    for name, spec in data.items():
        if name in RESERVED_KEYS or name.startswith(".") or not isinstance(spec, dict):
            continue
        if "script" not in spec:
            fail(f"Джоба {name}: нет ключа script")
        stage = spec.get("stage", "test")
        if stage not in stages:
            fail(f"Джоба {name}: стадия {stage} не объявлена в stages")
        image = spec.get("image", default_image)
        if isinstance(image, dict):
            image = image.get("name")
        if not image:
            fail(f"Джоба {name}: не указан image")
        deps = spec.get("dependencies")
        jobs.append(Job(
            name=name,
            stage=stage,
            image=str(image),
            script=as_list(spec["script"]),
            before_script=as_list(spec.get("before_script", default.get("before_script"))),
            variables={k: str(v) for k, v in (spec.get("variables") or {}).items()},
            dependencies=None if deps is None else as_list(deps),
            artifacts=spec.get("artifacts") or {},
            cache=spec.get("cache", default.get("cache")),
            allow_failure=bool(spec.get("allow_failure", False)),
            timeout=parse_duration(spec.get("timeout"), default_timeout),
        ))

    names = {j.name for j in jobs}
    for job in jobs:
        for dep in job.dependencies or []:
            if dep not in names:
                fail(f"Джоба {job.name}: неизвестная зависимость {dep}")
            if stages.index(next(j.stage for j in jobs if j.name == dep)) >= stages.index(job.stage):
                fail(f"Джоба {job.name}: зависимость {dep} должна быть на более ранней стадии")
    return stages, global_vars, jobs


# ---------------------------------------------------------------- секреты

def load_secrets(cfg: dict) -> dict[str, str]:
    """Секреты берутся из окружения раннера, а если там нет — из ci/secrets.env (права 600)."""
    wanted = cfg.get("secrets") or {}
    file_values: dict[str, str] = {}
    secrets_file = ROOT / cfg.get("secrets_file", "ci/secrets.env")
    if secrets_file.exists():
        mode = secrets_file.stat().st_mode
        if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
            fail(f"{secrets_file.relative_to(ROOT)} доступен другим пользователям. Выполните: chmod 600 {secrets_file.relative_to(ROOT)}")
        for raw in secrets_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            file_values[key.strip()] = value.strip().strip("'\"")

    secrets: dict[str, str] = {}
    for name in wanted:
        value = os.environ.get(name) or file_values.get(name)
        if value is None:
            continue
        if len(value) < 8:
            warn(f"Секрет {name} короче 8 символов: маскирование в логах ненадёжно")
        secrets[name] = value
    return secrets


class Masker:
    def __init__(self, values: list[str]):
        # Длинные значения заменяем первыми, чтобы не оставлять «хвосты».
        self.values = sorted({v for v in values if v}, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        for value in self.values:
            text = text.replace(value, "[MASKED]")
        return text


# ---------------------------------------------------------------- вспомогательное

VAR_RE = re.compile(r"\$\{(\w+)\}|\$(\w+)")


def expand(value: str, env: dict[str, str]) -> str:
    return VAR_RE.sub(lambda m: env.get(m.group(1) or m.group(2), m.group(0)), value)


def git(*args: str) -> str | None:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def snapshot_files() -> list[Path]:
    """Список файлов проекта, которые копируются в рабочую копию джобы."""
    listed = git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if listed is not None:
        files = [Path(p) for p in listed.split("\0") if p]
    else:
        files = []
        for path in ROOT.rglob("*"):
            rel = path.relative_to(ROOT)
            if any(part in SNAPSHOT_EXCLUDE for part in rel.parts):
                continue
            if path.is_file() or path.is_symlink():
                files.append(rel)
    result = []
    for rel in files:
        if rel.as_posix() in SNAPSHOT_EXCLUDE_FILES or any(p in SNAPSHOT_EXCLUDE for p in rel.parts):
            continue
        if rel.suffix in {".db", ".db-wal", ".db-shm"}:
            continue
        if (ROOT / rel).exists() or (ROOT / rel).is_symlink():
            result.append(rel)
    return result


def copy_tree(src: Path, dst: Path) -> None:
    """Копирует каталог с объединением, без перехода по символическим ссылкам."""
    for path in src.rglob("*"):
        target = dst / path.relative_to(src)
        if path.is_symlink():
            continue
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def inside(base: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def collect(workspace: Path, patterns: list[str], dest: Path) -> list[str]:
    """Собирает файлы по шаблонам из рабочей копии. Ссылки и пути за её пределами пропускаются."""
    found: list[str] = []
    for pattern in patterns:
        pattern = pattern.rstrip("/")
        if pattern.startswith("/") or ".." in Path(pattern).parts:
            warn(f"Шаблон {pattern} ведёт за пределы проекта и пропущен")
            continue
        for match in sorted(workspace.glob(pattern)):
            if match.is_symlink() or not inside(workspace, match):
                warn(f"{match.relative_to(workspace)}: символическая ссылка или путь вне проекта, пропущено")
                continue
            rel = match.relative_to(workspace)
            if match.is_dir():
                copy_tree(match, dest / rel)
            else:
                (dest / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(match, dest / rel)
            found.append(rel.as_posix())
    return found


def cache_key(cache: dict, job: Job) -> str:
    key = cache.get("key", "default")
    if isinstance(key, dict):
        digest = hashlib.sha256()
        for name in as_list(key.get("files")):
            path = ROOT / name
            digest.update(name.encode())
            if path.is_file():
                digest.update(path.read_bytes())
        prefix = key.get("prefix", "")
        key = f"{prefix}-{digest.hexdigest()[:16]}" if prefix else digest.hexdigest()[:16]
    key = expand(str(key), {"CI_JOB_NAME": job.name, "CI_JOB_STAGE": job.stage})
    return re.sub(r"[^A-Za-z0-9_.-]", "_", key)


def junit_summary(path: Path) -> str:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as e:
        return f"не удалось разобрать ({e})"
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    tests = sum(int(s.get("tests", 0)) for s in suites)
    failures = sum(int(s.get("failures", 0)) + int(s.get("errors", 0)) for s in suites)
    lines = [f"тестов {tests}, успешно {tests - failures}, с ошибкой {failures}"]
    for case in root.iter("testcase"):
        if case.find("failure") is not None or case.find("error") is not None:
            lines.append(f"    FAIL {case.get('classname')}: {case.get('name')}")
    return "\n".join(lines)


# ---------------------------------------------------------------- Docker

def docker(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], check=check, text=True,
                          capture_output=capture)


def ensure_docker() -> None:
    if shutil.which("docker") is None:
        fail("Docker не установлен (см. раздел 1 инструкции)")
    result = docker("info", "--format", "{{.ServerVersion}}", check=False, capture=True)
    if result.returncode != 0:
        fail("Нет доступа к Docker. Запущен ли демон и состоит ли пользователь в группе docker?\n"
             + result.stderr.strip())


def ensure_local_images(cfg: dict, dry_run: bool) -> None:
    """Собирает вспомогательные образы (например, SDK + python3), если их нет или Dockerfile изменился."""
    for name, dockerfile in (cfg.get("local_images") or {}).items():
        path = ROOT / dockerfile
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if dry_run:
            info(f"[dry-run] docker build -t {name} -f {dockerfile} ci/images")
            continue
        current = docker("image", "inspect", "-f", '{{index .Config.Labels "ci.dockerfile.sha256"}}',
                         name, check=False, capture=True)
        if current.returncode == 0 and current.stdout.strip() == digest:
            continue
        info(f"Сборка вспомогательного образа {name} из {dockerfile}")
        docker("build", "--pull", "-t", name, "--label", f"ci.dockerfile.sha256={digest}",
               "-f", str(path), str(path.parent))


# ---------------------------------------------------------------- раннер

class Runner:
    def __init__(self, cfg: dict, args: argparse.Namespace):
        self.cfg = cfg
        self.args = args
        self.state = ROOT / cfg.get("state_dir", ".local-ci")
        self.mount = cfg.get("project_mount", "/builds/project")
        self.pipeline_file = ROOT / cfg.get("pipeline_file", ".gitlab-ci.yml")
        self.stages, self.global_vars, self.jobs = load_pipeline(
            self.pipeline_file, parse_duration(cfg.get("default_timeout"), 1800))
        self.secrets = load_secrets(cfg)
        self.mask = Masker(list(self.secrets.values()))
        self.run_id = time.strftime("%Y%m%d-%H%M%S")
        self.run_dir = self.state / "runs" / self.run_id
        self.results: dict[str, dict] = {}
        self.current_container: str | None = None

    # -- вывод

    def log(self, fh, text: str) -> None:
        text = self.mask(text)
        sys.stdout.write(text)
        sys.stdout.flush()
        fh.write(text)

    # -- подготовка рабочей копии

    def make_snapshot(self) -> Path:
        source = self.run_dir / "source"
        for rel in snapshot_files():
            src, dst = ROOT / rel, source / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_symlink():
                os.symlink(os.readlink(src), dst)
            else:
                shutil.copy2(src, dst)
        return source

    def predefined(self, job: Job) -> dict[str, str]:
        sha = git("rev-parse", "HEAD") or "0" * 40
        return {
            "CI": "true",
            "CI_LOCAL_RUNNER": "python",
            "CI_PROJECT_DIR": self.mount,
            "CI_PROJECT_NAME": ROOT.name,
            "CI_PIPELINE_ID": self.run_id.replace("-", ""),
            "CI_JOB_NAME": job.name,
            "CI_JOB_STAGE": job.stage,
            "CI_COMMIT_SHA": sha,
            "CI_COMMIT_SHORT_SHA": sha[:8],
            "CI_COMMIT_REF_NAME": git("rev-parse", "--abbrev-ref", "HEAD") or "local",
            "HOME": f"{self.mount}/.ci-home",
        }

    def job_env(self, job: Job) -> dict[str, str]:
        env = self.predefined(job)
        for source in (self.global_vars, job.variables):
            for key, value in source.items():
                env[key] = expand(value, env)
        allowed = self.cfg.get("secrets") or {}
        for name, value in self.secrets.items():
            if job.name in as_list(allowed.get(name)):
                env[name] = value
        return env

    def write_script(self, job: Job, workspace: Path) -> None:
        lines = ["set -e"]
        for command in job.before_script + job.script:
            command = command.rstrip()
            lines.append(f"printf '%s\\n' {shlex_quote('$ ' + command)}")
            lines.append(command)
        (workspace / ".ci-job.sh").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def docker_command(self, job: Job, workspace: Path, env: dict[str, str]) -> list[str]:
        limits = self.cfg.get("limits") or {}
        name = f"localci-{self.run_id}-{job.name}".replace("_", "-")
        cmd = ["docker", "run", "--rm", "--name", name,
               "-v", f"{workspace}:{self.mount}", "-w", self.mount,
               "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
               "--cpus", str(limits.get("cpus", "2")),
               "--memory", str(limits.get("memory", "4g")),
               "--pids-limit", str(limits.get("pids", 4096))]
        if os.name == "posix" and hasattr(os, "getuid"):
            cmd += ["--user", f"{os.getuid()}:{os.getgid()}"]
        if job.name in as_list(self.cfg.get("docker_socket_jobs")):
            sock = Path("/var/run/docker.sock")
            cmd += ["-v", f"{sock}:{sock}"]
            if sock.exists():
                cmd += ["--group-add", str(sock.stat().st_gid)]
        for key, value in env.items():
            if key in self.secrets:
                # Значение секрета не попадает в командную строку (её видно в ps):
                # docker берёт его из окружения процесса раннера.
                cmd += ["-e", key]
            else:
                cmd += ["-e", f"{key}={value}"]
        cmd += ["--entrypoint", "sh", job.image, f"{self.mount}/.ci-job.sh"]
        self.current_container = name
        return cmd

    # -- выполнение одной джобы

    def run_job(self, job: Job) -> str:
        workspace = self.run_dir / "jobs" / job.name / "project"
        artifacts_dir = self.run_dir / "artifacts" / job.name
        log_path = self.run_dir / "logs" / f"{job.name}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        print()
        info(f"━━━ Джоба {job.name} (стадия {job.stage}, образ {job.image}) ━━━")
        shutil.copytree(self.run_dir / "source", workspace, symlinks=True)
        (workspace / ".ci-home").mkdir(exist_ok=True)

        # Артефакты предыдущих стадий.
        deps = job.dependencies
        if deps is None:
            earlier = self.stages[: self.stages.index(job.stage)]
            deps = [j.name for j in self.jobs if j.stage in earlier]
        for dep in deps:
            dep_dir = self.run_dir / "artifacts" / dep
            if dep_dir.exists():
                copy_tree(dep_dir, workspace)
                info(f"Артефакты {dep} восстановлены")
            elif self.results.get(dep, {}).get("status") is None:
                warn(f"{dep} не запускалась в этом конвейере, её артефактов нет")

        # Кэш.
        cache_dir = None
        cache = job.cache if isinstance(job.cache, dict) else None
        if cache:
            cache_dir = self.state / "cache" / cache_key(cache, job)
            if cache.get("policy", "pull-push") in ("pull", "pull-push") and cache_dir.exists():
                copy_tree(cache_dir, workspace)
                info(f"Кэш {cache_dir.name} восстановлен")

        env = self.job_env(job)
        self.write_script(job, workspace)
        cmd = self.docker_command(job, workspace, env)

        started = time.time()
        status = "failed"
        with log_path.open("w", encoding="utf-8") as fh:
            proc_env = dict(os.environ)
            proc_env.update({k: v for k, v in env.items() if k in self.secrets})
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    env=proc_env, text=True, errors="replace", encoding="utf-8")
            timed_out = threading.Event()
            container = self.current_container

            def on_timeout() -> None:
                timed_out.set()
                docker("kill", container or "", check=False, capture=True)

            watchdog = threading.Timer(job.timeout, on_timeout)
            watchdog.start()
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    self.log(fh, line)
                code = proc.wait()
            finally:
                watchdog.cancel()
                self.current_container = None
            if timed_out.is_set():
                self.log(fh, f"\nПревышено время выполнения ({job.timeout} с)\n")
            elif code:
                self.log(fh, f"\nКод завершения: {code}\n")
            else:
                status = "success"
        duration = time.time() - started

        # Артефакты.
        when = job.artifacts.get("when", "on_success")
        if when == "always" or (when == "on_success" and status == "success") \
                or (when == "on_failure" and status != "success"):
            patterns = as_list(job.artifacts.get("paths"))
            reports = job.artifacts.get("reports") or {}
            patterns += as_list(reports.get("junit"))
            saved = collect(workspace, patterns, artifacts_dir)
            if saved:
                info(f"Артефакты сохранены: {', '.join(sorted(set(saved)))}")
            for report in as_list(reports.get("junit")):
                for path in artifacts_dir.glob(report):
                    info(f"JUnit {path.name}: {junit_summary(path)}")

        # Кэш сохраняется только после успешной джобы.
        if cache and cache_dir and status == "success" and cache.get("policy", "pull-push") in ("push", "pull-push"):
            tmp = cache_dir.with_name(cache_dir.name + ".tmp")
            shutil.rmtree(tmp, ignore_errors=True)
            tmp.mkdir(parents=True)
            collect(workspace, as_list(cache.get("paths")), tmp)
            shutil.rmtree(cache_dir, ignore_errors=True)
            tmp.rename(cache_dir)
            info(f"Кэш {cache_dir.name} обновлён")

        if status != "success" and job.allow_failure:
            status = "allowed-failure"
        self.results[job.name] = {"stage": job.stage, "status": status,
                                  "duration": round(duration, 1), "log": str(log_path.relative_to(ROOT))}
        if status == "success" or not self.args.keep_failed:
            shutil.rmtree(workspace.parent, ignore_errors=True)
        mark = {"success": color("УСПЕХ", "32"), "allowed-failure": color("ОШИБКА (допустима)", "33")}
        print(f"Джоба {job.name}: {mark.get(status, color('ОШИБКА', '31'))} за {duration:.0f} с", flush=True)
        return status

    # -- конвейер целиком

    def selected_stages(self) -> list[str]:
        if not self.args.stages:
            return self.stages
        chosen = [s.strip() for s in self.args.stages.split(",") if s.strip()]
        for s in chosen:
            if s not in self.stages:
                fail(f"Нет стадии {s}. Есть: {', '.join(self.stages)}")
        return [s for s in self.stages if s in chosen]

    def list_jobs(self) -> None:
        for stage in self.stages:
            print(f"{stage}:")
            for job in (j for j in self.jobs if j.stage == stage):
                print(f"  - {job.name:<16} {job.image}")

    def dry_run(self) -> None:
        ensure_local_images(self.cfg, dry_run=True)
        for stage in self.selected_stages():
            for job in (j for j in self.jobs if j.stage == stage):
                env = self.job_env(job)
                ws = self.run_dir / "jobs" / job.name / "project"
                print(f"\n# {stage} / {job.name}")
                print(" ".join(self.docker_command(job, ws, env)))
                for line in job.before_script + job.script:
                    print(f"    $ {line}")

    def cleanup_old_runs(self) -> None:
        keep = int(self.cfg.get("keep_runs", 5))
        runs = sorted((self.state / "runs").glob("*"))
        for old in runs[:-keep] if keep > 0 else []:
            shutil.rmtree(old, ignore_errors=True)

    def run(self) -> int:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            warn("Раннер запущен от root: контейнеры джоб тоже будут работать от root. "
                 "Запускайте от обычного пользователя из группы docker")
        ensure_docker()
        ensure_local_images(self.cfg, dry_run=False)
        self.run_dir.mkdir(parents=True)
        info(f"Конвейер {self.run_id}: {self.pipeline_file.name}, каталог {self.run_dir.relative_to(ROOT)}")
        if git("status", "--porcelain"):
            warn("В рабочем каталоге есть незакоммиченные изменения: они тоже попадут в сборку")
        self.make_snapshot()
        missing = [n for n in (self.cfg.get("secrets") or {}) if n not in self.secrets]
        for name in missing:
            warn(f"Секрет {name} не задан (ни в окружении, ни в {self.cfg.get('secrets_file')})")

        overall = "success"
        for stage in self.selected_stages():
            info(f"\n══════ Стадия {stage} ══════")
            stage_failed = False
            for job in (j for j in self.jobs if j.stage == stage):
                if self.run_job(job) == "failed":
                    stage_failed = True
            if stage_failed:
                overall = "failed"
                break

        for job in self.jobs:
            self.results.setdefault(job.name, {"stage": job.stage, "status": "skipped"})
        summary = {"run_id": self.run_id, "status": overall, "jobs": self.results}
        (self.run_dir / "pipeline.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                                    encoding="utf-8")
        shutil.rmtree(self.run_dir / "source", ignore_errors=True)
        self.print_summary(overall)
        self.cleanup_old_runs()
        return 0 if overall == "success" else 1

    def print_summary(self, overall: str) -> None:
        print()
        info("━━━ Итог конвейера ━━━")
        names = {"success": "успех", "failed": "ошибка", "skipped": "пропущена",
                 "allowed-failure": "ошибка (допустима)"}
        for job in self.jobs:
            r = self.results[job.name]
            duration = f"{r['duration']:>6.1f} с" if "duration" in r else "       "
            print(f"  {job.stage:<8} {job.name:<16} {names[r['status']]:<20} {duration}")
        print(f"\nАртефакты: {(self.run_dir / 'artifacts').relative_to(ROOT)}")
        print(f"Логи:      {(self.run_dir / 'logs').relative_to(ROOT)}")
        verdict = color("КОНВЕЙЕР ПРОЙДЕН", "32") if overall == "success" else color("КОНВЕЙЕР НЕ ПРОЙДЕН", "31")
        print(verdict)

    def interrupt(self, *_):
        if self.current_container:
            docker("kill", self.current_container, check=False, capture=True)
        print("\nПрервано пользователем", file=sys.stderr)
        sys.exit(130)


def shlex_quote(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"


def main() -> int:
    parser = argparse.ArgumentParser(description="Локальный CI/CD-раннер (Python + Docker)")
    parser.add_argument("--list", action="store_true", help="показать стадии и джобы")
    parser.add_argument("--stages", help="запустить только эти стадии, через запятую")
    parser.add_argument("--dry-run", action="store_true", help="показать команды, ничего не запуская")
    parser.add_argument("--config", default=str(RUNNER_CONFIG), help="файл настроек раннера")
    parser.add_argument("--keep-failed", action="store_true",
                        help="не удалять рабочую копию упавшей джобы (для отладки)")
    args = parser.parse_args()

    cfg = load_yaml(Path(args.config).resolve())
    runner = Runner(cfg, args)
    if args.list:
        runner.list_jobs()
        return 0
    if args.dry_run:
        runner.dry_run()
        return 0
    signal.signal(signal.SIGINT, runner.interrupt)
    signal.signal(signal.SIGTERM, runner.interrupt)
    return runner.run()


if __name__ == "__main__":
    sys.exit(main())
