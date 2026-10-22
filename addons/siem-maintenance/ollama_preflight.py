#!/usr/bin/env python3
"""Ollama: print host specs, recommend models, check tags, optional ``ollama pull``.

Uses only the standard library except the installers already ship ``requests``;
HTTP falls back to ``urllib`` if needed.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable


def memory_gb() -> float:
    """Approximate installed RAM in GiB (best effort, cross-platform)."""
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return round(kb / (1024 * 1024), 2)
        if system == "Darwin":
            out = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                b = int(out.stdout.strip())
                return round(b / (1024**3), 2)
        if system == "Windows":
            ps = (
                "[math]::Round((Get-CimInstance Win32_ComputerSystem)"
                ".TotalPhysicalMemory / 1GB, 2)"
            )
            out = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    ps,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                return float(out.stdout.strip().replace(",", "."))
    except (OSError, ValueError, IndexError):
        pass
    return 8.0


def has_nvidia_gpu() -> bool:
    if not shutil.which("nvidia-smi"):
        return False
    try:
        r = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return r.returncode == 0 and bool((r.stdout or "").strip())
    except OSError:
        return False


def cpu_summary() -> str:
    try:
        return platform.processor() or platform.machine() or "unknown"
    except Exception:
        return "unknown"


def recommend_models(ram_gb: float, gpu: bool) -> list[tuple[str, str]]:
    """(model_tag, rationale) ordered best-first for SIEM Chat narrative (short answers OK)."""
    suffix = " GPU detected - larger 7B models are more usable." if gpu else " CPU-only - prefer smaller tags if generation is slow."

    if ram_gb < 6:
        return [
            ("gemma2:2b", f"~{ram_gb} GiB RAM: smallest sensible models.{suffix}"),
            ("phi3", "Microsoft Phi-3 small; good on low memory."),
            ("tinyllama", "Smallest; quality trade-off."),
        ]
    if ram_gb < 12:
        return [
            ("llama3.2", f"~{ram_gb} GiB RAM: balanced default (matches installer preset).{suffix}"),
            ("mistral", "Strong 7B-class general model."),
            ("gemma2:2b", "Fallback if 7B is too heavy on CPU."),
        ]
    return [
        ("llama3.2", f"~{ram_gb} GiB RAM: solid default.{suffix}"),
        ("llama3.1", "More context window; needs more RAM/VRAM."),
        ("mistral", "7B-class alternative."),
    ]


def print_recommendations() -> None:
    ram = memory_gb()
    gpu = has_nvidia_gpu()
    print("--- This machine (approximate) ---")
    print(f"  OS: {platform.system()} {platform.release()}")
    print(f"  RAM: ~{ram} GiB")
    print(f"  CPU: {cpu_summary()}")
    print(f"  NVIDIA GPU (nvidia-smi): {'yes' if gpu else 'no'}")
    print()
    print("Suggested Ollama tags for maintenance Chat (pick one in the installer menu):")
    for tag, why in recommend_models(ram, gpu):
        print(f"  - {tag}")
        print(f"      {why}")
    print()


def _normalize_base(url: str) -> str:
    u = (url or "http://localhost:11434").strip().rstrip("/")
    if not u.startswith("http"):
        u = "http://" + u
    return u


def _ollama_host_for_cli(server_base: str) -> str:
    """OLLAMA_HOST for the ``ollama`` CLI is ``host:port``, not a full URL (see Ollama FAQ)."""
    base = _normalize_base(server_base)
    parsed = urllib.parse.urlparse(base)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 11434)
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _resolve_ollama_cli() -> str | None:
    """PATH lookup plus common install locations (Linux minimal shells often miss ``/usr/local/bin``)."""
    override = (os.environ.get("OLLAMA_CLI") or "").strip()
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    w = shutil.which("ollama")
    if w:
        return w
    candidates = [
        "/usr/local/bin/ollama",
        "/usr/bin/ollama",
        "/bin/ollama",
        os.path.expanduser("~/.local/bin/ollama"),
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def _enriched_path(env: dict[str, str]) -> None:
    """Prepend standard locations so ``ollama`` is found in non-login / sudo-minimal PATH."""
    extra = ["/usr/local/bin", "/usr/bin", "/bin"]
    if platform.system() != "Windows":
        cur = env.get("PATH", "")
        prefixes = [p for p in extra if p]
        env["PATH"] = os.pathsep.join(prefixes + ([cur] if cur else []))


def fetch_tag_names(base_url: str, timeout: float = 8.0) -> set[str]:
    base = _normalize_base(base_url)
    req = urllib.request.Request(
        f"{base}/api/tags",
        headers={"User-Agent": "siem-maintenance-preflight"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return set()
    names: set[str] = set()
    for m in data.get("models") or []:
        n = (m.get("name") or "").strip()
        if n:
            names.add(n)
    return names


def model_matches(tags: set[str], want: str) -> bool:
    """True if ``want`` or want:tag is listed (Ollama often returns 'llama3.2:latest')."""
    w = want.strip()
    if not w:
        return False
    for n in tags:
        if n == w or n.startswith(w + ":") or w in n:
            return True
    return False


def ollama_cli_env(server_base: str) -> dict[str, str]:
    """So ``ollama pull`` targets the same host as OLLAMA_URL (local or remote)."""
    env = os.environ.copy()
    env["OLLAMA_HOST"] = _ollama_host_for_cli(server_base)
    return env


def run_pull(model: str, server_base: str) -> int:
    exe = _resolve_ollama_cli()
    if not exe:
        print(
            "ERROR: 'ollama' CLI not found. Install from https://ollama.com or set OLLAMA_CLI "
            "to the full path of the ollama binary (e.g. /usr/local/bin/ollama).",
            file=sys.stderr,
        )
        return 127
    host_var = _ollama_host_for_cli(server_base)
    print(f"Running: {exe} pull {model}  (OLLAMA_HOST={host_var})")
    env = ollama_cli_env(server_base)
    _enriched_path(env)
    return subprocess.call([exe, "pull", model], env=env)


def ensure_model(
    base_url: str,
    model: str,
    *,
    pull: bool = True,
    log: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    """Return (success, message)."""
    _log = log or print
    tags = fetch_tag_names(base_url)
    if not tags and pull is False:
        return False, "Could not reach Ollama /api/tags (server down or wrong OLLAMA_URL)."
    if model_matches(tags, model):
        return True, f"Model '{model}' is already available on {_normalize_base(base_url)}."
    if not pull:
        return False, f"Model '{model}' not listed on server. Run: ollama pull {model}"
    code = run_pull(model, base_url)
    if code != 0:
        return False, f"ollama pull exited {code}"
    tags2 = fetch_tag_names(base_url)
    if model_matches(tags2, model):
        return True, f"Pulled and verified '{model}'."
    return False, f"Pull finished but '{model}' still not listed - check OLLAMA_HOST and server logs."


def main() -> int:
    parser = argparse.ArgumentParser(description="Ollama preflight: specs, recommend, ensure model")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rec = sub.add_parser("recommend", help="Print RAM/CPU/GPU summary and suggested model tags")

    def _rec(_: argparse.Namespace) -> int:
        print_recommendations()
        return 0

    p_rec.set_defaults(func=_rec)

    p_en = sub.add_parser("ensure", help="Check /api/tags; optionally ollama pull if missing")
    p_en.add_argument("--url", default=os.getenv("OLLAMA_URL", "http://localhost:11434"))
    p_en.add_argument("--model", required=True)
    p_en.add_argument("--no-pull", action="store_true", help="Only check; do not pull")

    def _ensure(args: argparse.Namespace) -> int:
        pull = not args.no_pull
        ok, msg = ensure_model(args.url, args.model, pull=pull)
        print(msg)
        return 0 if ok else 1

    p_en.set_defaults(func=_ensure)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
