#!/usr/bin/env python3
"""Post-install checks: .env present, imports, optional Elasticsearch / LLM reachability.

Run from repository root (after install.ps1 / install.sh):

  python verify_setup.py
  python verify_setup.py --strict-ollama   # fail if Ollama unreachable (non-gpt model)
  python verify_setup.py --pull-missing-ollama   # ollama pull if LLM model not listed

With venv:

  .venv\\Scripts\\python.exe verify_setup.py   # Windows
  .venv/bin/python verify_setup.py              # Linux / macOS
"""
from __future__ import annotations

import argparse
import os
import sys
import warnings
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent


def _load_env(root: Path) -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        print("WARN: python-dotenv not installed - skipping .env load")
        return
    load_dotenv(root / ".env", override=False)
    load_dotenv(root / "Agent-SIEM-maintenance" / ".env", override=True)


def _step(name: str, ok: bool, detail: str = "") -> bool:
    sym = "OK " if ok else "FAIL"
    extra = f" - {detail}" if detail else ""
    print(f"  [{sym}] {name}{extra}")
    return ok


def _warn(name: str, detail: str = "") -> None:
    extra = f" - {detail}" if detail else ""
    print(f"  [WARN] {name}{extra}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify SIEM-Maintenance install")
    parser.add_argument(
        "--skip-network",
        action="store_true",
        help="Only check files and imports (no ES / Ollama HTTP)",
    )
    parser.add_argument(
        "--strict-ollama",
        action="store_true",
        help="Fail if Ollama is unreachable (default: warn only when using a non-gpt model)",
    )
    parser.add_argument(
        "--pull-missing-ollama",
        action="store_true",
        help="When using a non-gpt model, run ollama pull if the model is not listed (needs ollama CLI)",
    )
    args = parser.parse_args()

    root = _repo_root()
    agent = root / "Agent-SIEM-maintenance"
    env_root = root / ".env"
    env_agent = agent / ".env"

    print("SIEM-Maintenance - verification")
    print(f"  Repo: {root}")
    print()

    all_ok = True

    # [1] .env
    e1 = env_root.is_file() or env_agent.is_file()
    all_ok &= _step(
        ".env file",
        e1,
        f"found {env_root}" if env_root.is_file() else (f"found {env_agent}" if env_agent.is_file() else "missing - re-run install"),
    )

    _load_env(root)

    # [2] Required / conditional variables
    es_host = os.getenv("ES_HOST", "").strip()
    all_ok &= _step("ES_HOST set", bool(es_host), es_host[:48] + "…" if len(es_host) > 48 else es_host)

    llm_off = os.getenv("LLM_ENABLED", "true").lower() in ("0", "false", "no", "off")
    model = (os.getenv("LLM_MODEL") or os.getenv("ES_HEALTH_LLM_MODEL") or "").strip()
    if not llm_off:
        all_ok &= _step("LLM_MODEL / ES_HEALTH_LLM_MODEL", bool(model), model or "missing")
        if model.startswith("gpt-"):
            key = bool(os.getenv("OPENAI_API_KEY", "").strip())
            all_ok &= _step("OPENAI_API_KEY (OpenAI model)", key, "set" if key else "missing")
        else:
            url = os.getenv("OLLAMA_URL", "http://localhost:11434").strip()
            all_ok &= _step("OLLAMA_URL (non-gpt model)", bool(url), url)
    else:
        _step("LLM", True, "disabled (LLM_ENABLED)")

    wh = os.getenv("GC_ALERT_WEBHOOK", "").strip()
    _step("GC_ALERT_WEBHOOK", bool(wh), "set" if wh else "empty - Chat cards will not send")

    # [3] Imports
    sys.path.insert(0, str(agent))
    try:
        import apscheduler  # noqa: F401
        import elasticsearch  # noqa: F401
        import requests  # noqa: F401

        import maintenance_service  # noqa: F401
        import ultra_siem_monitor  # noqa: F401
        import enhanced_health_monitor  # noqa: F401
        import es_health_monitor  # noqa: F401

        all_ok &= _step("Python imports", True, "maintenance stack loads")
    except Exception as ex:
        all_ok &= _step("Python imports", False, str(ex))

    ollama_warn = False

    # [4] Optional: Elasticsearch ping
    if not args.skip_network and es_host:
        try:
            from elasticsearch import Elasticsearch
            from urllib3.exceptions import InsecureRequestWarning

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                warnings.simplefilter("ignore", DeprecationWarning)
                try:
                    from elasticsearch import SecurityWarning  # type: ignore[attr-defined]

                    warnings.simplefilter("ignore", SecurityWarning)
                except Exception:
                    pass

                user = os.getenv("ES_USERNAME") or os.getenv("ES_USER")
                pwd = os.getenv("ES_PASSWORD") or os.getenv("ES_PASS")
                es = Elasticsearch(
                    hosts=[es_host],
                    basic_auth=(user, pwd) if user and pwd else None,
                    verify_certs=False,
                )
                info = es.options(request_timeout=10).info()
            ver = info.get("version", {}).get("number", "?")
            all_ok &= _step("Elasticsearch reachable", True, f"cluster version {ver}")
        except Exception as ex:
            all_ok &= _step("Elasticsearch reachable", False, str(ex)[:120])

    # [5] Optional: Ollama (when LLM uses non-gpt model)
    if not args.skip_network and not llm_off and model and not model.startswith("gpt-"):
        base = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
        rp = str(_repo_root())
        if rp not in sys.path:
            sys.path.insert(0, rp)

        if args.pull_missing_ollama:
            from ollama_preflight import ensure_model

            ok_p, msg_p = ensure_model(base, model, pull=True)
            if ok_p:
                all_ok &= _step("Ollama model", True, msg_p)
            elif args.strict_ollama:
                all_ok &= _step("Ollama model", False, msg_p)
            else:
                ollama_warn = True
                _warn("Ollama model", msg_p)
        else:
            import requests

            try:
                r = requests.get(f"{base}/api/tags", timeout=5)
                if r.status_code == 200:
                    tags = r.json().get("models") or []
                    names = [m.get("name", "") for m in tags]
                    hit = any(model in n for n in names)
                    all_ok &= _step(
                        "Ollama /api/tags",
                        True,
                        f"model '{model}' listed" if hit else f"running - pull if missing: ollama pull {model}",
                    )
                elif args.strict_ollama:
                    all_ok &= _step("Ollama /api/tags", False, f"HTTP {r.status_code}")
                else:
                    ollama_warn = True
                    _warn("Ollama /api/tags", f"HTTP {r.status_code} - LLM will fail until Ollama responds at {base}")
            except Exception as ex:
                msg = str(ex)[:160]
                if args.strict_ollama:
                    all_ok &= _step("Ollama /api/tags", False, msg)
                else:
                    ollama_warn = True
                    _warn(
                        "Ollama not reachable",
                        f"{msg} | start Ollama or set OLLAMA_URL to your server",
                    )

    print()
    if all_ok:
        print("All required checks passed. You can run maintenance_service.py.")
        if ollama_warn:
            print("Note: Ollama was not verified - install/start Ollama or use an OpenAI (gpt-*) model for LLM text.")
        return 0
    print("Some checks failed - fix .env / network / pip install, then re-run.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
