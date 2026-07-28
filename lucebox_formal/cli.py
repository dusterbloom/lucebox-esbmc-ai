from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .manifest import ManifestError
from .repair import run_repair
from .security import BundleError
from .verifier import run_verify


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lucebox-formal")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--base-sha", default="")
    verify.add_argument(
        "--mode", choices=("pr", "all", "nightly"), default="pr"
    )
    verify.add_argument("--out", type=Path, required=True)

    repair = subparsers.add_parser("repair")
    repair.add_argument("--bundle", type=Path, required=True)
    repair.add_argument("--model", default="openai:gpt-5.6-sol")
    repair.add_argument("--max-attempts", type=int, default=3)
    repair.add_argument("--out", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "verify":
            code = run_verify(
                args.manifest, args.base_sha, args.mode, args.out
            )
        else:
            code = run_repair(
                args.bundle, args.model, args.max_attempts, args.out
            )
    except ManifestError as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        code = 13
    except BundleError as exc:
        print(f"bundle error: {exc}", file=sys.stderr)
        code = 21
    raise SystemExit(code)


if __name__ == "__main__":
    main()
