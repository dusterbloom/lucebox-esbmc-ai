from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .manifest import ManifestError
from .repair import run_propose, run_validate
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

    propose = subparsers.add_parser("propose")
    propose.add_argument("--bundle", type=Path, required=True)
    propose.add_argument("--model", default="openai:gpt-5.6-sol")
    propose.add_argument("--out", type=Path, required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--bundle", type=Path, required=True)
    validate.add_argument("--patch", type=Path, required=True)
    validate.add_argument("--out", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "verify":
            code = run_verify(
                args.manifest, args.base_sha, args.mode, args.out
            )
        elif args.command == "propose":
            code = run_propose(args.bundle, args.model, args.out)
        else:
            code = run_validate(args.bundle, args.patch, args.out)
    except ManifestError as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        code = 13
    except BundleError as exc:
        print(f"bundle error: {exc}", file=sys.stderr)
        code = 21
    raise SystemExit(code)


if __name__ == "__main__":
    main()
