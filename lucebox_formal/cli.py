from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .contract_proposal import (
    ContractProposalError,
    run_propose_contract,
    run_validate_contract,
)
from .manifest import ManifestError
from .plan import PlanError, run_plan
from .repair import run_propose, run_validate
from .security import BundleError
from .verifier import run_verify, run_verify_plan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lucebox-formal")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify")
    verify_input = verify.add_mutually_exclusive_group(required=True)
    verify_input.add_argument("--manifest", type=Path)
    verify_input.add_argument("--plan", type=Path)
    verify.add_argument("--workspace", type=Path)
    verify.add_argument("--generated-root", type=Path)
    verify.add_argument("--base-sha", default="")
    verify.add_argument("--mode", choices=("pr", "all", "nightly"), default="pr")
    verify.add_argument("--out", type=Path, required=True)

    plan = subparsers.add_parser("plan")
    plan.add_argument("--workspace", type=Path, required=True)
    plan.add_argument("--base-policy", required=True)
    plan.add_argument("--base-sha", required=True)
    plan.add_argument("--head-sha", required=True)
    plan.add_argument("--mode", choices=("pr", "all", "nightly"), default="pr")
    plan.add_argument("--out", type=Path, required=True)

    propose = subparsers.add_parser("propose")
    propose.add_argument("--bundle", type=Path, required=True)
    propose.add_argument("--model", default="openai:gpt-5.6-sol")
    propose.add_argument("--out", type=Path, required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--bundle", type=Path, required=True)
    validate.add_argument("--patch", type=Path, required=True)
    validate.add_argument("--out", type=Path, required=True)

    propose_contract = subparsers.add_parser("propose-contract")
    propose_contract.add_argument("--bundle", type=Path, required=True)
    propose_contract.add_argument("--model", default="openai:gpt-5.6-sol")
    propose_contract.add_argument("--out", type=Path, required=True)

    validate_contract = subparsers.add_parser("validate-contract")
    validate_contract.add_argument("--bundle", type=Path, required=True)
    validate_contract.add_argument("--proposal-dir", type=Path, required=True)
    validate_contract.add_argument("--workspace", type=Path, required=True)
    validate_contract.add_argument("--out", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "verify":
            if args.plan:
                if args.workspace is None or args.generated_root is None:
                    raise ManifestError("--plan requires --workspace and --generated-root")
                code = run_verify_plan(
                    args.workspace,
                    args.plan,
                    args.generated_root,
                    args.out,
                )
            else:
                code = run_verify(args.manifest, args.base_sha, args.mode, args.out)
        elif args.command == "plan":
            code = run_plan(
                args.workspace,
                args.base_policy,
                args.base_sha,
                args.head_sha,
                args.mode,
                args.out,
            )
        elif args.command == "propose":
            code = run_propose(args.bundle, args.model, args.out)
        elif args.command == "validate":
            code = run_validate(args.bundle, args.patch, args.out)
        elif args.command == "propose-contract":
            code = run_propose_contract(args.bundle, args.model, args.out)
        else:
            code = run_validate_contract(
                args.bundle,
                args.proposal_dir,
                args.workspace,
                args.out,
            )
    except ManifestError as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        code = 13
    except PlanError as exc:
        print(f"plan error: {exc}", file=sys.stderr)
        code = 13
    except ContractProposalError as exc:
        print(f"contract proposal error: {exc}", file=sys.stderr)
        code = 21
    except BundleError as exc:
        print(f"bundle error: {exc}", file=sys.stderr)
        code = 21
    raise SystemExit(code)


if __name__ == "__main__":
    main()
