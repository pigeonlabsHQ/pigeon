"""CLI: pigeon keygen | pigeon inspect <pass>"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pigeon.core.authority import Authority
from pigeon.crypto.keys import generate_keypair
from pigeon.verification.chain import assemble_steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pigeon",
        description="Pigeon Pass utilities",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keygen", help="Generate an Ed25519 keypair")

    inspect_p = sub.add_parser("inspect", help="Show a Pass and its chain")
    inspect_p.add_argument("pass_path", help="Path to a Pass JSON document")

    args = parser.parse_args(argv)
    if args.command == "keygen":
        return _keygen()
    if args.command == "inspect":
        return _inspect(args.pass_path)
    parser.error("unknown command")
    return 2


def _keygen() -> int:
    public, private = generate_keypair()
    json.dump(
        {"public_key": public, "private_key": private},
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


def _inspect(path: str) -> int:
    raw = Path(path).read_text(encoding="utf-8")
    document = json.loads(raw)
    try:
        authority = (
            Authority.from_pass_document(document)
            if isinstance(document, dict) and "authorities" in document
            else Authority.from_dict(document)
        )
    except Exception as exc:
        print(f"MALFORMED_AUTHORITY: {exc}", file=sys.stderr)
        return 1
    print(f"id:                {authority.id}")
    print(f"version:           {authority.version}")
    print(f"issuer:            {authority.issuer.principal_id} ({authority.issuer.principal_type})")
    print(f"subject:           {authority.subject.principal_id} ({authority.subject.principal_type})")
    print(f"parent:            {authority.parent}")
    print(f"delegation_depth:  {authority.delegation_depth}")
    print(f"issued_at:         {authority.issued_at}")
    print(f"expires_at:        {authority.expires_at}")
    print(f"capabilities:      {', '.join(authority.capabilities) or '(none)'}")
    print(f"resources:         {', '.join(authority.resources) or '(none)'}")
    print("constraints:")
    if authority.constraints:
        print(json.dumps(authority.constraints, indent=2, sort_keys=True))
    else:
        print("  (none)")
    print(f"own_signature:     {'valid' if authority.verify_own_signature() else 'INVALID'}")
    print("chain (leaf -> root):")
    for step in assemble_steps(authority):
        print(
            f"  [{step['index']}] {step['id']} "
            f"{step['issuer']} -> {step['subject']} "
            f"depth={step['delegation_depth']}"
        )
        sig_ok = authority.chain()[step["index"]].verify_own_signature()
        print(f"      signature={'valid' if sig_ok else 'INVALID'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
