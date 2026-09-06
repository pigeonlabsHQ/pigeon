"""1000 -> 500 -> 100 -> 50 works. 50 -> 200 fails."""

from pigeon import DelegationError, delegate, grant

level = grant(
    subject="agent:l0",
    capabilities=["purchase"],
    resources=["merchant:*"],
    constraints={"amount": 1000},
)

for i, cap in enumerate([500, 100, 50], start=1):
    level = delegate(
        level,
        subject=f"agent:l{i}",
        capabilities=["purchase"],
        resources=["merchant:books"],
        constraints={"amount": cap},
    )
    print(f"delegated amount={cap} depth={level.delegation_depth}")

try:
    delegate(
        level,
        subject="agent:l5",
        capabilities=["purchase"],
        resources=["merchant:books"],
        constraints={"amount": 200},
    )
except DelegationError as exc:
    assert exc.reason_code == "PRIVILEGE_ESCALATION"
    print(exc.reason_code, "50 -> 200 rejected")
else:
    raise SystemExit("raising the cap should have failed")
