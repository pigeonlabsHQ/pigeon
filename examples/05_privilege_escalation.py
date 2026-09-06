"""Parent grants read. Child that asks for read+write is rejected."""

from pigeon import DelegationError, delegate, grant

parent = grant(
    subject="agent:reader",
    capabilities=["read"],
    resources=["database:customers"],
)

try:
    delegate(
        parent,
        subject="agent:writer",
        capabilities=["read", "write"],
        resources=["database:customers"],
    )
except DelegationError as exc:
    assert exc.reason_code == "PRIVILEGE_ESCALATION"
    print(exc.reason_code, exc.message)
else:
    raise SystemExit("delegation should have failed")
