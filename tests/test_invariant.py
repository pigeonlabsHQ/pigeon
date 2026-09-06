from hypothesis import given, settings, strategies as st

from pigeon import DelegationError, Principal, delegate, grant, verify
from pigeon.core.capability import capabilities_subset
from pigeon.core.constraints import constraints_attenuate
from pigeon.core.resource import resources_attenuate

NOW = "2026-09-06T12:00:00Z"
EXP = "2026-09-07T12:00:00Z"
CAPS = ("read", "write", "deploy", "execute")
RESS = ("environment:staging", "environment:production", "repo:acme/api")


@given(
    parent_caps=st.lists(st.sampled_from(CAPS), min_size=1, unique=True),
    child_caps=st.lists(st.sampled_from(CAPS), min_size=0, unique=True),
    parent_res=st.lists(st.sampled_from(RESS), min_size=1, unique=True),
    child_res=st.lists(st.sampled_from(RESS + ("environment:*",)), min_size=0, unique=True),
    parent_max=st.integers(min_value=1, max_value=500),
    child_max=st.integers(min_value=1, max_value=500),
)
@settings(max_examples=80, deadline=None)
def test_child_never_has_greater_effective_authority(
    parent_caps,
    child_caps,
    parent_res,
    child_res,
    parent_max,
    child_max,
):
    issuer = Principal.generate("human:owner")
    parent = grant(
        "agent:parent",
        parent_caps,
        parent_res,
        {"amount": parent_max},
        issuer=issuer,
        now=NOW,
        expires_at=EXP,
    )
    try:
        child = delegate(
            parent,
            "agent:child",
            child_caps,
            child_res,
            {"amount": child_max},
            now=NOW,
        )
    except DelegationError as exc:
        assert exc.reason_code in {
            "PRIVILEGE_ESCALATION",
            "MALFORMED_AUTHORITY",
            "INVALID_DELEGATION",
        }
        return
    assert capabilities_subset(child.capabilities, parent.capabilities)
    assert resources_attenuate(parent.resources, child.resources)
    ok, _ = constraints_attenuate(parent.constraints, child.constraints)
    assert ok
    assert child.expires_at <= parent.expires_at
    if child.capabilities and child.resources:
        action = child.capabilities[0]
        # A concrete resource the child lists, or a staging env if wildcard
        resource = child.resources[0].rstrip("*") or parent.resources[0]
        if resource.endswith(":"):
            resource = resource + "x"
        result = verify(
            child,
            action,
            resource,
            {"amount": min(child_max, parent_max)},
            now=NOW,
        )
        if result.allowed:
            parent_result = verify(
                parent,
                action,
                resource,
                {"amount": min(child_max, parent_max)},
                now=NOW,
            )
            assert parent_result.allowed
