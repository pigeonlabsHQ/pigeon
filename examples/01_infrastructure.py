"""Agent may deploy to staging, never production."""

from pigeon import grant, verify

authority = grant(
    subject="agent:deployer",
    capabilities=["deploy"],
    resources=["environment:staging"],
)

allowed = verify(authority, action="deploy", resource="environment:staging")
print("staging:", "allowed" if allowed.allowed else allowed.reason_code)
assert allowed.allowed

denied = verify(authority, action="deploy", resource="environment:production")
print("production:", denied.reason_code, denied.message)
assert not denied.allowed
assert denied.reason_code == "RESOURCE_NOT_ALLOWED"
