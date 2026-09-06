"""Agent may read database:customers, never write it, never read payments."""

from pigeon import grant, verify

authority = grant(
    subject="agent:analyst",
    capabilities=["read"],
    resources=["database:customers"],
)

ok = verify(authority, action="read", resource="database:customers")
assert ok.allowed

write = verify(authority, action="write", resource="database:customers")
assert write.reason_code == "CAPABILITY_NOT_GRANTED"

payments = verify(authority, action="read", resource="database:payments")
assert payments.reason_code == "RESOURCE_NOT_ALLOWED"

print("read customers: allowed")
print("write customers:", write.reason_code)
print("read payments:", payments.reason_code)
