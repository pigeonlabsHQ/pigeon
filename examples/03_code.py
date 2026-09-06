"""Agent may open a PR on repo:acme/api, never merge to main."""

from pigeon import grant, verify

authority = grant(
    subject="agent:developer",
    capabilities=["open_pr"],
    resources=["repo:acme/api"],
    constraints={"target_branch": {"op": "neq", "value": "main"}},
)

pr = verify(
    authority,
    action="open_pr",
    resource="repo:acme/api",
    context={"target_branch": "feature/rate-limit"},
)
assert pr.allowed

merge_main = verify(
    authority,
    action="merge",
    resource="repo:acme/api",
    context={"target_branch": "main"},
)
assert merge_main.reason_code == "CAPABILITY_NOT_GRANTED"

pr_main = verify(
    authority,
    action="open_pr",
    resource="repo:acme/api",
    context={"target_branch": "main"},
)
assert pr_main.reason_code == "CONSTRAINT_VIOLATION"
print("open PR to feature: allowed")
print("merge:", merge_main.reason_code)
print("open PR to main:", pr_main.reason_code)
