# Pigeon

Your agent spawned a sub-agent and handed it the same API key. That sub-agent can now do everything the parent can do: deploy to production, read the payments database, merge to main.

Pigeon replaces that hand-off with a narrowed, cryptographically verifiable credential called a Pigeon Pass. The child gets permission to act, not permission to do everything.

## Install

Python 3.12 or newer.

```bash
pip install .
```

## A 20-line example

```python
from pigeon import grant, verify

authority = grant(
    subject="agent:deployer",
    capabilities=["deploy"],
    resources=["environment:staging"],
)

allowed = verify(
    authority,
    action="deploy",
    resource="environment:staging",
    context={},
)
assert allowed.allowed

denied = verify(
    authority,
    action="deploy",
    resource="environment:production",
    context={},
)
assert not denied.allowed
assert denied.reason_code == "RESOURCE_NOT_ALLOWED"
print(denied.reason_code, denied.message, denied.details)
```

`verify` never returns a bare boolean. When an action is denied you get a reason code, a message, and the concrete comparison that failed.

## MCP middleware

This is an enforcement point, not part of the protocol. The server verifies a Pass before a tool runs. The client mints a narrower Pass per tool call.

```python
from pigeon import grant
from pigeon.integrations.mcp import execute_tool, pass_for_tool

parent = grant(
    subject="agent:github",
    capabilities=["create_issue", "merge_pr"],
    resources=["mcp:github"],
)

tool_pass = pass_for_tool(parent, "create_issue", "mcp:github")

def create_issue(*, title, body):
    return {"created": True, "title": title}

ok = execute_tool(
    tool_pass,
    "create_issue",
    "mcp:github",
    {"title": "bump deps", "body": "automated"},
    create_issue,
)
assert ok["allowed"]

no = execute_tool(
    tool_pass,
    "merge_pr",
    "mcp:github",
    {"title": "nope", "body": "nope"},
    create_issue,
)
assert no["reason_code"] == "CAPABILITY_NOT_GRANTED"
```

Identity tells you who the agent is. Authority tells you what it may do.

## Delegation

```python
from pigeon import delegate, grant, verify

parent = grant(
    subject="agent:deploy",
    capabilities=["deploy"],
    resources=["environment:staging"],
    constraints={"max_deploys_per_hour": 3},
)

child = delegate(
    parent,
    subject="agent:runner",
    capabilities=["deploy"],
    resources=["environment:staging"],
    constraints={"max_deploys_per_hour": 1},
)

result = verify(child, action="deploy", resource="environment:staging", context={})
assert result.allowed
```

A child cannot add capabilities, widen resources, raise a bound, or drop a parent constraint. Attempts fail closed with `PRIVILEGE_ESCALATION`.

## CLI

```bash
pigeon keygen
pigeon inspect pass.json
```

## What this is not

Pigeon is a small primitive. It is not a platform, a policy engine, an identity provider, or a key custodian. Read `SPEC.md` for the protocol and `SECURITY.md` for the limits.
