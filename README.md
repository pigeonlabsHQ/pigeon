# Pigeon

Your agent spawned a sub-agent and handed it the same API key. That sub-agent can now deploy to production, read the payments database, and merge to main.

Pigeon stops that. You hand the child a **Pigeon Pass**: a narrowed, signed credential for what it may do, not a copy of everything you can do.

## Install

Python 3.12 or newer.

```bash
git clone https://github.com/pigeonlabsHQ/pigeon.git
cd pigeon
pip install .
```

## The whole idea, in 20 lines

```python
from pigeon import grant, verify

authority = grant(
    subject="agent:deployer",
    capabilities=["deploy"],
    resources=["environment:staging"],
)

allowed = verify(authority, action="deploy", resource="environment:staging")
assert allowed.allowed

denied = verify(authority, action="deploy", resource="environment:production")
assert not denied.allowed
assert denied.reason_code == "RESOURCE_NOT_ALLOWED"
print(denied.reason_code, denied.message, denied.details)
```

`verify` never returns a bare boolean. A denial includes a reason code, a message, and the comparison that failed (`requested` vs `allowed`).

Try it without writing that yourself:

```bash
python examples/01_infrastructure.py
python demo/agent.py
```

## Where it goes in an agent

There is no Pigeon server to connect to. You change two places you already have:

1. **Spawn.** Where you would have copied an API key into a sub-agent, call `delegate(...)` and give the child a Pass.
2. **Tool.** Where the side effect happens (deploy, query, MCP tool), call `verify(...)` and do not run the tool if it is denied.

Keep the real secret on the runner. The child carries the Pass.

```python
from pigeon import delegate, grant, verify, DelegationError

parent = grant(
    subject="agent:orchestrator",
    capabilities=["deploy", "open_pr"],
    resources=["environment:staging", "repo:acme/api"],
    constraints={"max_deploys_per_hour": 3},
)

worker = delegate(
    parent,
    subject="agent:pr-bot",
    capabilities=["open_pr"],
    resources=["repo:acme/api"],
    constraints={"max_deploys_per_hour": 3},  # cannot drop a parent constraint
)

result = verify(worker, action="open_pr", resource="repo:acme/api")
assert result.allowed

denied = verify(worker, action="deploy", resource="environment:staging")
assert denied.reason_code == "CAPABILITY_NOT_GRANTED"

try:
    delegate(worker, "agent:rogue", ["open_pr", "deploy"], ["repo:acme/api"])
except DelegationError as exc:
    assert exc.reason_code == "PRIVILEGE_ESCALATION"
```

A child cannot add capabilities, widen resources, raise a bound, or drop a parent constraint. If Pigeon cannot prove the child is narrower, it rejects.

If the runner never calls `verify`, the Pass is decoration.

## MCP middleware

This is an enforcement point, not part of the protocol. The client mints a narrower Pass per tool call. The server verifies it before the tool runs.

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

ok = execute_tool(tool_pass, "create_issue", "mcp:github",
                  {"title": "bump deps", "body": "automated"}, create_issue)
assert ok["allowed"]

no = execute_tool(tool_pass, "merge_pr", "mcp:github",
                  {"title": "nope", "body": "nope"}, create_issue)
assert no["reason_code"] == "CAPABILITY_NOT_GRANTED"
```

Identity tells you who the agent is. Authority tells you what it may do.

## CLI

```bash
pigeon keygen
pigeon inspect pass.json
```

## What this is not

Pigeon is a small primitive. It is not a platform, a policy engine, an identity provider, or a key custodian. It does not stop prompt injection. It bounds blast radius along the dimensions you put on the Pass, and only those.

- Protocol: [`SPEC.md`](SPEC.md)
- Limits: [`SECURITY.md`](SECURITY.md)
- More scripts: `examples/` (infrastructure, data, code, then payments)
