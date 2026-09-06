from pigeon.integrations.mcp import execute_tool, pass_for_tool
from pigeon import grant, verify

NOW = "2026-09-06T12:00:00Z"
EXP = "2026-09-07T12:00:00Z"


def _create_issue(*, title: str, body: str) -> dict:
    return {"title": title, "body": body, "created": True}


def test_mcp_allows_one_call_and_denies_another():
    parent = grant(
        "agent:github",
        ["create_issue", "merge_pr"],
        ["mcp:github"],
        now=NOW,
        expires_at=EXP,
    )
    allowed_pass = pass_for_tool(
        parent,
        "create_issue",
        "mcp:github",
        subject="agent:github-worker",
        now=NOW,
    )
    allowed = execute_tool(
        allowed_pass,
        "create_issue",
        "mcp:github",
        {"title": "bump deps", "body": "automated"},
        _create_issue,
        now=NOW,
    )
    assert allowed["allowed"] is True
    assert allowed["result"]["created"] is True

    denied = execute_tool(
        allowed_pass,
        "merge_pr",
        "mcp:github",
        {"title": "nope", "body": "nope"},
        _create_issue,
        now=NOW,
    )
    assert denied["allowed"] is False
    assert denied["reason_code"] == "CAPABILITY_NOT_GRANTED"

    still = verify(allowed_pass, "create_issue", "mcp:github", now=NOW)
    assert still.allowed
