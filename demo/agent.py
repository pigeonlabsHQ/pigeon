"""A tiny in-process agent used to exercise Pigeon.

There is no LLM and no framework. The orchestrator receives intents, sometimes
spawns a worker with a narrowed Pass, and every tool goes through verify()
before anything runs.
"""

from __future__ import annotations

from pigeon import DelegationError, Principal, delegate, grant, verify


def deploy(*, note: str = "") -> str:
    return f"deployed ({note})" if note else "deployed"


def read_customers() -> str:
    return "customers: 3 rows (simulated)"


def open_pr(*, target_branch: str) -> str:
    return f"opened PR targeting {target_branch}"


TOOLS = {
    ("deploy", "environment:staging"): lambda **kw: deploy(note=kw.get("note", "")),
    ("deploy", "environment:production"): lambda **kw: deploy(note="production"),
    ("read", "database:customers"): lambda **kw: read_customers(),
    ("open_pr", "repo:acme/api"): lambda **kw: open_pr(
        target_branch=kw["target_branch"]
    ),
}


class ToolRunner:
    """The enforcement point. Real credentials would live here, not on the agent."""

    def execute(self, authority, action: str, resource: str, context: dict | None = None):
        ctx = dict(context or {})
        result = verify(authority, action, resource, ctx)
        if not result.allowed:
            return {
                "ok": False,
                "reason_code": result.reason_code,
                "message": result.message,
                "details": result.details,
            }
        handler = TOOLS.get((action, resource))
        if handler is None:
            return {"ok": False, "reason_code": "NO_SUCH_TOOL", "message": resource}
        return {"ok": True, "result": handler(**ctx)}


class Agent:
    def __init__(self, name: str, authority, runner: ToolRunner) -> None:
        self.name = name
        self.authority = authority
        self.runner = runner

    def act(self, action: str, resource: str, **context):
        outcome = self.runner.execute(self.authority, action, resource, context)
        status = "ok" if outcome.get("ok") else outcome.get("reason_code")
        extra = outcome.get("result") or outcome.get("message")
        print(f"  [{self.name}] {action} {resource} -> {status}" + (f" ({extra})" if extra else ""))
        return outcome

    def spawn(self, name: str, capabilities, resources, constraints=None) -> Agent:
        child = delegate(
            self.authority,
            subject=f"agent:{name}",
            capabilities=capabilities,
            resources=resources,
            constraints=constraints,
        )
        print(f"  [{self.name}] spawned {name} with {capabilities} on {resources}")
        return Agent(name, child, self.runner)


def main() -> None:
    runner = ToolRunner()
    human = Principal.generate("human:you", "human")
    orchestrator = Agent(
        "orchestrator",
        grant(
            subject="agent:orchestrator",
            capabilities=["deploy", "read", "open_pr"],
            resources=["environment:staging", "database:customers", "repo:acme/api"],
            constraints={"max_deploys_per_hour": 3},
            issuer=human,
        ),
        runner,
    )

    print("1. Parent agent, allowed and denied")
    orchestrator.act("deploy", "environment:staging")
    orchestrator.act("deploy", "environment:production")
    orchestrator.act("read", "database:customers")

    print("\n2. Spawn a PR worker (no deploy, no production)")
    worker = orchestrator.spawn(
        "pr-bot",
        capabilities=["open_pr"],
        resources=["repo:acme/api"],
        constraints={
            # Parent rate limit must be kept. Dropping it would be escalation.
            "max_deploys_per_hour": 3,
            "target_branch": {"op": "neq", "value": "main"},
        },
    )
    worker.act("open_pr", "repo:acme/api", target_branch="feature/rate-limit")
    worker.act("open_pr", "repo:acme/api", target_branch="main")
    worker.act("deploy", "environment:staging")

    print("\n3. Worker tries to escalate: ask for deploy")
    try:
        worker.spawn(
            "rogue",
            capabilities=["open_pr", "deploy"],
            resources=["repo:acme/api"],
        )
    except DelegationError as exc:
        print(f"  [pr-bot] spawn rogue -> {exc.reason_code} ({exc.message})")


if __name__ == "__main__":
    main()
