from pigeon import delegate, grant, verify


def test_public_api_snippet():
    authority = grant(
        subject="agent:deploy",
        capabilities=["deploy"],
        resources=["environment:staging"],
        constraints={"max_deploys_per_hour": 3},
    )
    sub_authority = delegate(
        authority,
        subject="agent:runner",
        capabilities=["deploy"],
        resources=["environment:staging"],
        constraints={"max_deploys_per_hour": 1},
    )
    result = verify(
        sub_authority,
        action="deploy",
        resource="environment:staging",
        context={},
    )
    assert result.allowed
