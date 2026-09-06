from pigeon.verification.verifier import reset_default_stores


def pytest_runtest_setup(item):  # noqa: ARG001
    reset_default_stores()
