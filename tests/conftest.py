from pathlib import Path

import pytest

from modules.security.confine import add_trusted_workspace, remove_trusted_workspace


@pytest.fixture(autouse=True)
def manage_test_workspaces(request):
    """
    Automatically trusts pytest-generated tmp_path workspaces for functional tests.
    Leaves security tests strictly constrained to real configured trusted_workspaces.
    """
    trusted = []
    if "security" not in request.module.__name__:
        if "tmp_path" in request.fixturenames:
            tmp = request.getfixturevalue("tmp_path")
            if isinstance(tmp, Path):
                add_trusted_workspace(tmp)
                trusted.append(tmp)
    yield
    for t in trusted:
        remove_trusted_workspace(t)
