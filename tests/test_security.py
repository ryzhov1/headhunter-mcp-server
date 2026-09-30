import asyncio
from pathlib import Path

import server


def test_server_exports_only_read_only_tools() -> None:
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert "hh_apply_to_vacancy" not in names
    assert names


def test_runtime_has_no_application_submission_code() -> None:
    server_source = Path("server.py").read_text(encoding="utf-8")
    client_source = Path("hh_client.py").read_text(encoding="utf-8")
    assert "hh_apply_to_vacancy" not in server_source
    assert "apply_to_vacancy" not in client_source
    assert 'post(' not in server_source
    assert 'post(' not in client_source


def test_secrets_are_ignored() -> None:
    ignore = Path(".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in ignore
    assert ".env.*" in ignore
