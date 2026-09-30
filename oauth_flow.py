#!/usr/bin/env python3
"""Interactive HeadHunter OAuth flow with PKCE and non-logging token storage."""

import asyncio
import base64
import hashlib
import os
import secrets
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from dotenv import load_dotenv

load_dotenv(override=False)

AUTH_URL = "https://hh.ru/oauth/authorize"
OAUTH_ENDPOINT = "https://api.hh.ru/token"
TOKEN_FILE = Path(".env")
REFRESH_TOKEN_FILE = Path(".oauth-refresh-token")


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable is missing: {name}")
    return value


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _parse_redirect(value: str, expected_state: str) -> str:
    params = parse_qs(urlparse(value.strip()).query)
    if params.get("state", [None])[0] != expected_state:
        raise RuntimeError("OAuth state mismatch; aborting token exchange")
    code = params.get("code", [None])[0]
    if not code:
        raise RuntimeError("Authorization code is missing from redirect URL")
    return code


def _store_tokens(tokens: dict[str, object]) -> None:
    """Upsert OAuth tokens without displaying them or following symlinks."""
    target = TOKEN_FILE.resolve()
    if TOKEN_FILE.exists() and TOKEN_FILE.is_symlink():
        raise RuntimeError("Refusing to write tokens through a symbolic link")

    existing = (
        TOKEN_FILE.read_text(encoding="utf-8").splitlines()
        if TOKEN_FILE.exists()
        else []
    )
    kept = [
        line
        for line in existing
        if not line.startswith(("HH_ACCESS_TOKEN=", "HH_REFRESH_TOKEN="))
    ]
    kept.extend(
        [
            "",
            "# OAuth access token; keep this file local and never commit it",
            f"HH_ACCESS_TOKEN={tokens['access_token']}",
        ]
    )

    fd, temp_name = tempfile.mkstemp(prefix=".hh-oauth-", dir=target.parent)
    try:
        os.chmod(temp_name, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(kept).rstrip() + "\n")
        os.replace(temp_name, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)

    refresh_target = REFRESH_TOKEN_FILE.resolve()
    if REFRESH_TOKEN_FILE.exists() and REFRESH_TOKEN_FILE.is_symlink():
        raise RuntimeError("Refusing to write refresh token through a symbolic link")
    refresh_fd, refresh_temp = tempfile.mkstemp(
        prefix=".hh-refresh-", dir=refresh_target.parent
    )
    try:
        os.chmod(refresh_temp, 0o600)
        with os.fdopen(refresh_fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(str(tokens["refresh_token"]) + "\n")
        os.replace(refresh_temp, refresh_target)
        try:
            os.chmod(refresh_target, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(refresh_temp):
            os.unlink(refresh_temp)


async def main() -> None:
    client_id = _required("HH_CLIENT_ID")
    client_secret = _required("HH_CLIENT_SECRET")
    redirect_uri = _required("HH_REDIRECT_URI")
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)
    query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )

    print("Open this URL in a browser and authorize the application:\n")
    print(f"{AUTH_URL}?{query}")
    redirect = input("\nPaste the complete redirect URL: ")
    code = _parse_redirect(redirect, state)

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            OAUTH_ENDPOINT,
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "code": code,
                "code_verifier": verifier,
            },
            headers={"HH-User-Agent": "headhunter-mcp-server/1.0"},
        )
        response.raise_for_status()
        tokens = response.json()

    _store_tokens(tokens)
    print(
        "OAuth tokens were saved to git-ignored local files; values were not logged."
    )


if __name__ == "__main__":
    asyncio.run(main())
