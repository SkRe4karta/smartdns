import base64
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from zelyonka.oidc import ISSUER, TelegramOIDC
from zelyonka.security import digest


@pytest.fixture
def provider(stack):
    stack["settings"].telegram_file.write_text(
        json.dumps({"client_id": "123456", "client_secret": "fixture-provider-secret"})
    )
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    public["kid"] = "fixture-signing-key"
    return TelegramOIDC(stack["settings"], stack["accounts"]), private, public


def signed(private, **overrides):
    payload = {
        "iss": ISSUER,
        "aud": "123456",
        "sub": "100200300",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "nonce": "expected-nonce",
    } | overrides
    return jwt.encode(payload, private, algorithm="RS256", headers={"kid": "fixture-signing-key"})


@pytest.mark.asyncio
async def test_id_token_signature_audience_expiry_and_nonce(provider):
    oidc, private, public = provider
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"keys": [public]}))
    ) as client:
        claims = await oidc.verify(signed(private), "expected-nonce", "123456", client)
        assert claims["sub"] == "100200300"
        for changes in [
            {"aud": "other-app"},
            {"iss": "https://evil.example"},
            {"exp": int(time.time()) - 300},
            {"nonce": "wrong-nonce"},
        ]:
            with pytest.raises((ValueError, jwt.PyJWTError)):
                await oidc.verify(signed(private, **changes), "expected-nonce", "123456", client)
        foreign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(jwt.PyJWTError):
            await oidc.verify(signed(foreign), "expected-nonce", "123456", client)
        unsigned = jwt.encode({"sub": "admin"}, key=None, algorithm="none")
        with pytest.raises(ValueError):
            await oidc.verify(unsigned, "expected-nonce", "123456", client)


@pytest.mark.asyncio
async def test_oidc_state_is_browser_bound_and_one_time(stack, provider):
    oidc, _, _ = provider
    url, browser = oidc.start(account_id=None, invite=None)
    query = parse_qs(urlparse(url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == ["openid profile"]
    assert "client_secret" not in query
    state = query["state"][0]
    with pytest.raises(ValueError):
        await oidc.callback("code", state, "wrong-browser")
    with stack["db"].connect(readonly=True) as db:
        assert db.execute("SELECT 1 FROM oauth_states WHERE state_hash=?", (digest(state),)).fetchone()
    with stack["db"].connect() as db:
        db.execute("UPDATE oauth_states SET expires=0")
    with pytest.raises(ValueError):
        await oidc.callback("code", state, browser)


@pytest.mark.asyncio
async def test_telegram_setup_requires_invite_and_consumes_it(stack, provider, monkeypatch):
    oidc, private, public = provider
    invite = stack["accounts"].create("telegram-user", "Telegram user")
    token = invite["setup_url"].split("#")[1]
    url, browser = oidc.start(account_id=None, invite=token)
    query = parse_qs(urlparse(url).query)
    state, nonce = query["state"][0], query["nonce"][0]
    async_client = httpx.AsyncClient

    def exchange(request):
        if request.url.path == "/token":
            assert request.headers["authorization"].startswith("Basic ")
            body = parse_qs(request.content.decode())
            assert (
                base64.urlsafe_b64encode(
                    __import__("hashlib").sha256(body["code_verifier"][0].encode()).digest()
                )
                .decode()
                .rstrip("=")
                == query["code_challenge"][0]
            )
            return httpx.Response(
                200, json={"id_token": signed(private, nonce=nonce, preferred_username="owner")}
            )
        return httpx.Response(200, json={"keys": [public]})

    monkeypatch.setattr(
        "zelyonka.oidc.httpx.AsyncClient",
        lambda **kwargs: async_client(transport=httpx.MockTransport(exchange), **kwargs),
    )
    session = await oidc.callback("fixture-code", state, browser)
    account = stack["accounts"].authenticate(session[0])
    assert account["id"] == invite["id"] and account["role"] == "user"
    assert stack["accounts"].invite_info(token) is None
    with pytest.raises(ValueError):
        await oidc.callback("fixture-code", state, browser)


@pytest.mark.asyncio
async def test_unknown_telegram_identity_does_not_create_account(stack, provider, monkeypatch):
    oidc, private, public = provider
    url, browser = oidc.start(account_id=None, invite=None)
    query = parse_qs(urlparse(url).query)
    async_client = httpx.AsyncClient

    def exchange(request):
        return httpx.Response(
            200,
            json={"id_token": signed(private, nonce=query["nonce"][0])}
            if request.url.path == "/token"
            else {"keys": [public]},
        )

    monkeypatch.setattr(
        "zelyonka.oidc.httpx.AsyncClient",
        lambda **kwargs: async_client(transport=httpx.MockTransport(exchange), **kwargs),
    )
    with pytest.raises(ValueError, match="не привязан"):
        await oidc.callback("fixture-code", query["state"][0], browser)
    assert len(stack["accounts"].list()) == 2


@pytest.mark.asyncio
async def test_revoked_browser_session_cannot_finish_telegram_link(stack, provider):
    oidc, _, _ = provider
    url, browser = oidc.start(account_id=stack["owner"]["id"], invite=None)
    state = parse_qs(urlparse(url).query)["state"][0]
    with stack["db"].connect() as db:
        db.execute("DELETE FROM sessions")
    with pytest.raises(ValueError, match="Сеанс"):
        await oidc.callback("code", state, browser, stack["owner_session"][0])
