import asyncio
import ipaddress
import ssl
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from test_agent_migration import Adapter

from smartdns.node import NodeEngine, NodeSettings, Snapshot, create_node


def certificates(root):
    authority_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-node-test-ca")])
    now = datetime.now(UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(authority_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(authority_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(authority_key, hashes.SHA256())
    )
    (root / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for label, purpose in [
        ("server", ExtendedKeyUsageOID.SERVER_AUTH),
        ("client", ExtendedKeyUsageOID.CLIENT_AUTH),
    ]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()), critical=False
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(authority_key, hashes.SHA256())
        )
        (root / f"{label}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / f"{label}.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )


def engine(tmp_path):
    node = NodeEngine(NodeSettings("8.8.8.8", "8.8.4.4", "unused", "unused", "unused"), Adapter(tmp_path))
    node.observed_egress = "8.8.4.4"
    node.last_observation = time.monotonic()
    return node


def snapshot(generation=1, leases=None):
    return Snapshot(generation=generation, patterns=[r"^([a-z0-9-]+\.)*example\.com$"], leases=leases or [])


@pytest.mark.asyncio
async def test_node_revocation_expiry_generation_and_watchdog(tmp_path):
    node = engine(tmp_path)
    body = snapshot(
        leases=[{"account_id": "u0123456789ab", "ip": "1.1.1.1", "expires": int(time.time()) + 100}]
    )
    assert (await node.sync(body))["ready"]
    assert node.adapter.sources == {"1.1.1.1": body.leases[0].expires}
    assert (await node.sync(snapshot(2)))["ready"]
    assert not node.adapter.sources
    with pytest.raises(ValueError, match="Stale"):
        await node.sync(body)
    with pytest.raises(ValueError, match="lifetime"):
        await node.sync(
            snapshot(
                3, [{"account_id": "u0123456789ab", "ip": "1.1.1.1", "expires": int(time.time()) + 99999}]
            )
        )
    node.last_sync = time.monotonic() - 13
    assert not node.ready()
    node.observed_egress = "9.9.9.9"
    assert not (await node.sync(snapshot(4)))["ready"]
    node.adapter.fail = True
    with pytest.raises(RuntimeError):
        await node.sync(snapshot(5))
    assert not node.ready()


@pytest.mark.asyncio
async def test_real_node_tls_requires_client_certificate(tmp_path):
    certificates(tmp_path)
    node = engine(tmp_path)

    async def observe():
        node.observed_egress = "8.8.4.4"
        node.last_observation = time.monotonic()

    node.observe = observe
    config = uvicorn.Config(
        create_node(node),
        host="127.0.0.1",
        port=0,
        ssl_certfile=str(tmp_path / "server.pem"),
        ssl_keyfile=str(tmp_path / "server.key"),
        ssl_ca_certs=str(tmp_path / "ca.pem"),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        access_log=False,
        log_level="critical",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started
        port = server.servers[0].sockets[0].getsockname()[1]
        url = f"https://127.0.0.1:{port}"
        verify = ssl.create_default_context(cafile=str(tmp_path / "ca.pem"))
        async with httpx.AsyncClient(verify=verify, timeout=2, trust_env=False) as client:
            with pytest.raises(httpx.HTTPError):
                await client.get(url + "/status")
        verify.load_cert_chain(tmp_path / "client.pem", tmp_path / "client.key")
        async with httpx.AsyncClient(verify=verify, timeout=2, trust_env=False) as client:
            response = await client.post(url + "/sync", json=snapshot().model_dump())
            assert response.status_code == 200 and response.json()["ready"]
            response = await client.post(
                url + "/sync", json={"generation": 1, "patterns": [".*"], "leases": []}
            )
            assert response.status_code == 400
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
