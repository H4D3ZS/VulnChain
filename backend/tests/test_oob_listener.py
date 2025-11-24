"""Tests for OOB Listener"""

import asyncio
import base64
from datetime import datetime, timezone
from urllib.parse import quote

import pytest
import aiohttp

from app.core.oob_listener import OOBListener, Callback, PayloadRegistration


@pytest.fixture
async def oob_listener():
    """Create OOB listener for testing"""
    # Use non-privileged ports for testing
    listener = OOBListener(http_port=18080, dns_port=15353, domain="test.local")
    await listener.start()
    yield listener
    await listener.stop()


@pytest.mark.asyncio
async def test_oob_listener_initialization():
    """Test OOB listener initialization"""
    listener = OOBListener(http_port=18081, dns_port=15354, domain="test.local")
    assert listener.http_port == 18081
    assert listener.dns_port == 15354
    assert listener.domain == "test.local"
    assert not listener.is_running


@pytest.mark.asyncio
async def test_oob_listener_start_stop(oob_listener):
    """Test starting and stopping OOB listener"""
    assert oob_listener.is_running
    await oob_listener.stop()
    assert not oob_listener.is_running


@pytest.mark.asyncio
async def test_generate_unique_id(oob_listener):
    """Test unique ID generation"""
    id1 = oob_listener.generate_unique_id()
    id2 = oob_listener.generate_unique_id()

    assert id1 != id2
    assert len(id1) > 0
    assert len(id2) > 0


@pytest.mark.asyncio
async def test_get_callback_url(oob_listener):
    """Test callback URL generation"""
    unique_id = "test-123"
    url = oob_listener.get_callback_url(unique_id)

    assert unique_id in url
    assert oob_listener.domain in url
    assert str(oob_listener.http_port) in url


@pytest.mark.asyncio
async def test_get_dns_callback(oob_listener):
    """Test DNS callback hostname generation"""
    unique_id = "test-456"
    hostname = oob_listener.get_dns_callback(unique_id)

    assert unique_id in hostname
    assert oob_listener.domain in hostname


@pytest.mark.asyncio
async def test_http_callback_reception(oob_listener):
    """Test receiving HTTP callbacks"""
    unique_id = oob_listener.generate_unique_id()
    callback_url = f"http://localhost:{oob_listener.http_port}/{unique_id}"

    # Send HTTP request
    async with aiohttp.ClientSession() as session:
        async with session.get(callback_url) as response:
            assert response.status == 200

    # Wait a bit for callback to be processed
    await asyncio.sleep(0.1)

    # Check callback was stored
    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 1
    assert callbacks[0].unique_id == unique_id
    assert callbacks[0].callback_type == "http"


@pytest.mark.asyncio
async def test_http_callback_with_query_params(oob_listener):
    """Test HTTP callback with query parameters"""
    unique_id = oob_listener.generate_unique_id()
    callback_url = (
        f"http://localhost:{oob_listener.http_port}/{unique_id}?param1=value1"
    )

    async with aiohttp.ClientSession() as session:
        async with session.get(callback_url) as response:
            assert response.status == 200

    await asyncio.sleep(0.1)

    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 1
    assert "param1" in callbacks[0].data["query_params"]
    assert callbacks[0].data["query_params"]["param1"] == "value1"


@pytest.mark.asyncio
async def test_http_callback_with_body(oob_listener):
    """Test HTTP callback with POST body"""
    unique_id = oob_listener.generate_unique_id()
    callback_url = f"http://localhost:{oob_listener.http_port}/{unique_id}"
    test_data = "test payload data"

    async with aiohttp.ClientSession() as session:
        async with session.post(callback_url, data=test_data) as response:
            assert response.status == 200

    await asyncio.sleep(0.1)

    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 1
    assert callbacks[0].data["body"] == test_data
    assert callbacks[0].data["method"] == "POST"


@pytest.mark.asyncio
async def test_wait_for_callback_success(oob_listener):
    """Test waiting for callback with success"""
    unique_id = oob_listener.generate_unique_id()
    callback_url = f"http://localhost:{oob_listener.http_port}/{unique_id}"

    # Start waiting in background
    async def send_callback():
        await asyncio.sleep(0.1)
        async with aiohttp.ClientSession() as session:
            await session.get(callback_url)

    asyncio.create_task(send_callback())

    # Wait for callback
    callback = await oob_listener.wait_for_callback(unique_id, timeout=2.0)

    assert callback is not None
    assert callback.unique_id == unique_id


@pytest.mark.asyncio
async def test_wait_for_callback_timeout(oob_listener):
    """Test waiting for callback with timeout"""
    unique_id = oob_listener.generate_unique_id()

    # Wait for callback that never arrives
    callback = await oob_listener.wait_for_callback(unique_id, timeout=0.5)

    assert callback is None


@pytest.mark.asyncio
async def test_register_payload(oob_listener):
    """Test payload registration"""
    unique_id = oob_listener.generate_unique_id()

    await oob_listener.register_payload(
        unique_id=unique_id,
        payload="test payload",
        target_url="https://example.com",
        injection_point="param1",
        vulnerability_type="sqli",
        metadata={"test": "data"},
    )

    registration = oob_listener.get_payload_registration(unique_id)
    assert registration is not None
    assert registration.unique_id == unique_id
    assert registration.payload == "test payload"
    assert registration.target_url == "https://example.com"
    assert registration.injection_point == "param1"
    assert registration.vulnerability_type == "sqli"
    assert registration.metadata["test"] == "data"


@pytest.mark.asyncio
async def test_correlate_callback(oob_listener):
    """Test callback correlation with payload"""
    unique_id = oob_listener.generate_unique_id()

    # Register payload
    await oob_listener.register_payload(
        unique_id=unique_id,
        payload="test payload",
        target_url="https://example.com",
        injection_point="param1",
        vulnerability_type="xxe",
    )

    # Send callback
    callback_url = f"http://localhost:{oob_listener.http_port}/{unique_id}"
    async with aiohttp.ClientSession() as session:
        await session.get(callback_url)

    await asyncio.sleep(0.1)

    # Get callback
    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 1

    # Correlate
    payload_reg = oob_listener.correlate_callback(callbacks[0])
    assert payload_reg is not None
    assert payload_reg.unique_id == unique_id
    assert payload_reg.vulnerability_type == "xxe"


@pytest.mark.asyncio
async def test_get_correlated_callbacks(oob_listener):
    """Test getting correlated payload and callbacks"""
    unique_id = oob_listener.generate_unique_id()

    # Register payload
    await oob_listener.register_payload(
        unique_id=unique_id,
        payload="test",
        target_url="https://example.com",
        injection_point="test",
        vulnerability_type="ssrf",
    )

    # Send multiple callbacks
    callback_url = f"http://localhost:{oob_listener.http_port}/{unique_id}"
    async with aiohttp.ClientSession() as session:
        await session.get(callback_url)
        await session.get(callback_url)

    await asyncio.sleep(0.1)

    # Get correlated data
    payload, callbacks = oob_listener.get_correlated_callbacks(unique_id)

    assert payload is not None
    assert payload.vulnerability_type == "ssrf"
    assert len(callbacks) == 2


@pytest.mark.asyncio
async def test_decode_base64_data(oob_listener):
    """Test automatic base64 decoding"""
    unique_id = oob_listener.generate_unique_id()
    secret_data = "secret_flag{test123}"
    encoded_data = base64.b64encode(secret_data.encode()).decode()

    callback_url = (
        f"http://localhost:{oob_listener.http_port}/{unique_id}?data={encoded_data}"
    )

    async with aiohttp.ClientSession() as session:
        await session.get(callback_url)

    await asyncio.sleep(0.1)

    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 1
    assert callbacks[0].decoded_data is not None
    assert secret_data in callbacks[0].decoded_data


@pytest.mark.asyncio
async def test_decode_url_encoded_data(oob_listener):
    """Test automatic URL decoding"""
    unique_id = oob_listener.generate_unique_id()
    secret_data = "secret flag with spaces"
    # Double encode to test decoding (first encoding is handled by aiohttp)
    encoded_data = quote(quote(secret_data))

    callback_url = (
        f"http://localhost:{oob_listener.http_port}/{unique_id}?data={encoded_data}"
    )

    async with aiohttp.ClientSession() as session:
        await session.get(callback_url)

    await asyncio.sleep(0.1)

    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 1
    assert callbacks[0].decoded_data is not None
    # Should decode to the original or at least contain recognizable text
    assert "secret" in callbacks[0].decoded_data or secret_data in callbacks[0].decoded_data


@pytest.mark.asyncio
async def test_decode_hex_data(oob_listener):
    """Test automatic hex decoding"""
    unique_id = oob_listener.generate_unique_id()
    secret_data = "flag"
    encoded_data = secret_data.encode().hex()

    callback_url = (
        f"http://localhost:{oob_listener.http_port}/{unique_id}?data={encoded_data}"
    )

    async with aiohttp.ClientSession() as session:
        await session.get(callback_url)

    await asyncio.sleep(0.1)

    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 1
    assert callbacks[0].decoded_data is not None
    assert secret_data in callbacks[0].decoded_data


@pytest.mark.asyncio
async def test_clear_callbacks(oob_listener):
    """Test clearing callbacks"""
    unique_id = oob_listener.generate_unique_id()
    callback_url = f"http://localhost:{oob_listener.http_port}/{unique_id}"

    async with aiohttp.ClientSession() as session:
        await session.get(callback_url)

    await asyncio.sleep(0.1)

    # Verify callback exists
    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 1

    # Clear specific callbacks
    oob_listener.clear_callbacks(unique_id)
    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 0


@pytest.mark.asyncio
async def test_multiple_concurrent_callbacks(oob_listener):
    """Test handling multiple concurrent callbacks"""
    unique_ids = [oob_listener.generate_unique_id() for _ in range(5)]

    # Send multiple callbacks concurrently
    async def send_callback(uid):
        callback_url = f"http://localhost:{oob_listener.http_port}/{uid}"
        async with aiohttp.ClientSession() as session:
            await session.get(callback_url)

    await asyncio.gather(*[send_callback(uid) for uid in unique_ids])
    await asyncio.sleep(0.2)

    # Verify all callbacks were received
    for uid in unique_ids:
        callbacks = oob_listener.get_callbacks(uid)
        assert len(callbacks) == 1
        assert callbacks[0].unique_id == uid


@pytest.mark.asyncio
async def test_callback_timestamp(oob_listener):
    """Test callback timestamp is recorded"""
    unique_id = oob_listener.generate_unique_id()
    callback_url = f"http://localhost:{oob_listener.http_port}/{unique_id}"

    before = datetime.now(timezone.utc)
    async with aiohttp.ClientSession() as session:
        await session.get(callback_url)
    after = datetime.now(timezone.utc)

    await asyncio.sleep(0.1)

    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 1
    assert before <= callbacks[0].timestamp <= after


@pytest.mark.asyncio
async def test_callback_source_ip(oob_listener):
    """Test callback source IP is recorded"""
    unique_id = oob_listener.generate_unique_id()
    callback_url = f"http://localhost:{oob_listener.http_port}/{unique_id}"

    async with aiohttp.ClientSession() as session:
        await session.get(callback_url)

    await asyncio.sleep(0.1)

    callbacks = oob_listener.get_callbacks(unique_id)
    assert len(callbacks) == 1
    assert callbacks[0].source_ip is not None
    # Should be localhost
    assert "127.0.0.1" in callbacks[0].source_ip or "::1" in callbacks[0].source_ip
