from app.middleware._asgi import path_is_exempt
from app.middleware.rate_limit import client_key
from app.middleware.request_context import resolve_request_id
from app.middleware.security_headers import API_CSP, DOCS_CSP, SecurityHeadersConfig


def test_request_id_validation():
    assert resolve_request_id("abc-123_X.y") == "abc-123_X.y"
    minted = resolve_request_id("bad id with spaces")
    assert len(minted) == 32
    assert resolve_request_id("x" * 200) != "x" * 200


def test_path_exemption_is_prefix_segment_aware():
    assert path_is_exempt("/api/v1/health", ("/api/v1/health",))
    assert path_is_exempt("/api/v1/health/live", ("/api/v1/health",))
    assert not path_is_exempt("/api/v1/healthz", ("/api/v1/health",))


def test_security_headers_vary_for_docs():
    cfg = SecurityHeadersConfig(enable_hsts=True)
    api = dict(cfg.headers_for("/api/v1/users"))
    docs = dict(cfg.headers_for("/docs"))
    assert api[b"content-security-policy"] == API_CSP.encode()
    assert docs[b"content-security-policy"] == DOCS_CSP.encode()
    assert b"strict-transport-security" in api
    assert b"strict-transport-security" not in dict(
        SecurityHeadersConfig(enable_hsts=False).headers_for("/")
    )


def test_client_key_prefers_bearer_token():
    scope = {"client": ("1.2.3.4", 1234), "headers": [(b"authorization", b"Bearer abc")]}
    assert client_key(scope).startswith("tok:")
    assert client_key({"client": ("1.2.3.4", 1), "headers": []}) == "ip:1.2.3.4"
    assert client_key({"client": None, "headers": []}) == "ip:unknown"
