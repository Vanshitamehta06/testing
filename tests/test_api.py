from fastapi.testclient import TestClient

from app import main


def client() -> TestClient:
    main.store = main.UserStore()
    return TestClient(main.app)


def test_page_served_with_every_view():
    resp = client().get("/")
    assert resp.status_code == 200
    assert "Sign In Page" in resp.text
    for view in ("auth-form", "reset-request-form", "reset-confirm-form", "Forgot password?"):
        assert view in resp.text


def test_static_assets_served():
    c = client()
    assert c.get("/static/app.js").status_code == 200
    assert c.get("/static/styles.css").status_code == 200


def test_register_then_login_then_me():
    c = client()
    assert c.post("/api/register", json={"email": "ana@example.com", "password": "correct-horse"}).status_code == 201
    resp = c.post("/api/login", json={"email": "ana@example.com", "password": "correct-horse"})
    assert resp.status_code == 200
    token = resp.json()["token"]
    me = c.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert me.json() == {"email": "ana@example.com"}


def test_bad_credentials_and_duplicates():
    c = client()
    c.post("/api/register", json={"email": "ana@example.com", "password": "correct-horse"})
    assert c.post("/api/register", json={"email": "ana@example.com", "password": "correct-horse"}).status_code == 409
    assert c.post("/api/login", json={"email": "ana@example.com", "password": "nope-nope"}).status_code == 401
    assert c.post("/api/register", json={"email": "bad", "password": "correct-horse"}).status_code == 422
    assert c.get("/api/me").status_code == 401


def test_password_reset_over_http():
    c = client()
    c.post("/api/register", json={"email": "ana@example.com", "password": "correct-horse"})
    sent = c.post("/api/password-reset/request", json={"email": "ana@example.com"}).json()
    unknown = c.post("/api/password-reset/request", json={"email": "nobody@example.com"}).json()
    assert sent["message"] == unknown["message"]  # does not reveal which emails have accounts
    assert "demo_code" not in unknown
    bad = c.post("/api/password-reset/confirm",
                 json={"email": "ana@example.com", "code": "x", "new_password": "brand-new-pass"})
    assert bad.status_code == 400
    ok = c.post("/api/password-reset/confirm",
                json={"email": "ana@example.com", "code": sent["demo_code"], "new_password": "brand-new-pass"})
    assert ok.status_code == 200
    assert c.post("/api/login", json={"email": "ana@example.com", "password": "brand-new-pass"}).status_code == 200
    assert c.post("/api/login", json={"email": "ana@example.com", "password": "correct-horse"}).status_code == 401


def test_health():
    assert client().get("/health").json() == {"status": "ok"}
