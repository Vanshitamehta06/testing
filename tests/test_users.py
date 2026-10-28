import pytest

from app.users import AccountExistsError, InvalidAccountError, InvalidResetCodeError, UserStore


def test_register_and_authenticate():
    store = UserStore()
    store.register("Ana@Example.com", "correct-horse")
    token = store.authenticate("ana@example.com", "correct-horse")
    assert token
    assert store.user_for_token(token) == "ana@example.com"


def test_wrong_password_and_unknown_email_rejected():
    store = UserStore()
    store.register("ana@example.com", "correct-horse")
    assert store.authenticate("ana@example.com", "wrong-password") is None
    assert store.authenticate("nobody@example.com", "correct-horse") is None


def test_password_is_not_stored_in_plain_text():
    store = UserStore()
    user = store.register("ana@example.com", "correct-horse")
    assert b"correct-horse" not in user.password_hash


def test_duplicate_and_invalid_registrations_rejected():
    store = UserStore()
    store.register("ana@example.com", "correct-horse")
    with pytest.raises(AccountExistsError):
        store.register("ANA@example.com", "another-password")
    with pytest.raises(InvalidAccountError):
        store.register("not-an-email", "correct-horse")
    with pytest.raises(InvalidAccountError):
        store.register("bo@example.com", "short")


def test_password_reset_flow():
    store = UserStore()
    store.register("ana@example.com", "correct-horse")
    old_session = store.authenticate("ana@example.com", "correct-horse")
    code = store.request_reset("ANA@example.com")
    assert code and len(code) == 6 and code.isdigit()
    store.reset_password("ana@example.com", code, "brand-new-pass")
    assert store.authenticate("ana@example.com", "correct-horse") is None
    assert store.authenticate("ana@example.com", "brand-new-pass")
    assert store.user_for_token(old_session) is None  # signed out everywhere
    with pytest.raises(InvalidResetCodeError):
        store.reset_password("ana@example.com", code, "another-pass1")  # single use


def test_reset_for_unknown_email_gives_no_code():
    assert UserStore().request_reset("nobody@example.com") is None


def test_reset_code_expires_and_locks_after_wrong_attempts():
    store = UserStore()
    store.register("ana@example.com", "correct-horse")
    code = store.request_reset("ana@example.com", now=1000.0)
    with pytest.raises(InvalidResetCodeError):
        store.reset_password("ana@example.com", code, "brand-new-pass", now=1000.0 + 16 * 60)
    code = store.request_reset("ana@example.com")
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        with pytest.raises(InvalidResetCodeError):
            store.reset_password("ana@example.com", wrong, "brand-new-pass")
    with pytest.raises(InvalidResetCodeError):
        store.reset_password("ana@example.com", code, "brand-new-pass")  # locked after 5 wrong tries


def test_reset_rejects_short_new_password():
    store = UserStore()
    store.register("ana@example.com", "correct-horse")
    code = store.request_reset("ana@example.com")
    with pytest.raises(InvalidAccountError):
        store.reset_password("ana@example.com", code, "short")
