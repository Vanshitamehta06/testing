import sqlite3

from app.users import UserStore


def test_accounts_and_sessions_survive_a_restart(tmp_path):
    path = str(tmp_path / "app.db")
    first = UserStore(path)
    first.register("ana@example.com", "correct-horse")
    token = first.authenticate("ana@example.com", "correct-horse")
    restarted = UserStore(path)  # a new server process opening the same database
    assert restarted.authenticate("ana@example.com", "correct-horse")
    assert restarted.user_for_token(token) == "ana@example.com"


def test_reset_codes_survive_a_restart(tmp_path):
    path = str(tmp_path / "app.db")
    first = UserStore(path)
    first.register("ana@example.com", "correct-horse")
    code = first.request_reset("ana@example.com")
    UserStore(path).reset_password("ana@example.com", code, "brand-new-pass")
    assert UserStore(path).authenticate("ana@example.com", "brand-new-pass")


def test_secrets_are_not_stored_in_plain_text(tmp_path):
    path = str(tmp_path / "app.db")
    store = UserStore(path)
    store.register("ana@example.com", "correct-horse")
    token = store.authenticate("ana@example.com", "correct-horse")
    code = store.request_reset("ana@example.com")
    dump = "\n".join(sqlite3.connect(path).iterdump())
    assert "correct-horse" not in dump and token not in dump and code not in dump
