"""세션 기반 로그인 인증. 자격 증명은 SQLite settings 테이블에 해시로 저장한다."""
from functools import wraps

from flask import jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import store

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "fortinet1!"


def ensure_default_account(conn):
    """최초 실행 시에만 기본 계정을 생성 (이미 있으면 건드리지 않음)."""
    if store.get_setting(conn, "auth_username") is None:
        store.set_setting(conn, "auth_username", DEFAULT_USERNAME)
        store.set_setting(conn, "auth_password_hash", generate_password_hash(DEFAULT_PASSWORD))


def verify_login(conn, username: str, password: str) -> bool:
    stored_user = store.get_setting(conn, "auth_username")
    stored_hash = store.get_setting(conn, "auth_password_hash")
    if not stored_user or not stored_hash:
        return False
    return username == stored_user and check_password_hash(stored_hash, password)


def change_password(conn, current_password: str, new_password: str) -> tuple[bool, str]:
    stored_hash = store.get_setting(conn, "auth_password_hash")
    if not stored_hash or not check_password_hash(stored_hash, current_password):
        return False, "현재 비밀번호가 올바르지 않습니다"
    if len(new_password) < 8:
        return False, "새 비밀번호는 8자 이상이어야 합니다"
    store.set_setting(conn, "auth_password_hash", generate_password_hash(new_password))
    return True, ""


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if session.get("logged_in"):
            return view_func(*args, **kwargs)
        if request.path.startswith("/api/"):
            return jsonify({"error": "로그인이 필요합니다"}), 401
        return redirect(url_for("login", next=request.path))

    return wrapped
