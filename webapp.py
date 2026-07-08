"""웹 대시보드: 수집된 URL을 날짜/출처로 검색하고, 선택한 URL만 FortiProxy로 push,
VirusTotal 매칭 결과를 조회하는 Flask 앱.

실행: python webapp.py  (기본 포트 5050)
"""
import math
import os
import secrets
import time

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

import auth
import fortiguard
import scheduler
import store
import vt
from forti import FortiProxyClient

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_PATH)

app = Flask(__name__)
DB_PATH = os.path.join(BASE_DIR, os.environ.get("DB_PATH", "urls.db"))

# 세션 서명용 시크릿 키. .env에 없으면 최초 1회 생성해 저장(재시작해도 세션 유지).
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
    with open(ENV_PATH, "a") as f:
        f.write(f"\nFLASK_SECRET_KEY={app.secret_key}\n")

with store.connect(DB_PATH) as _conn:
    auth.ensure_default_account(_conn)

MAX_VT_BATCH = 4  # VirusTotal 무료 API: 분당 4건 제한
VT_CALL_DELAY = 15  # 초, 배치 내 호출 간격

MAX_FG_BATCH = 10  # FortiGuard 프리미엄 API 한 번 조회당 상한 (문서화된 제한 없어 안전하게 캡)

SCHEDULE_PRESETS = {
    "*/5 * * * *": "5분마다",
    "*/10 * * * *": "10분마다",
    "*/15 * * * *": "15분마다",
    "*/30 * * * *": "30분마다",
    "0 * * * *": "1시간마다",
    "0 */3 * * *": "3시간마다",
    "0 */6 * * *": "6시간마다",
    "0 */12 * * *": "12시간마다",
    "0 0 * * *": "매일 자정",
}


def _mask(key: str) -> str:
    if not key or len(key) < 8:
        return "****"
    return f"{key[:4]}…{key[-4:]}"


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        with store.connect(DB_PATH) as conn:
            ok = auth.verify_login(conn, username, password)
        if ok:
            session.clear()
            session["logged_in"] = True
            session["username"] = username
            return redirect(request.args.get("next") or url_for("index"))
        error = "아이디 또는 비밀번호가 올바르지 않습니다"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/change-password", methods=["POST"])
@auth.login_required
def api_change_password():
    data = request.get_json(force=True) or {}
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    with store.connect(DB_PATH) as conn:
        ok, msg = auth.change_password(conn, current_password, new_password)
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"ok": True})


@app.route("/")
@auth.login_required
def index():
    return render_template("index.html")


@app.route("/api/urls")
@auth.login_required
def api_urls():
    date = request.args.get("date") or None
    source = request.args.get("source") or None
    q = request.args.get("q") or None
    page = max(int(request.args.get("page", 1)), 1)
    page_size = min(max(int(request.args.get("page_size", 50)), 1), 200)

    with store.connect(DB_PATH) as conn:
        rows, total = store.search_urls(conn, date=date, source=source, q=q, page=page, page_size=page_size)

    return jsonify({
        "rows": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(math.ceil(total / page_size), 1),
    })


@app.route("/api/dates")
@auth.login_required
def api_dates():
    with store.connect(DB_PATH) as conn:
        return jsonify(store.list_dates(conn))


@app.route("/api/settings", methods=["GET", "POST"])
@auth.login_required
def api_settings():
    with store.connect(DB_PATH) as conn:
        if request.method == "POST":
            data = request.get_json(force=True) or {}
            if "vt_api_key" in data:
                store.set_setting(conn, "vt_api_key", (data.get("vt_api_key") or "").strip())
            if "fortiguard_api_key" in data:
                store.set_setting(
                    conn, "fortiguard_api_key", (data.get("fortiguard_api_key") or "").strip()
                )
            if "forti_host" in data:
                store.set_setting(conn, "forti_host", (data.get("forti_host") or "").strip())
            if "forti_api_key" in data:
                store.set_setting(conn, "forti_api_key", (data.get("forti_api_key") or "").strip())
            if "forti_resource_name" in data:
                store.set_setting(
                    conn, "forti_resource_name", (data.get("forti_resource_name") or "").strip()
                )
            return jsonify({"ok": True})

        vt_key = store.get_vt_api_key(conn)
        fg_key = store.get_fortiguard_api_key(conn)
        forti = store.get_forti_config(conn)
        return jsonify({
            "username": store.get_setting(conn, "auth_username"),
            "vt_api_key_set": bool(vt_key),
            "vt_api_key_masked": _mask(vt_key) if vt_key else None,
            "fortiguard_api_key_set": bool(fg_key),
            "fortiguard_api_key_masked": _mask(fg_key) if fg_key else None,
            "forti_host": forti["host"] or "",
            "forti_resource_name": forti["resource_name"] or "",
            "forti_api_key_set": bool(forti["api_key"]),
            "forti_api_key_masked": _mask(forti["api_key"]) if forti["api_key"] else None,
            "fortiproxy_configured": bool(
                forti["host"] and forti["api_key"] and forti["resource_name"]
            ),
        })


@app.route("/api/schedule", methods=["GET", "POST"])
@auth.login_required
def api_schedule():
    if request.method == "POST":
        data = request.get_json(force=True) or {}

        if data.get("action") == "clear":
            try:
                scheduler.clear_schedule()
            except Exception as e:
                return jsonify({"error": f"cron 해제 실패: {e}"}), 500
            return jsonify({"ok": True})

        cron_expr = (data.get("cron_expr") or "").strip()
        if not cron_expr:
            return jsonify({"error": "cron 표현식을 입력하세요"}), 400
        try:
            schedule = scheduler.set_schedule(BASE_DIR, cron_expr)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            return jsonify({"error": f"cron 등록 실패: {e}"}), 500
        return jsonify({"ok": True, "schedule": schedule})

    try:
        schedule = scheduler.get_schedule()
    except Exception as e:
        return jsonify({"error": f"cron 조회 실패: {e}"}), 500
    return jsonify({"schedule": schedule, "presets": SCHEDULE_PRESETS})


@app.route("/api/push", methods=["POST"])
@auth.login_required
def api_push():
    data = request.get_json(force=True) or {}
    urls = data.get("urls") or []
    if not urls:
        return jsonify({"error": "선택된 URL이 없습니다"}), 400

    with store.connect(DB_PATH) as conn:
        forti = store.get_forti_config(conn)

    missing = [k for k in ("host", "api_key", "resource_name") if not forti[k]]
    if missing:
        return jsonify({"error": f"FortiProxy 설정이 비어 있습니다: {', '.join(missing)} (설정 패널에서 입력하세요)"}), 400

    client = FortiProxyClient(
        host=forti["host"],
        api_key=forti["api_key"],
        resource_name=forti["resource_name"],
        verify_ssl=forti["verify_ssl"],
    )

    try:
        succeeded, failed = client.push_urls(urls)
    except Exception as e:  # FortiProxy 연결/인증 오류 등
        return jsonify({"error": f"FortiProxy 요청 실패: {e}"}), 502

    with store.connect(DB_PATH) as conn:
        store.mark_pushed(conn, succeeded)

    return jsonify({"succeeded": succeeded, "failed": failed})


@app.route("/api/vt-check", methods=["POST"])
@auth.login_required
def api_vt_check():
    data = request.get_json(force=True) or {}
    urls = (data.get("urls") or [])[:MAX_VT_BATCH]
    if not urls:
        return jsonify({"error": "선택된 URL이 없습니다"}), 400

    with store.connect(DB_PATH) as conn:
        api_key = store.get_vt_api_key(conn)
        if not api_key:
            return jsonify({"error": "VirusTotal API 키가 설정되어 있지 않습니다"}), 400

        raw_map = store.raw_urls_for(conn, urls)

        results = {}
        for i, url in enumerate(urls):
            raw = raw_map.get(url, url)
            result = vt.check_url(api_key, raw)
            results[url] = result
            store.update_vt_result(
                conn, url, result.get("status"), result.get("malicious"), result.get("total")
            )
            if i < len(urls) - 1:
                time.sleep(VT_CALL_DELAY)

    return jsonify({"results": results, "batch_limit": MAX_VT_BATCH})


@app.route("/api/fortiguard-check", methods=["POST"])
@auth.login_required
def api_fortiguard_check():
    data = request.get_json(force=True) or {}
    urls = (data.get("urls") or [])[:MAX_FG_BATCH]
    if not urls:
        return jsonify({"error": "선택된 URL이 없습니다"}), 400

    with store.connect(DB_PATH) as conn:
        api_key = store.get_fortiguard_api_key(conn)
        if not api_key:
            return jsonify({"error": "FortiGuard API 키가 설정되어 있지 않습니다"}), 400

        raw_map = store.raw_urls_for(conn, urls)

        results = {}
        for url in urls:
            raw = raw_map.get(url, url)
            result = fortiguard.check_url(api_key, raw)
            results[url] = result
            store.update_fg_result(
                conn, url, result.get("status"), result.get("category"), result.get("category_id")
            )

    return jsonify({"results": results, "batch_limit": MAX_FG_BATCH})


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("WEBAPP_PORT", 5050)))
