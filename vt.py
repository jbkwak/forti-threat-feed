"""VirusTotal v3 API 클라이언트 - URL 평판 조회.

무료 API 키는 분당 4건 / 일 500건 제한이 있으므로 호출 측(webapp.py)에서
배치 크기와 호출 간격을 조절해야 한다.
"""
import base64

import requests

API_BASE = "https://www.virustotal.com/api/v3"
TIMEOUT = 20


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_url(api_key: str, url: str, submit_if_missing: bool = True) -> dict:
    """VT에 등록된 스캔 결과를 조회. 없으면(옵션) 새로 제출만 하고 결과는 다음 조회 때 받는다.

    반환 예시:
      {"status": "found", "malicious": 3, "suspicious": 1, "total": 90, "permalink": "..."}
      {"status": "submitted", ...}   # VT에 처음 제출됨, 분석은 비동기로 진행됨
      {"status": "not_found", ...}   # 제출도 안 됨 (submit_if_missing=False)
      {"status": "error", "error": "invalid_api_key" | "rate_limited" | "http_5xx"}
    """
    headers = {"x-apikey": api_key}
    url_id = _url_id(url)
    permalink = f"https://www.virustotal.com/gui/url/{url_id}"

    try:
        resp = requests.get(f"{API_BASE}/urls/{url_id}", headers=headers, timeout=TIMEOUT)
    except requests.RequestException as e:
        return {"status": "error", "error": str(e)}

    if resp.status_code == 200:
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        return {
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values()) if stats else 0,
            "permalink": permalink,
        }

    if resp.status_code == 404:
        if submit_if_missing:
            try:
                requests.post(
                    f"{API_BASE}/urls", headers=headers, data={"url": url}, timeout=TIMEOUT
                )
            except requests.RequestException:
                pass
            return {
                "status": "submitted",
                "malicious": None,
                "suspicious": None,
                "total": None,
                "permalink": permalink,
            }
        return {
            "status": "not_found",
            "malicious": None,
            "suspicious": None,
            "total": None,
            "permalink": None,
        }

    if resp.status_code == 401:
        return {"status": "error", "error": "invalid_api_key"}
    if resp.status_code == 429:
        return {"status": "error", "error": "rate_limited"}
    return {"status": "error", "error": f"http_{resp.status_code}"}
