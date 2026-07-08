"""FortiGuard Web Filter Rating API (premiumapi.fortinet.com) 클라이언트.

샘플:
  curl -X GET --header 'Accept: application/json' --header 'Token: <API key>' \
    'https://premiumapi.fortinet.com/v1/rate?url=fndn.fortinet.net'
"""
import requests

API_URL = "https://premiumapi.fortinet.com/v1/rate"
TIMEOUT = 15


def check_url(api_key: str, url: str) -> dict:
    """FortiGuard 카테고리 등급 조회.

    반환 예시:
      {"status": "found", "category": "Information Technology", "category_id": 26, "raw": {...}}
      {"status": "not_found", "category": None, "category_id": None, "raw": {...}}
      {"status": "error", "error": "invalid_api_key" | "rate_limited" | "http_4xx/5xx" | 예외 메시지}
    """
    headers = {"Accept": "application/json", "Token": api_key}

    try:
        resp = requests.get(API_URL, headers=headers, params={"url": url}, timeout=TIMEOUT)
    except requests.RequestException as e:
        return {"status": "error", "error": str(e)}

    if resp.status_code in (401, 403):
        return {"status": "error", "error": "invalid_api_key"}
    if resp.status_code == 429:
        return {"status": "error", "error": "rate_limited"}
    if resp.status_code != 200:
        return {"status": "error", "error": f"http_{resp.status_code}"}

    try:
        data = resp.json()
    except ValueError:
        return {"status": "error", "error": "invalid_json_response"}

    # 실제 응답 형태: {"url": "...", "categoryid": 52, "categoryname": "Information Technology"}
    category = data.get("categoryname")
    category_id = data.get("categoryid")
    if category is None and category_id is None:
        return {"status": "not_found", "category": None, "category_id": None, "raw": data}

    return {"status": "found", "category": category, "category_id": category_id, "raw": data}
