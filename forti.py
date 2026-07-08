"""FortiProxy REST(monitor) API 클라이언트 - External Resource(Threat Feed)에 URL push.

사전 준비 (FortiProxy 측, 1회성):
  1) REST API 관리자 생성 후 API 토큰 발급 (Bearer 인증)
  2) External Resource 오브젝트 생성 (CLI 예):
       config system external-resource
           edit "3rd_feed"
               set type domain
               set resource "https://placeholder"
           next
       end
     (이름은 자유롭게 지정 가능 - 웹 대시보드 설정의 '리소스 이름' 값과 동일해야 함.
      resource 필드는 dynamic push만 쓰더라도 형식상 채워야 함)
  3) 해당 External Resource를 Web Filter 프로파일 등에서 참조해 실제 정책에 연결

API 형태 (FortiProxy 제공 샘플):
  POST /api/v2/monitor/system/external-resource/dynamic
  {"commands": [{"name": "<resource>", "command": "add", "entries": ["url1", "url2", ...]}]}
"""
import logging

import requests
import urllib3

logger = logging.getLogger(__name__)


class FortiProxyClient:
    def __init__(self, host: str, api_key: str, resource_name: str, verify_ssl: bool = False):
        self.url = f"https://{host}/api/v2/monitor/system/external-resource/dynamic"
        self.resource_name = resource_name
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })
        self.verify_ssl = verify_ssl
        if not verify_ssl:
            # FortiProxy 자체서명 인증서 사용 시 발생하는 InsecureRequestWarning 억제 (curl -k와 동일한 의도)
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def push_urls(self, urls, command: str = "add"):
        """선택된 URL을 한 번의 요청으로 external resource에 반영.

        FortiProxy는 배치 단위 응답만 주고 entry별 결과는 제공하지 않으므로,
        요청이 성공하면 전체를 성공으로, 실패하면 전체를 실패로 반환한다.
        """
        if not urls:
            return [], []

        urls = list(urls)
        payload = {
            "commands": [
                {"name": self.resource_name, "command": command, "entries": urls}
            ]
        }
        resp = self.session.post(self.url, json=payload, verify=self.verify_ssl, timeout=30)

        if resp.status_code == 200:
            data = resp.json() if resp.content else {}
            if data.get("status", "success") == "success":
                return urls, []
            logger.warning("push 실패 status=%s body=%s", resp.status_code, resp.text[:500])
            return [], urls

        logger.warning("push 실패 status=%s body=%s", resp.status_code, resp.text[:500])
        return [], urls
