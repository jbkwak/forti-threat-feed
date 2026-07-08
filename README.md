# forti-threat-feed

무료 악성 URL 피드(URLhaus, OpenPhish)를 수집 → 중복 제거 후 로컬 SQLite에 저장 →
웹 대시보드에서 날짜/출처로 검색하고, 필요한 URL만 선택해 FortiProxy External Resource(Threat Feed)로 push.
VirusTotal API 키를 넣으면 선택한 URL의 매칭(탐지) 결과도 조회 가능.

## 구성 파일
- `feeds.py` — 피드 수집기 (URLhaus, OpenPhish). 새 피드 추가 시 `fetch_*` 함수를 하나 만들고 `FEEDS` 리스트에 등록.
- `store.py` — SQLite 기반 중복 제거 / push 상태 / VT 결과 / 설정(웹 UI에서 입력한 값) 저장.
- `forti.py` — FortiProxy REST(monitor) API 클라이언트.
- `vt.py` — VirusTotal v3 API 클라이언트.
- `main.py` — cron용 배치 실행 진입점 (수집 → 미반영분 자동 push).
- `webapp.py` + `templates/`, `static/` — 검색/체크박스 선택 push/VT 확인용 웹 대시보드.
- `auth.py` — 로그인 세션 인증 (Flask session, 비밀번호는 해시로 SQLite에 저장).

## 로그인
웹 대시보드는 로그인해야 접근 가능합니다.
- 기본 계정: `admin` / `fortinet1!` (최초 실행 시 자동 생성)
- 대시보드 접속 후 설정 패널의 "계정 설정"에서 비밀번호 변경 가능
- **민감한 정보(FortiProxy/VT/FortiGuard API 키 등)를 다루는 화면이므로 최초 로그인 후 반드시 기본 비밀번호를 변경하세요.**
- 세션 서명 키(`FLASK_SECRET_KEY`)는 최초 실행 시 자동 생성되어 `.env`에 저장됨 — 재시작해도 로그인 세션 유지. 다른 서버로 옮길 때 이 값도 함께 복사하면 기존 세션이 유지되고, 지우면 전체 로그아웃됨.

## 설치
```bash
cd ~/forti-threat-feed
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # 최소한 cron 배치용 기본값 채우기 (웹 UI에서 덮어쓸 수도 있음)
```

## FortiProxy 사전 설정 (1회)
1. **REST API 관리자 생성**: System > Administrators > REST API Admin. Trusted Host를 이 스크립트가 실행되는 서버 IP로 제한 권장. 발급된 Bearer 토큰을 이후 `FORTIPROXY_TOKEN`(.env) 또는 웹 대시보드 설정 패널에 저장.
2. **External Resource(Threat Feed) 오브젝트 생성** (CLI 예):
   ```
   config system external-resource
       edit "3rd_feed"
           set type domain
           set resource "https://placeholder"
       next
   end
   ```
   이름("3rd_feed")은 자유롭게 지정 가능 — `.env`의 `FORTIPROXY_RESOURCE_NAME` 또는 웹 UI 설정의 "리소스 이름"과 반드시 동일해야 함. `resource` 필드는 dynamic push만 쓰더라도 형식상 채워야 함.
3. **정책에 연결**: 이 External Resource를 Web Filter 프로파일 등에서 참조해, 실제 트래픽에 적용되는 방화벽 정책에 연결.

이후 push는 다음 API 호출로 이뤄집니다 (내부적으로 `forti.py`가 수행):
```bash
curl -k -X POST -H 'Authorization: Bearer <API key>' --data '{
  "commands": [
    {"name": "3rd_feed", "command": "add", "entries": ["url1", "url2"]}
  ]
}' "https://<host>/api/v2/monitor/system/external-resource/dynamic"
```

## 웹 대시보드 실행
```bash
python webapp.py   # http://localhost:5050 (기본 포트, WEBAPP_PORT로 변경 가능)
```
- **검색**: 날짜(KST 기준) / 출처(urlhaus, openphish) / URL 텍스트로 필터링, 페이지네이션.
- **체크박스 선택 → FortiProxy Push**: 선택한 URL만 골라 위 API로 한 번에 반영. 성공한 항목은 `pushed`로 표시되어 중복 push 방지.
- **VirusTotal 확인**: 설정 패널에 API 키를 넣으면 선택 URL(최대 4개, 무료 API 분당 제한 때문)의 탐지 결과 조회.
- **FortiGuard 확인**: 설정 패널에 FortiGuard 프리미엄 API 토큰을 넣으면 선택 URL(최대 10개)의 카테고리 등급(rating) 조회 (`GET https://premiumapi.fortinet.com/v1/rate?url=...`).
- **설정 패널**: FortiProxy host/API 토큰/리소스 이름, VirusTotal API 키, FortiGuard API 토큰을 화면에서 직접 입력·저장 가능 (SQLite에 저장되며 `.env`보다 우선 적용됨). cron 배치(`main.py`)만 쓸 경우엔 `.env`만 채워도 충분.
- **수집 주기(cron) 설정**: 설정 패널에서 주기(프리셋 또는 직접 cron 표현식)를 선택해 저장하면, `python-crontab`으로 **현재 로그인 사용자의 시스템 crontab에 즉시 반영**됨 (`crontab -l`로 확인 가능, 주석 `# forti-threat-feed-collect`로 식별). 별도 재시작 없이 다음 분 단위 cron 체크부터 새 주기로 동작. "사용 안함"을 누르면 해당 항목만 제거됨(다른 crontab 항목에는 영향 없음).

## cron 배치 테스트 (실제 push 없이 확인)
```bash
python main.py --dry-run
```
로그(`sync.log`)에서 수집 건수, 신규 건수, push 대상 목록을 확인하세요.

## cron 배치 실제 실행
```bash
python main.py
```

## cron 등록
웹 대시보드 설정 패널에서 주기를 선택해 저장하면 자동으로 등록됩니다 (위 "수집 주기(cron) 설정" 참고). 수동으로 등록하고 싶다면:
```bash
crontab -e
```
```
0 * * * * cd /Users/jay/forti-threat-feed && ./venv/bin/python main.py >> cron.log 2>&1
```
(Ubuntu 등 다른 서버에 배포할 경우 `venv`/프로젝트 경로가 해당 서버 기준 절대경로와 일치해야 합니다. 웹 UI로 등록하면 이 경로를 자동으로 서버 자신의 `webapp.py` 위치 기준으로 채워줍니다.)

## 동작 방식 요약
1. `feeds.py`가 URLhaus / OpenPhish에서 URL을 받아 정규화(스킴 제거)한 값과 원본(raw) 값을 함께 수집.
2. `store.py`가 SQLite(`urls.db`)에 `INSERT OR IGNORE`로 저장 — 이미 본 URL은 자동으로 스킵됨 (기본 중복 제거).
3. cron(`main.py`)은 아직 반영 안 된(`pushed=0`) URL을 자동으로, 웹 대시보드는 사용자가 체크박스로 고른 URL만 `forti.py`가 REST API로 한 번에 POST.
4. 성공한 URL만 `pushed=1`로 표시. 실패한 URL은 cron 기준 다음 실행 때 자동 재시도.
5. VT 조회 결과(`vt_status`, `vt_malicious`, `vt_total`)도 같은 DB에 캐시되어 대시보드에 배지로 표시됨.

## 알아둘 점
- FortiProxy External Resource 항목 수에도 모델별 제한이 있을 수 있습니다. `MAX_PUSH_PER_RUN`(cron)으로 회당 반영량을 조절하세요.
- URLhaus/OpenPhish는 요청 빈도 제한이 있으니 cron 주기를 너무 짧게(예: 분 단위) 잡지 마세요. URLhaus는 5분, OpenPhish 무료 피드는 12시간마다만 갱신되므로 시간 단위 cron이면 충분합니다.
- FortiProxy의 push 응답은 배치 단위 성공/실패만 알려주고 entry별 결과는 제공하지 않습니다 — 실패 시 배치 전체가 재시도 대상(`pushed=0` 유지)이 됩니다.
- VirusTotal 무료 API는 분당 4건 / 일 500건 제한이 있어 `MAX_VT_BATCH=4`, 호출 간 15초 간격으로 제한 처리되어 있습니다.
