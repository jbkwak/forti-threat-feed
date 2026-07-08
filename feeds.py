"""무료 악성 URL 피드 수집기.

각 fetch_* 함수는 (url, source, raw_url) 튜플의 이터러블을 반환한다.
- url: 스킴(http://, https://)을 제거해 FortiProxy urlfilter 형식에 맞춘 정규화 값
- raw_url: 피드 원본 그대로의 URL (VirusTotal 조회 등 원본이 필요한 용도)
"""
import logging
import re

import requests

logger = logging.getLogger(__name__)

USER_AGENT = "forti-threat-feed-sync/1.0"
TIMEOUT = 30

_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


def normalize_url(raw: str) -> str:
    """스킴 제거 + 앞뒤 공백/슬래시 정리."""
    url = raw.strip()
    url = _SCHEME_RE.sub("", url)
    return url.rstrip("/")


def fetch_urlhaus():
    """abuse.ch URLhaus - 최근 활성 악성 URL 전체 텍스트 피드."""
    src = "urlhaus"
    resp = requests.get(
        "https://urlhaus.abuse.ch/downloads/text/",
        headers={"User-Agent": USER_AGENT},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    count = 0
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        yield normalize_url(line), src, line
        count += 1
    logger.info("urlhaus: %d URL 수신", count)


def fetch_openphish():
    """OpenPhish 무료(지연) 피드."""
    src = "openphish"
    resp = requests.get(
        "https://openphish.com/feed.txt",
        headers={"User-Agent": USER_AGENT},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    count = 0
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        yield normalize_url(line), src, line
        count += 1
    logger.info("openphish: %d URL 수신", count)


FEEDS = [fetch_urlhaus, fetch_openphish]


def collect_all():
    """등록된 모든 피드를 수집해 (url, source, raw_url) 리스트 반환. 개별 피드 실패는 격리."""
    results = []
    for fetch_fn in FEEDS:
        try:
            results.extend(fetch_fn())
        except requests.RequestException as e:
            logger.error("%s 수집 실패: %s", fetch_fn.__name__, e)
    return results
