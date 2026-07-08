"""오케스트레이션: 피드 수집 -> 중복 제거 -> 저장. cron에서 이 파일을 실행.

FortiProxy push는 여기서 자동으로 하지 않는다. 대시보드에서 체크박스로 선택한
URL만 수동으로 push하는 것이 유일한 push 경로다.
"""
import logging
import os
import sys

from dotenv import load_dotenv

import feeds
import store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.environ.get("LOG_PATH", "sync.log")),
    ],
)
logger = logging.getLogger(__name__)


def main():
    load_dotenv()

    db_path = os.environ.get("DB_PATH", "urls.db")

    logger.info("피드 수집 시작")
    collected = feeds.collect_all()
    logger.info("수집 완료: %d건 (중복 포함)", len(collected))

    with store.connect(db_path) as conn:
        new_count = store.add_new_urls(conn, collected)
        logger.info("신규 URL %d건 저장 (push는 대시보드에서 수동으로)", new_count)


if __name__ == "__main__":
    main()
