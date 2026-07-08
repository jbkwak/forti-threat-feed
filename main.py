"""오케스트레이션: 피드 수집 -> 중복 제거 -> FortiProxy Push. cron에서 이 파일을 실행."""
import argparse
import logging
import os
import sys

from dotenv import load_dotenv

import feeds
import store
from forti import FortiProxyClient

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

    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="FortiProxy에 실제로 push하지 않고 로그만 출력")
    args = parser.parse_args()

    db_path = os.environ.get("DB_PATH", "urls.db")
    max_push = int(os.environ.get("MAX_PUSH_PER_RUN", "500"))

    logger.info("피드 수집 시작")
    collected = feeds.collect_all()
    logger.info("수집 완료: %d건 (중복 포함)", len(collected))

    with store.connect(db_path) as conn:
        new_count = store.add_new_urls(conn, collected)
        logger.info("신규 URL %d건 저장", new_count)

        to_push = store.get_unpushed_urls(conn, limit=max_push)
        logger.info("이번 실행에서 push 대상: %d건", len(to_push))

        if not to_push:
            logger.info("push할 신규 URL 없음. 종료")
            return

        if args.dry_run:
            logger.info("[dry-run] push 생략. 대상 목록 일부: %s", to_push[:10])
            return

        forti = store.get_forti_config(conn)
        missing = [k for k in ("host", "api_key", "resource_name") if not forti[k]]
        if missing:
            logger.error("FortiProxy 설정이 비어 있습니다: %s (.env 또는 웹 설정 패널 확인)", ", ".join(missing))
            return

        client = FortiProxyClient(
            host=forti["host"],
            api_key=forti["api_key"],
            resource_name=forti["resource_name"],
            verify_ssl=forti["verify_ssl"],
        )
        try:
            succeeded, failed = client.push_urls(to_push)
        except Exception as e:
            # 네트워크 오류 등으로 여기서 예외가 나면 이번 실행에서 새로 수집한 URL 저장까지
            # 롤백되므로(commit 전), 반드시 잡아서 로그만 남기고 정상 종료한다.
            logger.error("FortiProxy push 요청 실패: %s", e)
            return

        store.mark_pushed(conn, succeeded)

        logger.info("push 성공 %d건 / 실패 %d건", len(succeeded), len(failed))
        if failed:
            logger.warning("실패 URL은 pushed=0으로 남아 다음 실행에서 재시도됨")


if __name__ == "__main__":
    main()
