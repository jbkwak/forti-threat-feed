"""시스템 crontab에 URL 수집(main.py) 실행 주기를 등록/해제.

python-crontab으로 현재 로그인 사용자의 crontab을 직접 수정한다. 저장 즉시
`crontab -l`에 반영되며, cron 데몬이 다음 분 단위 체크에서 그대로 인식한다.
Ubuntu 등 리눅스 배포 환경 기준으로 설계됨.
"""
import os

from crontab import CronTab

COMMENT = "forti-threat-feed-collect"


def _command(base_dir: str) -> str:
    python = os.path.join(base_dir, "venv", "bin", "python")
    main = os.path.join(base_dir, "main.py")
    log = os.path.join(base_dir, "cron.log")
    return f'cd "{base_dir}" && "{python}" "{main}" >> "{log}" 2>&1'


def get_schedule():
    cron = CronTab(user=True)
    jobs = list(cron.find_comment(COMMENT))
    if not jobs:
        return None
    job = jobs[0]
    return {
        "cron_expr": str(job.slices),
        "command": str(job.command),
        "enabled": job.is_enabled(),
    }


def set_schedule(base_dir: str, cron_expr: str) -> dict:
    cron = CronTab(user=True)
    cron.remove_all(comment=COMMENT)
    job = cron.new(command=_command(base_dir), comment=COMMENT)
    job.setall(cron_expr)
    if not job.is_valid():
        cron.remove(job)
        raise ValueError(f"유효하지 않은 cron 표현식입니다: {cron_expr}")
    cron.write()
    return get_schedule()


def clear_schedule():
    cron = CronTab(user=True)
    cron.remove_all(comment=COMMENT)
    cron.write()
