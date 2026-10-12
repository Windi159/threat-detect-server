"""환경 변수로 받는 서버 설정."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # 학습된 분류 모델 폴더(train.py 출력). 비우면 개발용 KeywordClassifier를 쓴다.
    model_dir: str | None
    # 관제 서버의 알람 수신 주소
    control_url: str
    # 욕설·위협 확신도가 이 값 이상일 때만 알람을 보낸다
    threshold: float
    # 관제 서버 요청 타임아웃(초)
    alert_timeout: float
    # 기기 ID → 사용자 이름 DB 파일
    user_db_path: str


def load_settings() -> Settings:
    return Settings(
        model_dir=os.getenv("THREAT_MODEL_DIR") or None,
        control_url=os.getenv("CONTROL_SERVER_URL", "http://127.0.0.1:9000/api/alerts"),
        threshold=float(os.getenv("THREAT_THRESHOLD", "0.7")),
        alert_timeout=float(os.getenv("ALERT_TIMEOUT", "3.0")),
        user_db_path=os.getenv("USER_DB_PATH", "data/users.db"),
    )
