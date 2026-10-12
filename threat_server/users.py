"""기기 ID → 사용자 이름 저장소 (SQLite).

앱은 기기 고유 ID(ANDROID_ID)로 사용자를 구분한다. 첫 설치 때 입력받은 이름을 여기에
등록해 두면, 앱을 재설치해도 같은 기기 ID로 이름을 다시 받아갈 수 있다.
"""
import sqlite3
import threading
from datetime import datetime
from pathlib import Path


class UserStore:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # FastAPI 동기 엔드포인트는 스레드풀에서 돌기 때문에 연결을 공유하고 락으로 직렬화한다
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                " device_id TEXT PRIMARY KEY,"
                " name TEXT NOT NULL,"
                " updated_at TEXT NOT NULL)")

    def get_name(self, device_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT name FROM users WHERE device_id = ?", (device_id,)).fetchone()
        return row[0] if row else None

    def upsert(self, device_id: str, name: str) -> None:
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO users (device_id, name, updated_at) VALUES (?, ?, ?)"
                " ON CONFLICT(device_id) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at",
                (device_id, name, now))
