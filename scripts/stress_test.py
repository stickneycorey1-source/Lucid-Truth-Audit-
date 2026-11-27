    def _init_sqlite(self) -> None:
        raw_path = self.db_url
        if raw_path.startswith("sqlite:///"):
            raw_path = raw_path[len("sqlite:///"):]
        if raw_path != ":memory:":
            parent = Path(raw_path).parent
            if str(parent) not in ("", "."):
                os.makedirs(parent, exist_ok=True)
        self._sqlite_conn = sqlite3.connect(
            raw_path, check_same_thread=False, timeout=5.0
        )
        if raw_path != ":memory:":
            self._sqlite_conn.execute("PRAGMA journal_mode=WAL;")
            self._sqlite_conn.execute("PRAGMA synchronous=NORMAL;")
            self._sqlite_conn.execute("PRAGMA busy_timeout=5000;")