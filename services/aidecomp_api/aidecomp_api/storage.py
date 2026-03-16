from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import Annotation, Bookmark, Program, ProjectInfo, ProjectState, Rename, SampleRecord, UIState


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SessionStore:
    project_id: str
    sample_id: str
    program: Program


class SQLiteRepository:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS samples (
                    sample_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    location TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(project_id)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    sample_id TEXT NOT NULL,
                    program_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(project_id)
                );
                CREATE TABLE IF NOT EXISTS annotations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    text TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS bookmarks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS renames (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    new_name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ui_state (
                    project_id TEXT PRIMARY KEY,
                    current_function TEXT NOT NULL,
                    current_block TEXT NOT NULL,
                    beginner_mode INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    def ensure_project(self, project_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO projects(project_id, name, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(project_id) DO NOTHING
                """,
                (project_id, project_id, _now()),
            )

    def create_project(self, project_id: str, name: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO projects(project_id, name, created_at) VALUES (?, ?, COALESCE((SELECT created_at FROM projects WHERE project_id=?), ?))",
                (project_id, name, project_id, _now()),
            )

    def list_projects(self) -> list[ProjectInfo]:
        with self._connect() as conn:
            rows = conn.execute("SELECT project_id, name, created_at FROM projects ORDER BY created_at DESC").fetchall()
        return [ProjectInfo(project_id=row["project_id"], name=row["name"], created_at=row["created_at"]) for row in rows]

    def delete_project(self, project_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM annotations WHERE project_id=?", (project_id,))
            conn.execute("DELETE FROM bookmarks WHERE project_id=?", (project_id,))
            conn.execute("DELETE FROM renames WHERE project_id=?", (project_id,))
            conn.execute("DELETE FROM sessions WHERE project_id=?", (project_id,))
            conn.execute("DELETE FROM samples WHERE project_id=?", (project_id,))
            conn.execute("DELETE FROM ui_state WHERE project_id=?", (project_id,))
            conn.execute("DELETE FROM projects WHERE project_id=?", (project_id,))

    def add_sample(self, sample: SampleRecord) -> None:
        self.ensure_project(sample.project_id)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO samples(sample_id, project_id, source_type, location, created_at) VALUES (?, ?, ?, ?, ?)",
                (sample.sample_id, sample.project_id, sample.source_type, sample.location, sample.created_at),
            )

    def list_samples(self, project_id: str) -> list[SampleRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT sample_id, project_id, source_type, location, created_at FROM samples WHERE project_id=? ORDER BY created_at DESC",
                (project_id,),
            ).fetchall()
        return [
            SampleRecord(
                sample_id=row["sample_id"],
                project_id=row["project_id"],
                source_type=row["source_type"],
                location=row["location"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def save_session(self, session_id: str, project_id: str, sample_id: str, program: Program) -> None:
        self.ensure_project(project_id)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions(session_id, project_id, sample_id, program_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (session_id, project_id, sample_id, json.dumps(program.model_dump(), ensure_ascii=False), _now()),
            )

    def get_session(self, session_id: str) -> SessionStore:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT project_id, sample_id, program_json FROM sessions WHERE session_id=?",
                (session_id,),
            ).fetchone()
        if row is None:
            raise KeyError(session_id)
        program = Program.model_validate(json.loads(row["program_json"]))
        return SessionStore(project_id=row["project_id"], sample_id=row["sample_id"], program=program)

    def add_annotation(self, project_id: str, annotation: Annotation) -> None:
        self.ensure_project(project_id)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO annotations(project_id, target_type, target_id, text, created_at) VALUES (?, ?, ?, ?, ?)",
                (project_id, annotation.target_type, annotation.target_id, annotation.text, _now()),
            )

    def add_bookmark(self, project_id: str, bookmark: Bookmark) -> None:
        self.ensure_project(project_id)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO bookmarks(project_id, target_type, target_id, note, created_at) VALUES (?, ?, ?, ?, ?)",
                (project_id, bookmark.target_type, bookmark.target_id, bookmark.note, _now()),
            )

    def add_rename(self, project_id: str, rename: Rename) -> None:
        self.ensure_project(project_id)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO renames(project_id, target_type, target_id, new_name, created_at) VALUES (?, ?, ?, ?, ?)",
                (project_id, rename.target_type, rename.target_id, rename.new_name, _now()),
            )

    def get_project_state(self, project_id: str) -> ProjectState:
        self.ensure_project(project_id)
        with self._connect() as conn:
            ann_rows = conn.execute(
                "SELECT target_type, target_id, text FROM annotations WHERE project_id=? ORDER BY id",
                (project_id,),
            ).fetchall()
            bm_rows = conn.execute(
                "SELECT target_type, target_id, note FROM bookmarks WHERE project_id=? ORDER BY id",
                (project_id,),
            ).fetchall()
            rn_rows = conn.execute(
                "SELECT target_type, target_id, new_name FROM renames WHERE project_id=? ORDER BY id",
                (project_id,),
            ).fetchall()

        return ProjectState(
            project_id=project_id,
            annotations=[Annotation(target_type=row["target_type"], target_id=row["target_id"], text=row["text"]) for row in ann_rows],
            bookmarks=[Bookmark(target_type=row["target_type"], target_id=row["target_id"], note=row["note"]) for row in bm_rows],
            renames=[Rename(target_type=row["target_type"], target_id=row["target_id"], new_name=row["new_name"]) for row in rn_rows],
        )

    def save_ui_state(self, state: UIState) -> None:
        self.ensure_project(state.project_id)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ui_state(project_id, current_function, current_block, beginner_mode, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                    current_function=excluded.current_function,
                    current_block=excluded.current_block,
                    beginner_mode=excluded.beginner_mode,
                    updated_at=excluded.updated_at
                """,
                (state.project_id, state.current_function, state.current_block, 1 if state.beginner_mode else 0, _now()),
            )

    def get_ui_state(self, project_id: str) -> UIState:
        self.ensure_project(project_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT current_function, current_block, beginner_mode FROM ui_state WHERE project_id=?",
                (project_id,),
            ).fetchone()
        if row is None:
            return UIState(project_id=project_id)
        return UIState(
            project_id=project_id,
            current_function=row["current_function"],
            current_block=row["current_block"],
            beginner_mode=bool(row["beginner_mode"]),
        )
