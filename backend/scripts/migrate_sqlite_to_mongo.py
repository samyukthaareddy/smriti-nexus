from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

from dotenv import load_dotenv

backend_dir = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(backend_dir))

from app.storage import create_database  # noqa: E402


def main() -> int:
    load_dotenv(backend_dir / ".env")
    parser = argparse.ArgumentParser(
        description="Copy existing Smriti Nexus SQLite records to one MongoDB organization."
    )
    parser.add_argument(
        "--sqlite",
        default=str(backend_dir / "data" / "smriti_nexus.db"),
        help="Path to the existing SQLite file (read-only).",
    )
    parser.add_argument(
        "--organization-id",
        required=True,
        help="Target organization_id from an authorized MongoDB workspace.",
    )
    args = parser.parse_args()
    if not os.getenv("MONGODB_URI"):
        parser.error("Set MONGODB_URI in the backend environment before migrating.")
    sqlite_path = Path(args.sqlite).resolve()
    if not sqlite_path.is_file():
        parser.error(f"SQLite source does not exist: {sqlite_path}")

    database = create_database()
    organization = database.organizations.find_one(
        {"organization_id": args.organization_id}, {"_id": 1}
    )
    if not organization:
        parser.error("The target organization_id does not exist.")

    connection = sqlite3.connect(f"file:{sqlite_path.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    migrated = 0
    try:
        rows = connection.execute("SELECT * FROM memories").fetchall()
        for row in rows:
            source = dict(row)
            record = {
                **source,
                "id": str(source["id"]),
                "organization_id": args.organization_id,
                "sensitivity": "INTERNAL",
                "tags": [],
            }
            database.memories.update_one(
                {"organization_id": args.organization_id, "id": record["id"]},
                {"$setOnInsert": record},
                upsert=True,
            )
            migrated += 1
        if "corrections" in {
            item["name"]
            for item in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }:
            for row in connection.execute("SELECT * FROM corrections"):
                source = dict(row)
                source["id"] = str(source["id"])
                source["organization_id"] = args.organization_id
                database.corrections.update_one(
                    {"organization_id": args.organization_id, "id": source["id"]},
                    {"$setOnInsert": source},
                    upsert=True,
                )
    finally:
        connection.close()
    print(
        f"Migration complete: processed {migrated} memories for the selected organization. "
        "The SQLite source was not modified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
