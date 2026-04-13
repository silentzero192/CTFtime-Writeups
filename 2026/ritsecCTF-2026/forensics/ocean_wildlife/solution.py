#!/usr/bin/env python3
import argparse
import re
import sqlite3
import sys
from pathlib import Path


FLAG_RE = re.compile(rb"RS\{[^}\r\n]+\}")


def search_blob(data):
    match = FLAG_RE.search(data)
    return match.group().decode() if match else None


def find_flag_in_rosout(db_path):
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "select id from topics where name = '/rosout' limit 1"
        ).fetchone()
        if not row:
            return None

        topic_id = row[0]
        for (data,) in conn.execute(
            "select data from messages where topic_id = ? order by timestamp",
            (topic_id,),
        ):
            flag = search_blob(data)
            if flag:
                return flag
    finally:
        conn.close()
    return None


def find_flag_anywhere(db_path):
    return search_blob(db_path.read_bytes())


def main():
    parser = argparse.ArgumentParser(
        description="Extract the flag from the Ocean Wildlife ROS bag."
    )
    parser.add_argument(
        "--db",
        default="mystery_message_0.db3",
        help="path to the rosbag sqlite database",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"[-] Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    flag = find_flag_in_rosout(db_path)
    if not flag:
        flag = find_flag_anywhere(db_path)

    if not flag:
        print("[-] Flag not found", file=sys.stderr)
        sys.exit(1)

    print(flag)


if __name__ == "__main__":
    main()
