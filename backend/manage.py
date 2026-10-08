"""
Skylos — Administrative CLI

Usage (from the backend directory):
    python manage.py create-admin --username alice --email alice@example.com
    python manage.py reset-password alice

The password is read from SKYLOS_ADMIN_PASSWORD if set (for automation),
otherwise it is prompted for interactively and never echoed.
"""

import argparse
import getpass
import os
import sys

from database import SessionLocal, init_db
from bootstrap import BootstrapError, create_initial_admin, reset_password


def _read_password() -> str:
    env_pw = os.getenv("SKYLOS_ADMIN_PASSWORD")
    if env_pw:
        return env_pw
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Confirm password: "):
        raise BootstrapError("Passwords do not match.")
    return pw


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="manage.py", description="Skylos administrative commands")
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create-admin", help="Create the first administrator (only if none exists)")
    p_create.add_argument("--username", required=True)
    p_create.add_argument("--email", required=True)

    p_reset = sub.add_parser("reset-password", help="Reset a user's password")
    p_reset.add_argument("username")

    args = parser.parse_args(argv)
    init_db()
    db = SessionLocal()
    try:
        if args.command == "create-admin":
            create_initial_admin(db, args.username, args.email, _read_password(), source="manage.py create-admin")
            print(f"Administrator {args.username} created.")
        elif args.command == "reset-password":
            reset_password(db, args.username, _read_password(), source="manage.py reset-password")
            print(f"Password for {args.username} reset.")
        return 0
    except BootstrapError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
