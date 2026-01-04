import argparse
from getpass import getpass
from pathlib import Path

from .crypto_utils import new_params
from .vault import (
    vault_exists,
    init_vault,
    add_entry,
    get_entry,
    delete_entry,
    list_services,
    VaultError,
)


def default_root() -> Path:
    # Store vault in a local folder inside the repo by default
    return Path(".") / ".vault"


def cmd_init(args: argparse.Namespace) -> None:
    root = Path(args.path) if args.path else default_root()
    if vault_exists(root):
        print(f"Vault already exists at: {root.resolve()}")
        return

    master1 = getpass("Create master password: ")
    master2 = getpass("Confirm master password: ")
    if master1 != master2:
        print("Passwords do not match.")
        return
    if len(master1) < 10:
        print("Use a longer master password (10+ characters recommended).")
        return

    params = new_params()
    init_vault(root, master1, params.salt, params.iterations)
    print(f"Vault initialized at: {root.resolve()}")


def prompt_master() -> str:
    return getpass("Master password: ")


def cmd_add(args: argparse.Namespace) -> None:
    root = Path(args.path) if args.path else default_root()
    master = prompt_master()

    service = args.service.strip()
    username = args.username.strip()

    pw = args.password
    if not pw:
        pw = getpass("Password to store: ")

    note = args.note or ""
    add_entry(root, master, service, username, pw, note)
    print(f"Saved entry for: {service}")


def cmd_get(args: argparse.Namespace) -> None:
    root = Path(args.path) if args.path else default_root()
    master = prompt_master()

    entry = get_entry(root, master, args.service.strip())
    if not entry:
        print("No entry found.")
        return

    # For demos, printing is fine. In “real life,” you might copy to clipboard instead.
    print(f"Service:  {args.service}")
    print(f"Username: {entry.get('username','')}")
    print(f"Password: {entry.get('password','')}")
    if entry.get("note"):
        print(f"Note:     {entry.get('note','')}")


def cmd_list(args: argparse.Namespace) -> None:
    root = Path(args.path) if args.path else default_root()
    master = prompt_master()

    services = list_services(root, master)
    if not services:
        print("No saved services.")
        return
    for s in services:
        print(s)


def cmd_delete(args: argparse.Namespace) -> None:
    root = Path(args.path) if args.path else default_root()
    master = prompt_master()

    ok = delete_entry(root, master, args.service.strip())
    print("Deleted." if ok else "No entry found.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwman",
        description="Secure Password Manager (local encrypted vault)",
    )
    p.add_argument("--path", help="Vault folder path (defaults to ./.vault)")

    sub = p.add_subparsers(dest="cmd", required=True)

    s_init = sub.add_parser("init", help="Initialize a new vault")
    s_init.set_defaults(func=cmd_init)

    s_add = sub.add_parser("add", help="Add a service credential")
    s_add.add_argument("service")
    s_add.add_argument("username")
    s_add.add_argument("--password", help="Password (if omitted, you will be prompted)")
    s_add.add_argument("--note", help="Optional note")
    s_add.set_defaults(func=cmd_add)

    s_get = sub.add_parser("get", help="Get a service credential")
    s_get.add_argument("service")
    s_get.set_defaults(func=cmd_get)

    s_list = sub.add_parser("list", help="List saved services")
    s_list.set_defaults(func=cmd_list)

    s_del = sub.add_parser("delete", help="Delete a service credential")
    s_del.add_argument("service")
    s_del.set_defaults(func=cmd_delete)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except VaultError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
