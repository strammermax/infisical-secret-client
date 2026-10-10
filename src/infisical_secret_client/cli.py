from __future__ import annotations

import argparse
import os
import subprocess
import sys

from .client import InfisicalClient, InfisicalConfig, InfisicalError


def _client() -> InfisicalClient:
    return InfisicalClient(InfisicalConfig.from_env())


def _docker_login(client: InfisicalClient, registry: str, *, app_path: str | None,
                  shared_path: str | None, environment: str | None) -> int:
    secrets = client.load_bundle(app_path=app_path, shared_path=shared_path,
                                 environment=environment)
    username = secrets.get("GHCR_USERNAME")
    token = secrets.get("GHCR_READ_TOKEN")
    if not username or not token:
        raise InfisicalError("GHCR_USERNAME of GHCR_READ_TOKEN ontbreekt")
    result = subprocess.run(
        ["docker", "login", registry, "--username", username, "--password-stdin"],
        input=token, text=True,
    )
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lees secrets veilig uit een self-hosted Infisical")
    parser.add_argument("--path", help="overschrijf INFISICAL_SECRET_PATH")
    parser.add_argument("--environment", help="overschrijf INFISICAL_ENVIRONMENT")
    parser.add_argument("--shared-path", help="overschrijf INFISICAL_SHARED_PATH; leeg schakelt shared uit")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="toon alleen namen, nooit waarden")
    get = sub.add_parser("get", help="schrijf één secretwaarde naar stdout")
    get.add_argument("name")
    run = sub.add_parser("run", help="start een proces met secrets uitsluitend in zijn environment")
    run.add_argument("argv", nargs=argparse.REMAINDER)
    login = sub.add_parser("docker-login", help="login bij een registry met secrets uit Infisical")
    login.add_argument("--registry", default="ghcr.io")
    put = sub.add_parser("set", help="maak of wijzig één secret; waarde via stdin")
    put.add_argument("name")
    delete = sub.add_parser("delete", help="verwijder één secret")
    delete.add_argument("name")
    folder = sub.add_parser("folder-ensure", help="maak een map (en bovenliggende) aan")
    folder.add_argument("folder")
    ident = sub.add_parser("identity-ensure",
                           help="app-identiteit met leesrecht op mappen; schrijft bootstrap-env naar stdout (admin)")
    ident.add_argument("name")
    ident.add_argument("--read", action="append", required=True, help="map met leesrecht (herhaalbaar)")
    ident.add_argument("--write", action="append", default=[], help="map met schrijfrecht (herhaalbaar)")
    parser.add_argument("--admin", action="store_true",
                        help="gebruik INFISICAL_ADMIN_CLIENT_ID/SECRET (voor set/delete/folder/identity)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        admin = args.admin or args.command == "identity-ensure"
        client = InfisicalClient(InfisicalConfig.from_env(admin=admin))
        if args.command == "set":
            value = sys.stdin.read()
            if value.endswith("\n"):
                value = value[:-1]
            print(client.set_secret(args.name, value, secret_path=args.path, environment=args.environment))
            return 0
        if args.command == "delete":
            client.delete_secret(args.name, secret_path=args.path, environment=args.environment)
            return 0
        if args.command == "folder-ensure":
            client.ensure_folder(args.folder, environment=args.environment)
            return 0
        if args.command == "identity-ensure":
            identity = client.ensure_app_identity(args.name, read_paths=args.read, write_paths=args.write,
                                                  environment=args.environment)
            sys.stdout.write(client.bootstrap_env(identity, secret_path=args.read[-1],
                                                  shared_path=",".join(args.read[:-1]) or None))
            return 0
        kwargs = {"secret_path": args.path, "environment": args.environment}
        shared_path = args.shared_path if args.shared_path is not None else client.config.shared_path
        if args.command == "list":
            for name in sorted(client.load_bundle(app_path=args.path, shared_path=shared_path,
                                                   environment=args.environment)):
                print(name)
            return 0
        if args.command == "get":
            secrets = client.load_bundle(app_path=args.path, shared_path=shared_path,
                                         environment=args.environment)
            if args.name not in secrets:
                raise InfisicalError(f"secret niet gevonden: {args.name}")
            print(secrets[args.name])
            return 0
        if args.command == "docker-login":
            return _docker_login(client, args.registry, app_path=args.path,
                                 shared_path=shared_path, environment=args.environment)
        if not args.argv:
            raise InfisicalError("run vereist een commando na --")
        command = args.argv[1:] if args.argv[0] == "--" else args.argv
        environment = os.environ.copy()
        environment.update(client.load_bundle(app_path=args.path, shared_path=shared_path,
                                               environment=args.environment))
        return subprocess.run(command, env=environment).returncode
    except InfisicalError as exc:
        print(f"fout: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
