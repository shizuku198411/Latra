#!/usr/bin/env python3
"""Minimal SDK Store-compatible server for Latra end-to-end tests."""

from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


DEFAULT_SDK_NAME = "fixture-sdk"
DEFAULT_CHANNEL = "latest/stable"
DEFAULT_REVISION = 42
DEFAULT_PACKAGE_ID = "latra-e2e-fixture"
MAX_REQUEST_BYTES = 1 << 20


class Artifact:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.size = len(content)
        self.digest = hashlib.sha3_384(content).hexdigest()


class RequestStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._resolve_requests = 0
        self._download_requests = 0

    def record_resolve(self) -> None:
        with self._lock:
            self._resolve_requests += 1

    def record_download(self) -> None:
        with self._lock:
            self._download_requests += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "resolveRequests": self._resolve_requests,
                "downloadRequests": self._download_requests,
            }


class MockStoreServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        artifact: Artifact,
        sdk_name: str,
        channel: str,
        revision: int,
        package_id: str,
    ) -> None:
        super().__init__(address, MockStoreHandler)
        self.artifact = artifact
        self.sdk_name = sdk_name
        self.channel = channel
        self.revision = revision
        self.package_id = package_id
        self.stats = RequestStats()

    @property
    def base_url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def download_path(self) -> str:
        return f"/api/v1/sdks/download/{self.package_id}_{self.revision}.sdk"


class MockStoreHandler(BaseHTTPRequestHandler):
    server: MockStoreServer

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._write_json(200, {"status": "ok"})
            return
        if self.path == "/stats":
            self._write_json(200, self.server.stats.snapshot())
            return
        if self.path == self.server.download_path:
            self.server.stats.record_download()
            content = self.server.artifact.content
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        self._write_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/v2/revisions/resolve":
            self._write_json(404, {"error": "not found"})
            return
        try:
            request = self._read_json()
        except ValueError as error:
            self._write_json(400, {"error": str(error)})
            return
        packages = request.get("packages")
        if not isinstance(packages, list):
            self._write_json(400, {"error": "packages must be an array"})
            return

        self.server.stats.record_resolve()
        results = [self._resolve_package(package) for package in packages]
        self._write_json(200, {"package-results": results})

    def _resolve_package(self, package: Any) -> dict[str, Any]:
        if not isinstance(package, dict):
            return self._resolution_error("", "invalid package request")
        instance_key = package.get("instance-key", "")
        platform = package.get("platform")
        expected_platform = {
            "name": "all",
            "channel": "all",
            "architecture": "all",
        }
        valid = (
            package.get("namespace") == "sdk"
            and package.get("name") == self.server.sdk_name
            and package.get("channel") in {"stable", self.server.channel}
            and platform == expected_platform
        )
        if not valid:
            return self._resolution_error(instance_key, "Revision not found")

        return {
            "instance-key": instance_key,
            "status": "ok",
            "name": self.server.sdk_name,
            "id": self.server.package_id,
            "result": {
                "channel": {"effective-channel": self.server.channel},
                "revision": {
                    "revision": self.server.revision,
                    "download": {
                        "url": self.server.base_url + self.server.download_path,
                        "size": self.server.artifact.size,
                        "sha3-384": self.server.artifact.digest,
                    },
                },
            },
        }

    def _resolution_error(self, instance_key: str, message: str) -> dict[str, Any]:
        return {
            "instance-key": instance_key,
            "status": "error",
            "name": self.server.sdk_name,
            "error": {
                "code": "revision-not-found",
                "message": message,
            },
        }

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("invalid Content-Length") from error
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request body size is invalid")
        try:
            value = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("request body is not valid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("request body must be an object")
        return value

    def _write_json(self, status: int, value: Any) -> None:
        content = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"mock-store: {self.address_string()} - {format % args}", flush=True)


def build_archive(fixture: Path) -> Artifact:
    if not fixture.is_dir():
        raise ValueError(f"SDK fixture directory does not exist: {fixture}")
    paths = sorted(path for path in fixture.rglob("*") if path.is_file())
    if not paths:
        raise ValueError(f"SDK fixture directory is empty: {fixture}")

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:zst") as archive:
        for path in paths:
            if path.is_symlink():
                raise ValueError(f"SDK fixture symlinks are not supported: {path}")
            relative = path.relative_to(fixture).as_posix()
            content = path.read_bytes()
            entry = tarfile.TarInfo(relative)
            entry.size = len(content)
            entry.mode = 0o755 if "/hooks/" in f"/{relative}" else 0o644
            entry.mtime = 0
            entry.uid = 0
            entry.gid = 0
            entry.uname = ""
            entry.gname = ""
            archive.addfile(entry, io.BytesIO(content))
    return Artifact(output.getvalue())


def write_ready_file(path: Path, server: MockStoreServer) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "url": server.base_url,
        "sdkName": server.sdk_name,
        "channel": server.channel,
        "revision": server.revision,
        "size": server.artifact.size,
        "sha3-384": server.artifact.digest,
    }
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def parse_args() -> argparse.Namespace:
    default_fixture = Path(__file__).resolve().parent / "store-sdk"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--fixture", type=Path, default=default_fixture)
    parser.add_argument("--ready-file", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    address = ipaddress.ip_address(args.listen)
    if not address.is_loopback:
        raise SystemExit("mock Store must listen on a loopback address")
    if args.port < 0 or args.port > 65535:
        raise SystemExit("port must be between 0 and 65535")

    artifact = build_archive(args.fixture.resolve())
    server = MockStoreServer(
        (str(address), args.port),
        artifact,
        DEFAULT_SDK_NAME,
        DEFAULT_CHANNEL,
        DEFAULT_REVISION,
        DEFAULT_PACKAGE_ID,
    )
    if args.ready_file is not None:
        write_ready_file(args.ready_file.resolve(), server)
    print(f"mock-store: listening on {server.base_url}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
