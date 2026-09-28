#!/usr/bin/env python3
"""Validate a PocketBook package and publish it after the CI checks pass."""

import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid
import zipfile


ROOT = Path(__file__).resolve().parent
ALLOWED_SERVERS = ("https://git.xloud.ru", "http://gitea:3000")


def release_api():
    server = (os.environ.get("RELEASE_SERVER_URL") or
              os.environ.get("GITHUB_SERVER_URL", "")).rstrip("/")
    if server not in ALLOWED_SERVERS:
        raise ValueError("Unexpected Gitea server URL")
    return server + "/api/v1/repos/gpakoh/WiFiFiles"


def validate_package():
    version = re.search(r'^const version = "([0-9]+\.[0-9]+\.[0-9]+)"$',
                        (ROOT / "server.go").read_text(), re.M).group(1)
    native = re.search(r'^#define WF_VERSION "([^"]+)"$',
                       (ROOT / "native_app.c").read_text(), re.M).group(1)
    if native != version:
        raise ValueError("Go and native versions differ")
    build = ROOT / "build"
    archive = build / f"WiFiFiles_{version}.zip"
    checksum = build / f"WiFiFiles_{version}.sha256"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if checksum.read_text().split() != [digest, archive.name]:
        raise ValueError("Archive checksum or filename is invalid")
    with zipfile.ZipFile(archive) as package:
        files = [item for item in package.infolist() if not item.is_dir()]
        if [item.filename for item in files] != ["applications/WiFiFiles.app"]:
            raise ValueError("Unexpected archive layout")
        if not (files[0].external_attr >> 16) & 0o111:
            raise ValueError("Application is not executable")
        app = package.read(files[0])
    if app != (build / "WiFiFiles.app").read_bytes():
        raise ValueError("Packaged application differs from build output")
    if app[:7] != b"\x7fELF\x01\x01\x01" or struct.unpack_from("<H", app, 18)[0] != 40:
        raise ValueError("Application is not a 32-bit little-endian ARM ELF")
    magic, length, check = struct.unpack("<8sII", app[-16:])
    if magic != b"WFSRV722" or check != (length ^ 0xA55AA55A) or length >= len(app) - 16:
        raise ValueError("Embedded server footer is invalid")
    server = app[-16-length:-16]
    if server != (build / "WiFiFiles.server").read_bytes():
        raise ValueError("Embedded server differs from build output")
    notes = (ROOT / "CHANGELOG.md").read_text().split(f"## {version}\n", 1)[1]
    notes = notes.split("\n## ", 1)[0].strip()
    print(f"Validated WiFiFiles {version}: {archive.name}, SHA-256 {digest}", flush=True)
    return version, [archive, checksum], notes


def publish(version, artifacts, notes):
    api = release_api()
    token = os.environ.get("GITEA_TOKEN", "")
    if not token:
        raise ValueError("GITEA_TOKEN is required")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if head != os.environ.get("GITHUB_SHA"):
        raise ValueError("Checkout does not match the CI commit")
    if os.environ.get("GITHUB_REPOSITORY") != "gpakoh/WiFiFiles":
        raise ValueError("Unexpected CI repository")

    def request(path, method="GET", data=None, content_type="application/json"):
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        req = Request(api + path, data=data, method=method, headers={
            "Authorization": "token " + token,
            "Content-Type": content_type,
            "Accept": "application/json",
        })
        with urlopen(req, timeout=120) as response:
            return json.load(response)

    tag = "v" + version
    try:
        existing = request("/releases/tags/" + tag)
    except HTTPError as error:
        if error.code != 404:
            raise
    else:
        if existing.get("draft"):
            raise ValueError("A draft for this version already exists; review it before retrying")
        print("Release already published; keeping its original files: " + existing["html_url"])
        return

    body = notes + "\n\nУстановка: распакуйте архив в корень внутренней памяти PocketBook; "
    body += "файл попадёт в applications/WiFiFiles.app.\n\n"
    body += "Сборка: Go 1.23.12, ARMv5, CGO=0; целевая система — Linux 3.0.35.\n"
    body += "Тесты CI пройдены. Передача с iPhone/Safari на физическом ридере требует проверки.\n"
    body += "\nКоммит: `" + head + "`.\n"
    release = request("/releases", "POST", {
        "tag_name": tag, "target_commitish": head,
        "name": "WiFiFiles " + version, "body": body,
        "draft": True, "prerelease": False,
    })
    release_path = "/releases/" + str(release["id"])
    for artifact in artifacts:
        boundary = "wififiles-" + uuid.uuid4().hex
        data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; "
                f"filename=\"{artifact.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
        data += artifact.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
        asset = request(release_path + "/assets", "POST", data,
                        "multipart/form-data; boundary=" + boundary)
        if asset["name"] != artifact.name or asset["size"] != artifact.stat().st_size:
            raise ValueError("Uploaded attachment metadata does not match the package")
    expected = {p.name: p.stat().st_size for p in artifacts}
    observed = {a["name"]: a["size"] for a in request(release_path + "/assets")}
    if observed != expected:
        raise ValueError("Release attachments are incomplete; leaving draft unpublished")
    request(release_path, "PATCH", {"draft": False})
    published = request(release_path)
    if published["draft"] or published["prerelease"] or published["tag_name"] != tag:
        raise ValueError("Release publication could not be verified")
    print("Published " + published["html_url"], flush=True)
    for asset in published["assets"]:
        print(f"Asset: {asset['name']} ({asset['size']} bytes) {asset['browser_download_url']}", flush=True)


def ci_publication_requested():
    context = {name: os.environ.get(name, "") for name in
               ("GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SERVER_URL")}
    print("CI release context: " + json.dumps(context), flush=True)
    if not context["GITHUB_EVENT_NAME"] or not context["GITHUB_REF"]:
        raise ValueError("CI event and ref are required for publication")
    if (context["GITHUB_EVENT_NAME"] != "push" or
            context["GITHUB_REF"] not in ("refs/heads/main", "main") or
            context["GITHUB_SERVER_URL"].rstrip("/") == "https://github.com"):
        print("Package build verified; publication is only enabled for Gitea main pushes.", flush=True)
        return False
    return True


def main():
    os.chdir(ROOT)
    if sys.argv[1:] not in ([], ["--validate-only"], ["--ci"]):
        raise ValueError("Usage: publish_release.py [--validate-only|--ci]")
    if sys.argv[1:] == ["--ci"] and not ci_publication_requested():
        return
    version, artifacts, notes = validate_package()
    if sys.argv[1:] == ["--validate-only"]:
        return
    publish(version, artifacts, notes)


if __name__ == "__main__":
    main()
