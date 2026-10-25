"""Preservação local com criação exclusiva e proteção contra links simbólicos."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import stat
from datetime import datetime, timezone
from pathlib import Path

from . import VERSION

MAX_FILE = 20 * 1024 * 1024
PUBLIC_COMPONENTS = {"public_html", "dropbox", "onedrive", "google drive", "nextcloud"}


def default_root() -> Path:
    return Path("/root/backup/php-security-auditor") if os.geteuid() == 0 else Path.home() / "backup/php-security-auditor"


def _safe_root(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Diretório de backup deve ser absoluto e sem '..'.")
    resolved = str(path)
    if any(resolved == prefix or resolved.startswith(prefix + "/") for prefix in
           ("/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html", "/tmp", "/var/tmp")):
        raise ValueError("Diretório de backup não pode ficar sob webroot ou área temporária.")
    _check_public_tree(path)


def _check_public_tree(path: Path) -> None:
    """Recusa árvores Git e diretórios públicos/sincronizados reconhecíveis."""
    if any(part.lower() in PUBLIC_COMPONENTS for part in path.parts):
        raise ValueError("Destino está em diretório público ou sincronizado reconhecido.")
    for ancestor in (path, *path.parents):
        if os.path.lexists(ancestor / ".git"):
            raise ValueError("Destino está dentro de uma árvore Git; escolha local privado externo.")


def _secure_mkdirs(path: Path) -> None:
    _safe_root(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        _trusted_directory(os.fstat(fd))
        for component in path.parts[1:]:
            try:
                os.mkdir(component, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                _trusted_directory(os.fstat(next_fd))
            except BaseException:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or (info.st_mode & 0o077):
            raise PermissionError("Diretório final de backup deve pertencer ao usuário atual e ter modo 0700.")
    finally:
        os.close(fd)


def _trusted_directory(info: os.stat_result) -> None:
    uid = os.geteuid()
    if info.st_uid not in ((0,) if uid == 0 else (0, uid)) or (info.st_mode & 0o022):
        raise PermissionError("Ancestral do diretório é controlável por outro usuário.")


def _open_trusted_existing(path: Path) -> int:
    _safe_root(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        _trusted_directory(os.fstat(fd))
        for component in path.parts[1:]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                _trusted_directory(os.fstat(next_fd))
            except BaseException:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or (info.st_mode & 0o077):
            raise PermissionError("Sessão deve pertencer ao usuário atual e ter modo 0700.")
        result, fd = fd, -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _write_exclusive(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


class BackupSession:
    def __init__(self, root: Path | None = None, expected_bytes: int = 0):
        self.root = root or default_root()
        _secure_mkdirs(self.root)
        free = shutil.disk_usage(self.root).free
        if free < max(10 * 1024 * 1024, expected_bytes * 2):
            raise OSError("Espaço livre insuficiente para backup e manifestos.")
        host = "".join(c if c.isalnum() or c == "-" else "-" for c in socket.gethostname())[:48] or "host"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.path = None
        for suffix in range(1000):
            name = f"{host}-{stamp}-{suffix:03d}"
            try:
                self.path = self.root / name
                self.path.mkdir(mode=0o700)
                break
            except FileExistsError:
                continue
        if self.path is None:
            raise FileExistsError("Não foi possível criar pasta exclusiva.")
        self.entries: list[dict] = []
        for folder in ("configuracoes", "evidencias", "manifestos", "relatorios", "transacao", "recuperacao"):
            (self.path / folder).mkdir(mode=0o700)

    def preserve(self, source: Path, category: str = "evidencias", expected: dict[str, int] | None = None) -> dict:
        if category not in ("evidencias", "configuracoes"):
            raise ValueError("Categoria inválida")
        if len(self.entries) >= 100:
            raise ValueError("Limite de 100 arquivos preservados")
        if expected is not None and (not isinstance(expected, dict) or any(
                not isinstance(expected.get(key), int) for key in ("dev", "ino", "size", "mtime_ns"))):
            raise ValueError("Metadados esperados da evidência inválidos")
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise ValueError("Fonte não regular ou maior que 20 MiB")
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError("Fonte mudou durante a abertura")
            if expected is not None and any(getattr(opened, "st_" + key) != expected[key]
                                            for key in ("dev", "ino", "size", "mtime_ns")):
                raise ValueError("Fonte difere do arquivo examinado; preserve a evidência atual separadamente")
            target = self.path / category / f"{len(self.entries):04d}-{source.name[:80]}"
            digest = hashlib.sha256()
            out_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(out_fd, "wb") as out:
                    total = 0
                    while True:
                        chunk = os.read(fd, min(1024 * 1024, MAX_FILE + 1 - total))
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_FILE:
                            raise ValueError("Fonte cresceu além do limite")
                        out.write(chunk)
                        digest.update(chunk)
                    out.flush()
                    os.fsync(out.fileno())
            except BaseException:
                target.unlink(missing_ok=True)
                raise
            after = os.fstat(fd)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                    opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
                target.unlink(missing_ok=True)
                raise ValueError("Fonte mudou durante a cópia")
            copied = hashlib.sha256(target.read_bytes()).hexdigest()
            if copied != digest.hexdigest():
                target.unlink(missing_ok=True)
                raise ValueError("Falha de integridade da cópia")
            entry = {"source": str(source), "copy": str(target.relative_to(self.path)),
                     "sha256": copied, "size": total, "mode": oct(opened.st_mode & 0o7777),
                     "uid": opened.st_uid, "gid": opened.st_gid,
                     "mtime_ns": opened.st_mtime_ns, "sensitive": category == "configuracoes" or
                     any(word in source.name.lower() for word in ("auth", "secret", "key", "password"))}
            self.entries.append(entry)
            return entry
        finally:
            os.close(fd)

    def finalize(self, os_info: dict, operations: list[str]) -> Path:
        manifest = {"tool_version": VERSION, "hostname": socket.gethostname(),
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "original_user": os.environ.get("SUDO_USER") or os.environ.get("USER") or "desconhecido",
                    "effective_uid": os.geteuid(), "os": os_info, "operations": operations,
                    "files": self.entries}
        target = self.path / "manifestos/manifesto.json"
        _write_exclusive(target, json.dumps(manifest, ensure_ascii=False, indent=2).encode())
        return target


def validate_manifest(session_path: Path) -> list[str]:
    session_fd = _open_trusted_existing(session_path)
    try:
        manifest_dir = os.open("manifestos", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=session_fd)
        try:
            manifest_fd = os.open("manifesto.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=manifest_dir)
            try:
                info = os.fstat(manifest_fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                    raise ValueError("Manifesto inválido ou maior que 1 MiB")
                data = bytearray()
                while len(data) <= 1024 * 1024:
                    chunk = os.read(manifest_fd, min(65536, 1024 * 1024 + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                if len(data) > 1024 * 1024:
                    raise ValueError("Manifesto maior que 1 MiB")
                manifest = json.loads(data)
            finally:
                os.close(manifest_fd)
        finally:
            os.close(manifest_dir)
        if not isinstance(manifest, dict):
            raise ValueError("Manifesto com formato inválido")
        entries = manifest.get("files")
        if not isinstance(entries, list) or len(entries) > 100:
            raise ValueError("Manifesto excede 100 arquivos ou tem formato inválido")
        failures = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("copy"), str):
                failures.append("Entrada inválida no manifesto")
                continue
            relative = Path(entry["copy"])
            if (relative.is_absolute() or len(relative.parts) != 2 or
                    relative.parts[0] not in ("evidencias", "configuracoes") or ".." in relative.parts):
                failures.append("Caminho inválido no manifesto")
                continue
            try:
                folder_fd = os.open(relative.parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=session_fd)
                try:
                    file_fd = os.open(relative.parts[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder_fd)
                    try:
                        info = os.fstat(file_fd)
                        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE or info.st_size != entry.get("size"):
                            raise ValueError("Cópia inválida, grande demais ou com tamanho diferente")
                        digest = hashlib.sha256()
                        remaining = info.st_size
                        while remaining:
                            chunk = os.read(file_fd, min(1024 * 1024, remaining))
                            if not chunk:
                                raise ValueError("Cópia truncada")
                            digest.update(chunk)
                            remaining -= len(chunk)
                        if digest.hexdigest() != entry.get("sha256"):
                            raise ValueError("hash diferente")
                    finally:
                        os.close(file_fd)
                finally:
                    os.close(folder_fd)
            except (OSError, ValueError) as exc:
                failures.append(f"{relative}: {exc}")
        return failures
    finally:
        os.close(session_fd)
