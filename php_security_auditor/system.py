"""Fronteira única para subprocessos e informações do hospedeiro."""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path


def _stop_process_group(process: subprocess.Popen[bytes]) -> str | None:
    """Sinaliza o grupo antes de colher o líder, evitando reutilização do PGID."""
    errors = []
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as exc:
        errors.append(f"SIGTERM: {type(exc).__name__}")
    try:
        time.sleep(0.25)
    except KeyboardInterrupt:
        pass  # Conclui o encerramento mesmo após uma segunda interrupção.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        errors.append(f"SIGKILL: {type(exc).__name__}")
    try:
        process.wait(timeout=2)
    except (subprocess.TimeoutExpired, OSError) as exc:
        errors.append(f"processo {process.pid} não foi colhido após SIGKILL: {type(exc).__name__}")
    return "; ".join(errors) or None


class System:
    def run(self, args: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C",
                       "DEBIAN_FRONTEND": "noninteractive", "APT_LISTCHANGES_FRONTEND": "none"}
        try:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=environment, start_new_session=True)
        except OSError as exc:
            return subprocess.CompletedProcess(args, 127, "", type(exc).__name__)
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        show_apt_prompt = args[:1] == ["apt-get"] and "-s" not in args and sys.stdin.isatty()
        selector = None
        deadline = time.monotonic() + max(timeout, 0)
        failure = None
        cleanup_error = None
        interrupted = False
        captured_bytes = 0
        try:
            selector = selectors.DefaultSelector()
            for stream in streams:
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "Tempo limite excedido"
                    break
                if not selector.get_map():
                    time.sleep(min(0.05, remaining))
                    continue
                for key, _ in selector.select(min(0.5, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    accepted = chunk[:max(0, 2 * 1024 * 1024 - captured_bytes)]
                    streams[key.fileobj].extend(accepted)
                    captured_bytes += len(accepted)
                    if show_apt_prompt:
                        visible = accepted.decode("utf-8", "replace")
                        sys.stderr.write("".join(c if c in "\n\t" or (ord(c) >= 32 and not 127 <= ord(c) < 160) else f"\\x{ord(c):02x}"
                                                 for c in visible))
                        sys.stderr.flush()
                    if len(accepted) < len(chunk):
                        failure = "Saída excedeu 2 MiB"
                        break
                if failure:
                    break
        except BaseException:
            failure = "Execução interrompida"
            interrupted = True
            raise
        finally:
            try:
                if failure:
                    cleanup_error = _stop_process_group(process)
                    if interrupted and cleanup_error:
                        sys.stderr.write("Falha no encerramento do subprocesso: " + cleanup_error + "\n")
            finally:
                try:
                    if selector is not None:
                        selector.close()
                finally:
                    for stream in streams:
                        stream.close()
        output = list(streams.values())
        return subprocess.CompletedProcess(args, 124 if failure else process.returncode,
                                           output[0].decode("utf-8", "replace"),
                                           (failure + ("; " + cleanup_error if cleanup_error else ""))
                                           if failure else output[1].decode("utf-8", "replace"))

    def read(self, path: str, limit: int = 65536) -> str:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")

    def exists(self, path: str) -> bool:
        return Path(path).exists()


def os_release(system: System) -> dict[str, str]:
    try:
        raw = system.read("/etc/os-release", 8192)
    except OSError:
        return {"id": "desconhecido", "version": ""}
    fields = {}
    for line in raw.splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            fields[key] = value.strip().strip('"')
    return {"id": fields.get("ID", "desconhecido").lower(),
            "version": fields.get("VERSION_ID", ""),
            "name": fields.get("PRETTY_NAME", "")}
