"""Regressões sintéticas dos quatro defeitos da auditoria remota."""
import contextlib
import gzip
import hashlib
import io
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from php_security_auditor import cli, forensics, remediation, report, versions
from php_security_auditor.system import System, _stop_process_group


class FakeSystem:
    def __init__(self, outputs):
        self.outputs = outputs

    def run(self, args, timeout=10):
        return subprocess.CompletedProcess(args, *self.outputs.get(tuple(args), (127, "", "ausente")))


def apt_policy(name, version, *sources):
    return (f"{name}:\n  Installed: {version}\n  Version table:\n *** {version} 500\n" +
            "".join(f"        500 {source}\n" for source in sources) +
            "        100 /var/lib/dpkg/status\n")


def repository_policy(*entries):
    return "Package files:\n" + "".join(
        f" 500 {source}\n     release {release}\n     origin {host}\n"
        for source, release, host in entries)


class AptOriginTests(unittest.TestCase):
    def origin(self, distro, source, metadata, extra_sources=()):
        name, version = "php8.2-fpm", "8.2.35-1~deb12u1"
        sources = (source,) + tuple(entry[0] for entry in extra_sources)
        system = FakeSystem({
            ("apt-cache", "policy", name): (0, apt_policy(name, version, *sources), ""),
            ("apt-cache", "policy"): (0, repository_policy((source, *metadata), *extra_sources), ""),
        })
        return versions.package_origin(system, name, version, distro)

    def test_debian_oficial_sem_release_na_consulta_por_pacote(self):
        source = "http://deb.debian.org/debian bookworm/main amd64 Packages"
        self.assertEqual(self.origin("debian", source,
                                     ("v=12,o=Debian,a=oldstable,n=bookworm,l=Debian,c=main,b=amd64",
                                      "deb.debian.org")), "oficial debian")

    def test_ubuntu_espelho_regional_com_metadados_ubuntu(self):
        source = "http://br.archive.ubuntu.com/ubuntu noble/main amd64 Packages"
        self.assertEqual(self.origin("ubuntu", source,
                                     ("v=24.04,o=Ubuntu,a=noble,n=noble,l=Ubuntu,c=main,b=amd64",
                                      "br.archive.ubuntu.com")), "oficial ubuntu")

    def test_terceiro_e_url_enganosa_continuam_indeterminados(self):
        for source, host in (
            ("https://third-party.invalid/repo stable/main amd64 Packages", "third-party.invalid"),
            ("https://deb.debian.org.evil.invalid/debian bookworm/main amd64 Packages",
             "deb.debian.org.evil.invalid"),
        ):
            with self.subTest(source=source):
                self.assertEqual(self.origin("debian", source, ("o=Debian,a=stable", host)),
                                 "não comprovada")

    def test_mesma_versao_em_origem_oficial_e_terceiro_nao_e_comprovada(self):
        source = "http://deb.debian.org/debian bookworm/main amd64 Packages"
        other = ("https://third-party.invalid/repo bookworm/main amd64 Packages",
                 "o=Vendor,a=stable", "third-party.invalid")
        self.assertEqual(self.origin("debian", source, ("o=Debian,a=stable", "deb.debian.org"),
                                     (other,)), "não comprovada")

    def test_metadados_incompletos_ou_host_divergente_falham_fechado(self):
        source = "http://deb.debian.org/debian bookworm/main amd64 Packages"
        for metadata in (("a=stable", "deb.debian.org"),
                         ("o=Debian,a=stable", "outro.invalid")):
            with self.subTest(metadata=metadata):
                self.assertEqual(self.origin("debian", source, metadata), "não comprovada")

        name, version = "php8.2-fpm", "8.2.35-1~deb12u1"
        policy = apt_policy(name, version, source)
        incomplete = f"Package files:\n 500 {source}\n     release o=Debian,a=stable\n"
        system = FakeSystem({("apt-cache", "policy", name): (0, policy, ""),
                             ("apt-cache", "policy"): (0, incomplete, "")})
        self.assertEqual(versions.package_origin(system, name, version, "debian"), "não comprovada")

    def test_metadados_duplicados_nao_sobrescrevem_origem(self):
        source = "http://deb.debian.org/debian bookworm/main amd64 Packages"
        self.assertEqual(self.origin("debian", source,
                                     ("o=Vendor,o=Debian,a=stable", "deb.debian.org")),
                         "não comprovada")

    def test_apenas_fontes_da_versao_instalada_sao_consideradas(self):
        name, installed = "php8.2-fpm", "8.2.35-1~deb12u1"
        official = "http://deb.debian.org/debian bookworm/main amd64 Packages"
        third = "https://third-party.invalid/repo stable/main amd64 Packages"
        package_policy = (f"{name}:\n  Installed: {installed}\n  Candidate: 8.2.36-1\n"
                          f"  Version table:\n     8.2.36-1 500\n        500 {third}\n"
                          f" *** {installed} 500\n        500 {official}\n"
                          "        100 /var/lib/dpkg/status\n")
        global_policy = repository_policy((official, "o=Debian,a=stable", "deb.debian.org"),
                                          (third, "o=Vendor,a=stable", "third-party.invalid"))
        system = FakeSystem({("apt-cache", "policy", name): (0, package_policy, ""),
                             ("apt-cache", "policy"): (0, global_policy, "")})
        self.assertEqual(versions.package_origin(system, name, installed, "debian"), "oficial debian")
        self.assertEqual(versions.package_origin(system, name, "8.2.36-1", "debian"), "não comprovada")

    def test_cabecalhos_ubuntu_com_e_sem_atualizacao_gradual(self):
        name, target = "php8.2-fpm", "8.2.35-1ubuntu0.1"
        source = "http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages"
        global_policy = repository_policy((source, "o=Ubuntu,a=jammy-updates", "archive.ubuntu.com"))
        for annotation in ("", " (phased 20%)", " (phased 100%)"):
            with self.subTest(annotation=annotation):
                policy = (f"{name}:\n  Version table:\n     {target} 500{annotation}\n"
                          f"        500 {source}\n")
                system = FakeSystem({("apt-cache", "policy", name): (0, policy, ""),
                                     ("apt-cache", "policy"): (0, global_policy, "")})
                self.assertEqual(versions.package_origin(system, name, target, "ubuntu"), "oficial ubuntu")
                self.assertEqual(versions.package_origin(system, name, target + "x", "ubuntu"), "não comprovada")

    def test_exemplo_documentado_pela_canonical_preserva_versao_e_prioridade(self):
        # Formato de ubuntu.com/server/docs/explanation/software/about-apt-upgrade-and-phased-updates/
        source = "http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages"
        policy = ("libglapi-mesa:\n  Version table:\n"
                  "     22.2.5-0ubuntu0.1~22.04.1 500 (phased 20%)\n"
                  f"        500 {source}\n"
                  " *** 22.0.5-0ubuntu0.3 100\n        100 /var/lib/dpkg/status\n")
        self.assertEqual(set(versions._policy_sources(policy, "22.2.5-0ubuntu0.1~22.04.1")), {source})
        self.assertEqual(versions._policy_sources(policy, "22.0.5-0ubuntu0.3"), {})

    def test_anotacao_gradual_invalida_ou_metadados_mistos_falham_fechado(self):
        name, target = "php8.2-fpm", "8.2.35-1ubuntu0.1"
        official = "http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages"
        third = "https://third-party.invalid/ubuntu jammy/main amd64 Packages"
        global_policy = repository_policy((official, "o=Ubuntu,a=jammy-updates", "archive.ubuntu.com"),
                                          (third, "o=Other,a=jammy", "third-party.invalid"))
        for annotation in (" (phased 120%)", " (phased -1%)", " (phased 020%)", " (phased 20%) extra"):
            with self.subTest(annotation=annotation):
                policy = (f"{name}:\n  Version table:\n     {target} 500{annotation}\n"
                          f"        500 {official}\n")
                system = FakeSystem({("apt-cache", "policy", name): (0, policy, ""),
                                     ("apt-cache", "policy"): (0, global_policy, "")})
                self.assertEqual(versions.package_origin(system, name, target, "ubuntu"), "não comprovada")
        previous_version = (f"{name}:\n  Version table:\n     {target} 500\n"
                            f"        500 {official}\n     8.2.36-1ubuntu0.1 500 (phased 120%)\n"
                            f"        500 {third}\n")
        system = FakeSystem({("apt-cache", "policy", name): (0, previous_version, ""),
                             ("apt-cache", "policy"): (0, global_policy, "")})
        self.assertEqual(versions.package_origin(system, name, target, "ubuntu"), "oficial ubuntu")
        mixed = (f"{name}:\n  Version table:\n     {target} 500 (phased 20%)\n"
                 f"        500 {official}\n        500 {third}\n")
        system = FakeSystem({("apt-cache", "policy", name): (0, mixed, ""),
                             ("apt-cache", "policy"): (0, global_policy, "")})
        self.assertEqual(versions.package_origin(system, name, target, "ubuntu"), "não comprovada")

    def test_plano_nao_contorna_prioridade_da_atualizacao_gradual(self):
        name, fixed = "php8.2-fpm", "8.2.35-1ubuntu0.1"
        policy = (f"{name}:\n  Candidate: 8.2.34-1ubuntu0.1\n  Version table:\n"
                  f"     {fixed} 1 (phased 20%)\n"
                  "        500 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages\n"
                  " *** 8.2.34-1ubuntu0.1 100\n        100 /var/lib/dpkg/status\n")
        system = FakeSystem({("apt-cache", "policy", name): (0, policy, "")})
        inv = {"os": {"id": "ubuntu", "version": "22.04"}, "services": [],
               "coverage": {"pacotes": "completa", "processos": "completa"}}
        assessed = [{"name": name, "status": "VULNERÁVEL", "fixed": fixed,
                     "origin": "oficial ubuntu"}]
        with patch.object(remediation, "package_origin", return_value="oficial ubuntu"), \
             patch.object(remediation, "compare", return_value=False):
            planned = remediation.plan(system, inv, assessed)
        self.assertFalse(planned["approved_possible"])
        self.assertEqual(planned["packages"], [])
        self.assertEqual(planned["reason_code"], "CANDIDATO_ABAIXO_CORRECAO")


def inventory(packages=(), binaries=(), processes=(), host_php=True, coverage="completa"):
    return {"os": {"id": "debian", "version": "12", "name": "Debian 12"},
            "packages": list(packages), "binaries": list(binaries), "processes": list(processes),
            "services": [], "containers": [], "host_php": host_php,
            "exposure": "HTTP indeterminada", "coverage": {"pacotes": coverage}, "methods": []}


class InvestigationDecisionTests(unittest.TestCase):
    def invoked(self, found, assessed):
        with patch.object(cli, "discover", return_value=found), \
             patch.object(cli, "evaluate", return_value=assessed), \
             patch.object(cli, "investigate") as investigation, \
             patch.object(cli, "build", return_value={}), \
             patch.object(cli, "render", return_value=""), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["audit"]), 0)
        return investigation.called

    def test_extensao_nao_aplicavel_nao_oculta_php_manual(self):
        found = inventory(packages=[{"name": "php8.2-xdebug"}],
                          binaries=[{"path": "/opt/php/bin/php", "target": "/opt/php/bin/php"}])
        self.assertTrue(self.invoked(found, [{"status": "NÃO APLICÁVEL"}]))

    def test_pacote_corrigido_nao_oculta_segundo_runtime_manual(self):
        found = inventory(binaries=[{"path": "/usr/bin/php", "target": "/opt/php/bin/php"}])
        self.assertTrue(self.invoked(found, [{"status": "CORRIGIDO"}]))

    def test_processo_php_sem_pacote_avaliavel_e_investigado(self):
        found = inventory(packages=[{"name": "php8.2-xdebug"}],
                          processes=[{"name": "php-fpm", "exe": "/opt/php/sbin/php-fpm"}])
        self.assertTrue(self.invoked(found, [{"status": "NÃO APLICÁVEL"}]))

    def test_processo_manual_com_pacote_corrigido_aparece_indeterminado_no_relatorio(self):
        found = inventory(processes=[{"pid": 10, "ppid": 1, "uid": 33,
                                     "name": "php-fpm8.2", "exe": "/opt/php/sbin/php-fpm8.2"}])
        assessed = [{"status": "CORRIGIDO", "name": "php8.2-fpm"}]
        self.assertTrue(self.invoked(found, assessed))
        self.assertEqual(report.build(found, assessed, None)["vulnerability_status"], "INDETERMINADO")

    def test_ausencia_de_php_e_extensao_sem_runtime_nao_investigam(self):
        self.assertFalse(self.invoked(inventory(host_php=False, coverage="incompleta"), []))
        self.assertFalse(self.invoked(inventory(packages=[{"name": "php8.2-xdebug"}]),
                                      [{"status": "NÃO APLICÁVEL"}]))


class SubprocessDeadlineTests(unittest.TestCase):
    def test_termino_normal(self):
        result = System().run([sys.executable, "-c", "print('ok')"], timeout=2)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "ok"))

    def test_fechou_fluxos_mas_continua_executando(self):
        start = time.monotonic()
        result = System().run([sys.executable, "-c",
                               "import os,time; os.close(1); os.close(2); time.sleep(1.5)"], timeout=0.2)
        self.assertEqual(result.returncode, 124)
        self.assertIn("Tempo limite", result.stderr)
        self.assertLess(time.monotonic() - start, 1.3)

    def test_ignora_sigterm_e_e_colhido_apos_sigkill(self):
        real_popen = subprocess.Popen
        children = []

        def launch(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        code = ("import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "print('pronto',flush=True); time.sleep(2)")
        with patch("php_security_auditor.system.subprocess.Popen", side_effect=launch):
            start = time.monotonic()
            result = System().run([sys.executable, "-c", code], timeout=0.2)
        self.assertEqual(result.returncode, 124)
        self.assertLess(time.monotonic() - start, 1.4)
        self.assertTrue(children and children[0].returncode is not None)

    def test_timeout_encerra_descendente_no_mesmo_grupo(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "descendente-executou"
            grandchild = ("import time,pathlib; time.sleep(1); "
                          f"pathlib.Path({str(marker)!r}).write_text('executou')")
            parent = ("import os,subprocess,sys,time; "
                      f"subprocess.Popen([sys.executable,'-c',{grandchild!r}],"
                      "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                      "print('pronto',flush=True); os.close(1); os.close(2); time.sleep(2)")
            result = System().run([sys.executable, "-c", parent], timeout=0.4)
            self.assertEqual(result.returncode, 124)
            self.assertIn("pronto", result.stdout)
            time.sleep(0.8)
            self.assertFalse(marker.exists())

    def test_saida_excessiva_nao_ultrapassa_limite(self):
        code = "import sys; sys.stdout.write('x' * (2 * 1024 * 1024 + 4096)); sys.stdout.flush()"
        result = System().run([sys.executable, "-c", code], timeout=3)
        self.assertEqual(result.returncode, 124)
        self.assertLessEqual(len(result.stdout.encode()), 2 * 1024 * 1024)
        self.assertIn("2 MiB", result.stderr)

    def test_interrupcao_encerra_e_colhe_filho(self):
        real_popen = subprocess.Popen
        children = []

        def launch(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        with patch("php_security_auditor.system.subprocess.Popen", side_effect=launch), \
             patch.object(selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                System().run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=1)
        self.assertTrue(children and children[0].returncode is not None)

    def test_wait_excepcional_e_comunicado_sem_sucesso_falso(self):
        real_popen = subprocess.Popen
        children = []

        def launch(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            real_wait = child.wait
            child.wait = Mock(side_effect=subprocess.TimeoutExpired(args[0], 2))
            children.append((child, real_wait))
            return child

        try:
            with patch("php_security_auditor.system.subprocess.Popen", side_effect=launch):
                result = System().run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1)
            self.assertEqual(result.returncode, 124)
            self.assertIn("não foi colhido após SIGKILL", result.stderr)
        finally:
            for child, real_wait in children:
                child.wait = real_wait
                real_wait(timeout=2)

    def test_helper_retorna_falha_de_wait_sem_espera_adicional(self):
        process = Mock(pid=12345)
        process.wait.side_effect = subprocess.TimeoutExpired("sintético", 2)
        with patch("php_security_auditor.system.os.killpg"), patch("php_security_auditor.system.time.sleep"):
            error = _stop_process_group(process)
        self.assertIn("não foi colhido após SIGKILL", error)
        process.wait.assert_called_once_with(timeout=2)


class CorruptGzipTests(unittest.TestCase):
    since = datetime(2026, 10, 1, tzinfo=timezone.utc)
    valid_line = b"2026-10-21T12:00:00+00:00 out of memory\n"

    def scan(self, paths, limit=4096):
        return forensics._scan_logs_with_coverage(self.since, paths, limit)

    def test_gzip_valido(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log.gz"
            path.write_bytes(gzip.compress(self.valid_line))
            findings, limits, inspected, coverage = self.scan([path])
        self.assertEqual(len(findings), 1)
        self.assertEqual(limits, [])
        self.assertEqual(inspected, [str(path)])
        self.assertEqual(coverage["files_partial"], [])

    def test_gzip_truncado_preserva_achado_e_marca_parcial(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log.gz"
            path.write_bytes(gzip.compress(self.valid_line)[:-5])
            findings, limits, inspected, coverage = self.scan([path])
        self.assertEqual(len(findings), 1)
        self.assertTrue(limits)
        self.assertEqual(inspected, [str(path)])
        self.assertEqual(len(coverage["files_partial"]), 1)
        self.assertFalse(coverage["essential_complete"])

    def test_gzip_corrompido_continua_outro_arquivo(self):
        broken_member = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x06"
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "error.log.1.gz"
            good = Path(tmp) / "error.log"
            bad.write_bytes(gzip.compress(self.valid_line) + broken_member)
            good.write_bytes(self.valid_line)
            findings, limits, inspected, coverage = self.scan([bad, good])
        self.assertEqual(len(findings), 2)
        self.assertTrue(any("zlib.error" in item for item in limits))
        self.assertEqual(len(inspected), 2)
        self.assertEqual(len(coverage["files_partial"]), 1)
        self.assertFalse(coverage["essential_complete"])

    def test_gzip_invalido_antes_da_primeira_linha_e_ignorado(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log.gz"
            path.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x06")
            findings, limits, inspected, coverage = self.scan([path])
        self.assertEqual(findings, [])
        self.assertTrue(limits)
        self.assertEqual(inspected, [])
        self.assertEqual(len(coverage["files_skipped"]), 1)

    def test_expansao_gzip_respeita_orcamento_de_leitura(self):
        original = gzip.GzipFile.readline
        bytes_returned = []

        def counted(handle, size=-1):
            data = original(handle, size)
            bytes_returned.append(len(data))
            return data

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log.gz"
            path.write_bytes(gzip.compress(b"x" * 10000))
            with patch.object(gzip.GzipFile, "readline", counted):
                _, limits, _, coverage = self.scan([path], limit=1024)
        self.assertTrue(limits)
        self.assertEqual(len(coverage["files_partial"]), 1)
        self.assertLessEqual(sum(bytes_returned), 1024)
        self.assertLessEqual(coverage["bytes_read"], 1024)

    def test_fragmento_no_limite_nao_produz_achado_de_linha_inteira(self):
        line = b"2026-10-21T12:00:00+00:00 out of memory" + b"x" * 200 + b"\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log.gz"
            path.write_bytes(gzip.compress(line))
            findings, limits, _, coverage = self.scan([path], limit=45)
        self.assertEqual(findings, [])
        self.assertTrue(any("linha incompleta" in item for item in limits))
        self.assertEqual(len(coverage["files_partial"]), 1)

    def test_linha_longa_e_omitida_e_analise_continua(self):
        long_line = b"2026-10-21T12:00:00+00:00 out of memory " + b"x" * 9000 + b"\n"
        short_line = self.valid_line
        for suffix in ("", ".gz"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / ("error.log" + suffix)
                payload = long_line + short_line
                path.write_bytes(gzip.compress(payload) if suffix else payload)
                findings, limits, _, coverage = self.scan([path], limit=len(payload) + 10)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["line"], 2)
                self.assertEqual(findings[0]["evidence"],
                                 "SHA-256 da linha: " + hashlib.sha256(short_line).hexdigest())
                self.assertTrue(any("linhas acima de 8192 bytes" in item for item in limits))
                self.assertEqual(len(coverage["files_partial"]), 1)
                self.assertEqual(coverage["bytes_read"], len(payload))

    def test_limite_exato_marca_fim_nao_comprovado_sem_ultrapassar_orcamento(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log.gz"
            path.write_bytes(gzip.compress(self.valid_line))
            findings, limits, _, coverage = self.scan([path], limit=len(self.valid_line))
        self.assertEqual(len(findings), 1)
        self.assertTrue(any("fim do arquivo não comprovado" in item for item in limits))
        self.assertEqual(coverage["bytes_read"], len(self.valid_line))


if __name__ == "__main__":
    unittest.main()
