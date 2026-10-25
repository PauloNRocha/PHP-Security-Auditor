"""Testes isolados: nunca executam APT de instalação nem usam servidores reais."""
import gzip
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from php_security_auditor import backup, cli, discovery, forensics, remediation, report, versions
from php_security_auditor.system import System


class FakeSystem:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.calls = []

    def run(self, args, timeout=10):
        self.calls.append(tuple(args))
        key = tuple(args)
        status, out, err = self.outputs.get(key, (127, "", "ausente"))
        return subprocess.CompletedProcess(args, status, out, err)

    def read(self, path, limit=65536):
        return self.outputs.get(("read", path), "")


def fake_compare_outputs(values):
    output = {}
    for version, fixed, result in values:
        output[("dpkg", "--compare-versions", version, "ge", fixed)] = (result, "", "")
    return output


def inventory(packages=None, binaries=None, containers=None, services=None):
    return {"os": {"id": "debian", "version": "12", "name": "Debian 12"},
            "packages": packages or [], "binaries": binaries or [], "containers": containers or [],
            "processes": [], "services": services or [], "host_php": bool(packages or binaries),
            "exposure": "HTTP indeterminada", "coverage": {"pacotes": "completa", "processos": "completa", "serviços": "completa", "contêineres": "incompleta"},
            "methods": ["dpkg-query", "/proc"]}


def package(name="php8.2-fpm", version="8.2.34-1~deb12u1", origin="oficial debian"):
    import re
    branch = re.search(r"\d+\.\d+", name)
    return {"name": name, "version": version, "origin": origin,
            "source_package": "php" + branch.group() if branch else ""}


class DiscoveryTests(unittest.TestCase):
    def test_servidor_sem_php(self):
        system = FakeSystem({("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Status}\t${source:Package}\n"): (0, "bash\t5\tinstall ok installed\tbash\n", "")})
        with patch.object(discovery, "binaries", return_value=[]), patch.object(discovery, "processes", return_value=([], "completa")), patch.object(discovery, "services", return_value=([], "completa")), patch.object(discovery, "containers", return_value=([], {"docker": "incompleta"})):
            found = discovery.discover(system)
        self.assertFalse(found["host_php"])
        self.assertEqual(found["packages"], [])
        self.assertIn("docker ps", found["methods"])

    def test_multiplas_versoes(self):
        output = "php8.2-cli\t8.2.34-1~deb12u1\tinstall ok installed\tphp8.2\nphp8.3-cli\t8.3.36\tinstall ok installed\tphp8.3\n"
        system = FakeSystem({("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Status}\t${source:Package}\n"): (0, output, "")})
        with patch.object(discovery, "package_origin", return_value="não comprovada"):
            found, _ = discovery.packages(system, {"id": "debian"})
        self.assertEqual(len(found), 2)

    def test_apache_mod_php(self):
        with patch.object(discovery, "packages", return_value=([package("libapache2-mod-php8.2")], "completa")), patch.object(discovery, "binaries", return_value=[]), patch.object(discovery, "processes", return_value=([], "completa")), patch.object(discovery, "services", return_value=(["apache2.service"], "completa")), patch.object(discovery, "containers", return_value=([], {})):
            self.assertEqual(discovery.discover(FakeSystem())["exposure"], "HTTP provável")

    def test_php_fpm(self):
        with patch.object(discovery, "packages", return_value=([package()], "completa")), patch.object(discovery, "binaries", return_value=[]), patch.object(discovery, "processes", return_value=([], "completa")), patch.object(discovery, "services", return_value=(["php8.2-fpm.service", "nginx.service"], "completa")), patch.object(discovery, "containers", return_value=([], {})):
            self.assertEqual(discovery.discover(FakeSystem())["exposure"], "HTTP provável")

    def test_php_somente_cli(self):
        with patch.object(discovery, "packages", return_value=([package("php8.2-cli")], "completa")), patch.object(discovery, "binaries", return_value=[]), patch.object(discovery, "processes", return_value=([], "completa")), patch.object(discovery, "services", return_value=([], "completa")), patch.object(discovery, "containers", return_value=([], {})):
            self.assertIn("CLI", discovery.discover(FakeSystem())["exposure"])

    def test_conteiner_metadados_sem_exec(self):
        system = FakeSystem({("docker", "ps", "--format", "{{json .}}"): (0, '{"ID":"abc","Image":"php:8.2","Command":"php-fpm"}\n', "")})
        containers, coverage = discovery.containers(system)
        self.assertEqual(containers[0]["status"], "INDETERMINADO")
        self.assertFalse(any("exec" in call for call in system.calls))
        self.assertIn("interior não inspecionado", coverage["docker"])

    def test_falta_permissoes_conteiner(self):
        containers, coverage = discovery.containers(FakeSystem())
        self.assertEqual(containers, [])
        self.assertIn("incompleta", coverage["docker"])


class VersionTests(unittest.TestCase):
    def test_vulneravel(self):
        system = FakeSystem(fake_compare_outputs([("8.2.34-1~deb12u1", "8.2.35-1~deb12u1", 1)]))
        self.assertEqual(versions.evaluate([package()], inventory()["os"], system)[0]["status"], "VULNERÁVEL")

    def test_corrigido(self):
        p = package(version="8.2.35-1~deb12u1")
        system = FakeSystem(fake_compare_outputs([(p["version"], p["version"], 0)]))
        self.assertEqual(versions.evaluate([p], inventory()["os"], system)[0]["status"], "CORRIGIDO")

    def test_backport_ubuntu(self):
        p = package("php8.3-fpm", "8.3.6-0ubuntu0.24.04.13", "oficial ubuntu")
        system = FakeSystem(fake_compare_outputs([(p["version"], p["version"], 0)]))
        assessed = versions.evaluate([p], {"id": "ubuntu", "version": "24.04"}, system)
        self.assertEqual(assessed[0]["status"], "CORRIGIDO")

    def test_origem_desconhecida(self):
        assessed = versions.evaluate([package(origin="não comprovada")], inventory()["os"], FakeSystem())
        self.assertEqual(assessed[0]["status"], "INDETERMINADO")

    def test_extensao_terceirizada_nao_representa_runtime(self):
        entry = dict(package("php8.2-xdebug"), source_package="xdebug")
        self.assertEqual(versions.evaluate([entry], inventory()["os"], FakeSystem())[0]["status"], "NÃO APLICÁVEL")

    def test_origem_spoofada_por_release(self):
        policy = "php8.2-fpm:\n  Candidate: 8.2.35-1\n  Version table:\n     8.2.35-1 500\n        500 https://third-party.invalid/repo stable/main amd64 Packages\n        release o=Debian,a=stable\n"
        system = FakeSystem({("apt-cache", "policy", "php8.2-fpm"): (0, policy, "")})
        self.assertEqual(versions.package_origin(system, "php8.2-fpm", "8.2.35-1", "debian"), "não comprovada")

    def test_origem_debian_oficial(self):
        policy = "php8.2-fpm:\n  Version table:\n     8.2.35-1 500\n        500 http://deb.debian.org/debian bookworm/main amd64 Packages\n        release o=Debian,a=oldstable\n"
        system = FakeSystem({("apt-cache", "policy", "php8.2-fpm"): (0, policy, "")})
        self.assertEqual(versions.package_origin(system, "php8.2-fpm", "8.2.35-1", "debian"), "oficial debian")

    def test_origem_mista_mesma_versao_indeterminada(self):
        policy = "php8.2-fpm:\n  Version table:\n     8.2.35-1 500\n        500 http://deb.debian.org/debian bookworm/main amd64 Packages\n        release o=Debian,a=oldstable\n        500 https://third-party.invalid/repo stable/main amd64 Packages\n        release o=Vendor,a=stable\n"
        system = FakeSystem({("apt-cache", "policy", "php8.2-fpm"): (0, policy, "")})
        self.assertEqual(versions.package_origin(system, "php8.2-fpm", "8.2.35-1", "debian"), "não comprovada")

    def test_ramo_desconhecido(self):
        assessed = versions.evaluate([package("php7.4-fpm")], inventory()["os"], FakeSystem())
        self.assertEqual(assessed[0]["status"], "INDETERMINADO")

    def test_epoca_dpkg_e_nao_comparacao_textual(self):
        p = package(version="1:8.2.34-1~deb12u1")
        system = FakeSystem(fake_compare_outputs([(p["version"], "8.2.35-1~deb12u1", 0)]))
        self.assertEqual(versions.evaluate([p], inventory()["os"], system)[0]["status"], "CORRIGIDO")


class ForensicTests(unittest.TestCase):
    def test_logs_inexistentes(self):
        result, limits, inspected = forensics.scan_logs(datetime(2026, 10, 1, tzinfo=timezone.utc), [Path("/arquivo/inexistente")])
        self.assertEqual(result, [])
        self.assertFalse(inspected)
        self.assertTrue(limits)

    def test_logs_rotacionados_gzip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log.1.gz"
            with gzip.open(path, "wb") as out:
                out.write(b"2026-10-21 12:00:00 Allowed memory size exhausted\n")
            found, _, _ = forensics.scan_logs(datetime(2026, 10, 1, tzinfo=timezone.utc), [path])
            self.assertEqual(found[0]["title"], "Erro de memória")
            self.assertNotIn("Allowed memory", found[0]["evidence"])

    def test_linha_maliciosa_nao_executada(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "executado"
            path = Path(tmp) / "access.log"
            path.write_text(f"2026-10-21 12:00:00 PHP_SESSION_UPLOAD_PROGRESS $({marker})\n")
            found, _, _ = forensics.scan_logs(datetime(2026, 10, 1, tzinfo=timezone.utc), [path])
            self.assertTrue(found)
            self.assertFalse(marker.exists())

    def test_link_simbolico_recusado(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "original"
            original.write_text("out of memory")
            link = Path(tmp) / "access.log"
            link.symlink_to(original)
            found, limits, _ = forensics.scan_logs(datetime(2026, 10, 1, tzinfo=timezone.utc), [link])
            self.assertFalse(found)
            self.assertTrue(limits)

    def test_processo_shell_filho(self):
        processes = [{"pid": 1, "ppid": 0, "name": "apache2", "exe": "/usr/sbin/apache2"},
                     {"pid": 2, "ppid": 1, "name": "sh", "exe": "/bin/dash"}]
        self.assertEqual(forensics.inspect_processes(processes)[0]["title"], "Shell filho de serviço web")


class BackupTests(unittest.TestCase):
    def make_root(self):
        return tempfile.TemporaryDirectory(dir=Path.cwd())

    def setUp(self):
        # Estes testes cobrem integridade e links; a política de destinos é testada separadamente.
        # Cópias extraídas sob /tmp são recusadas pelo código de produção por definição.
        self.destination_patch = patch.object(backup, "_safe_root", return_value=None)
        self.destination_patch.start()
        self.addCleanup(self.destination_patch.stop)
        self.trust_patch = patch.object(backup, "_trusted_directory", return_value=None)
        self.trust_patch.start()
        self.addCleanup(self.trust_patch.stop)
        # A política de destinos é exercitada por testes específicos.
        self.public_patch = patch.object(backup, "_check_public_tree", return_value=None)
        self.public_patch.start()
        self.addCleanup(self.public_patch.stop)

    def test_ancestral_grupo_escrita_recusado(self):
        self.trust_patch.stop()
        with self.assertRaises(PermissionError):
            backup._trusted_directory(type("Info", (), {"st_uid": os.geteuid(), "st_mode": 0o40770})())
        self.trust_patch.start()

    def test_backup_hash_e_metadados(self):
        with self.make_root() as tmp:
            source = Path(tmp) / "log"
            source.write_text("evidência")
            root = Path(tmp) / "backup"
            session = backup.BackupSession(root)
            session.preserve(source)
            session.finalize({"id": "debian"}, ["teste"])
            self.assertEqual(backup.validate_manifest(session.path), [])

    def test_disco_sem_espaco(self):
        with self.make_root() as tmp, patch.object(backup.shutil, "disk_usage", return_value=type("Space", (), {"free": 1})()):
            with self.assertRaises(OSError):
                backup.BackupSession(Path(tmp) / "backup")

    def test_falha_backup_symlink(self):
        with self.make_root() as tmp:
            root = Path(tmp) / "backup"
            source = Path(tmp) / "source"
            source.write_text("segredo")
            link = Path(tmp) / "link"
            link.symlink_to(source)
            with self.assertRaises(ValueError):
                backup.BackupSession(root).preserve(link)

    def test_falha_integridade(self):
        with self.make_root() as tmp:
            source = Path(tmp) / "log"
            source.write_text("antes")
            session = backup.BackupSession(Path(tmp) / "backup")
            entry = session.preserve(source)
            session.finalize({}, [])
            (session.path / entry["copy"]).write_text("depois")
            self.assertTrue(backup.validate_manifest(session.path))

    def test_manifesto_caminho_traversal_recusado(self):
        with self.make_root() as tmp:
            session = backup.BackupSession(Path(tmp) / "backup")
            manifest = session.finalize({}, [])
            content = json.loads(manifest.read_text())
            content["files"] = [{"copy": "../segredo", "size": 0, "sha256": "x"}]
            manifest.write_text(json.dumps(content))
            self.assertIn("Caminho inválido no manifesto", backup.validate_manifest(session.path))

    def test_manifesto_grande_recusado(self):
        with self.make_root() as tmp:
            session = backup.BackupSession(Path(tmp) / "backup")
            manifest = session.finalize({}, [])
            manifest.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                backup.validate_manifest(session.path)

    def test_diretorio_raiz_symlink(self):
        with self.make_root() as tmp:
            real = Path(tmp) / "real"
            real.mkdir(mode=0o700)
            link = Path(tmp) / "link"
            link.symlink_to(real)
            with self.assertRaises(OSError):
                backup.BackupSession(link)


class FlowTests(unittest.TestCase):
    def test_auditoria_padrao_sem_comandos_de_escrita(self):
        with patch.object(cli, "discover", return_value=inventory()), patch.object(cli, "evaluate", return_value=[]), patch.object(cli, "investigate") as inv, patch.object(cli, "remediate") as rem, patch.object(cli, "BackupSession") as bkp, patch("sys.stdout"):
            self.assertEqual(cli.main([]), 0)
            inv.assert_not_called()
            rem.assert_not_called()
            bkp.assert_not_called()

    def test_plano_simula_sem_instalar(self):
        assessed = versions.evaluate([package()], inventory()["os"], FakeSystem(fake_compare_outputs([("8.2.34-1~deb12u1", "8.2.35-1~deb12u1", 1)])))
        system = FakeSystem({("apt-cache", "policy", "php8.2-fpm"): (0, "Candidate: 8.2.35-1~deb12u1", "")})
        with patch.object(remediation, "package_origin", return_value="oficial debian"), patch.object(remediation, "compare", return_value=True):
            remediation.plan(system, inventory([package()]), assessed)
        self.assertFalse(any(call[:2] == ("apt-get", "install") for call in system.calls))

    def test_plano_bloqueia_dependencia_sem_origem(self):
        assessed = [dict(package(), status="VULNERÁVEL", fixed="8.2.35-1~deb12u1")]
        simulation = "Inst php8.2-fpm [8.2.34] (8.2.35-1~deb12u1 Debian:12 [amd64])\nInst helper [1] (2 vendor:1 [amd64])\n"
        outputs = {("apt-cache", "policy", "php8.2-fpm"): (0, "Candidate: 8.2.35-1~deb12u1", ""),
                   ("apt-get", "-s", "--no-remove", "--only-upgrade", "install", "php8.2-fpm=8.2.35-1~deb12u1"): (0, simulation, "")}
        with patch.object(remediation, "compare", return_value=True), patch.object(remediation, "package_origin", side_effect=lambda _sys, name, _version, _distro: "oficial debian" if name == "php8.2-fpm" else "não comprovada"):
            proposed = remediation.plan(FakeSystem(outputs), inventory([package()]), assessed)
        self.assertFalse(proposed["approved_possible"])
        self.assertTrue(any("Dependência" in item for item in proposed["errors"]))

    def test_remediacao_nao_interativa_bloqueada(self):
        proposed = {"approved_possible": True, "packages": ["php8.2-fpm=8.2.35-1~deb12u1"], "simulation": ["Inst php8.2-fpm"]}
        with patch.object(cli, "discover", return_value=inventory([package()])), patch.object(cli, "evaluate", return_value=[dict(package(), status="VULNERÁVEL")]), patch.object(cli, "investigate", return_value={"status": "SEM INDÍCIOS IDENTIFICADOS", "findings": [], "logs_inspected": [], "limitations": []}), patch.object(cli, "plan", return_value=proposed), patch.object(cli, "remediate") as rem, patch("sys.stdout"), patch("sys.stderr"):
            self.assertEqual(cli.main(["remediate", "--non-interactive"]), 2)
            rem.assert_not_called()

    def test_interrupcao_atualizacao_retorna_falha(self):
        response = System().run([sys.executable, "-c", "import time; time.sleep(3)"], timeout=1)
        self.assertEqual(response.returncode, 124)
        self.assertIn("Tempo limite", response.stderr)

    def test_falha_backup_bloqueia_apt(self):
        approved = {"packages": ["php8.2-fpm=8.2.35-1~deb12u1"], "simulation": ["Inst php8.2-fpm"]}
        current = dict(approved, approved_possible=True)
        system = FakeSystem()
        with patch.object(remediation, "REMEDIATION_VALIDATED", True), patch.object(remediation.os, "geteuid", return_value=0), patch.object(remediation, "discover", return_value=inventory([package()])), patch.object(remediation, "evaluate", return_value=[]), patch.object(remediation, "plan", return_value=current), patch.object(remediation, "_configs", return_value=[]), patch.object(remediation, "BackupSession", side_effect=OSError("disco cheio")):
            with self.assertRaises(OSError):
                remediation.remediate(system, approved, investigation_reviewed=True)
        self.assertFalse(any(call and call[0] == "apt-get" for call in system.calls))

    def test_falha_apt_interrompe_validacao_posterior(self):
        approved = {"packages": ["php8.2-fpm=8.2.35-1~deb12u1"], "simulation": ["Inst php8.2-fpm"]}
        current = dict(approved, approved_possible=True)
        apt = ("apt-get", "--no-remove", "--only-upgrade", "install", "php8.2-fpm=8.2.35-1~deb12u1")
        system = FakeSystem({apt: (124, "", "Tempo limite excedido")})
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            (Path(tmp) / "transacao").mkdir()
            fake_session = type("Session", (), {"path": Path(tmp), "preserve": lambda *_args: None,
                                                "finalize": lambda *_args: Path(tmp) / "manifesto.json"})()
            with patch.object(remediation, "REMEDIATION_VALIDATED", True), patch.object(remediation.os, "geteuid", return_value=0), patch.object(remediation, "discover", return_value=inventory([package()])) as get_inventory, patch.object(remediation, "evaluate", return_value=[]), patch.object(remediation, "plan", return_value=current), patch.object(remediation, "_configs", return_value=[]), patch.object(remediation, "BackupSession", return_value=fake_session), patch.object(remediation, "validate_manifest", return_value=[]), patch.object(remediation, "_modules", return_value={}), patch.object(remediation, "_ports", return_value=[]):
                result = remediation.remediate(system, approved, investigation_reviewed=True)
        self.assertEqual(result["status"], "FALHA NA ATUALIZAÇÃO")
        self.assertEqual(get_inventory.call_count, 1)

    def test_erro_validacao_modulos(self):
        before = {"modules": {"8.2": ["mysqli", "PDO", "curl"]}, "services": ["php8.2-fpm.service"], "ports": ["0.0.0.0:80"]}
        after = {"modules": {"8.2": ["PDO", "curl"]}, "services": ["php8.2-fpm.service"], "ports": ["0.0.0.0:80"]}
        self.assertIn("Módulos do PHP 8.2 falharam ou desapareceram.", remediation.validate_after(before, after, [{"status": "CORRIGIDO"}], []))

    def test_rollback_sessao_invalida(self):
        with tempfile.TemporaryDirectory() as tmp, patch("sys.stdout"), patch("sys.stderr"):
            self.assertEqual(cli.main(["rollback-config", "--session", tmp]), 2)

    def test_relatorio_resumido_nao_expoe_linha_de_log(self):
        data = report.build(inventory([package()]), [dict(package(), status="VULNERÁVEL")],
                            {"status": "EVENTOS SUSPEITOS", "findings": [{"id": "LOG-1", "title": "Erro", "severity": "MÉDIA", "confidence": "BAIXA", "time": "hoje", "origin": "/var/log/x", "evidence": "segredo", "legitimate": "erro normal", "recommendation": "analisar"}], "logs_inspected": [], "limitations": []})
        self.assertNotIn("segredo", report.render(data, "txt", detailed=False))

    def test_runtime_sem_pacote_fica_indeterminado(self):
        data = report.build(inventory(binaries=[{"path": "/usr/bin/php8.2", "target": "/usr/bin/php8.2"}]), [], None)
        self.assertEqual(data["vulnerability_status"], "INDETERMINADO")

    def test_controle_terminal_em_nome_de_pacote_e_escapado(self):
        entry = dict(package(), status="INDETERMINADO", fixed=None, name="php8.2-cli\x1b[2J")
        data = report.build(inventory([entry]), [entry], None)
        rendered = report.render(data, "txt", detailed=True)
        self.assertNotIn("\x1b", rendered)
        self.assertIn("\\x1b", rendered)
        self.assertNotIn("php8.2-cli", report.render(data, "txt"))


if __name__ == "__main__":
    unittest.main()
