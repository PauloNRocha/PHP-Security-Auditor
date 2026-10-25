"""Regressões isoladas para segurança, cobertura e relatórios."""
import contextlib
import gzip
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from php_security_auditor import VERSION
from php_security_auditor import backup, cli, forensics, remediation, report, versions
from tools.check_sdist import REQUIRED, inspect


def sample_inventory():
    return {"os": {"id": "debian", "version": "12", "name": "PRIVATE_MARKER"},
            "packages": [], "binaries": [], "containers": [{"id": "PRIVATE_MARKER", "image": "PRIVATE_MARKER"}],
            "processes": [], "services": ["php8.2-fpm.service"], "host_php": True,
            "exposure": "HTTP provável", "coverage": {"pacotes": "completa"}, "methods": []}


def sample_assessed():
    return [{"name": "php8.2-fpm", "version": "8.2.34", "status": "VULNERÁVEL",
             "origin": "oficial debian", "fixed": "8.2.35", "source": "fonte", "advisory_updated": "2026-10-21"}]


def sample_investigation(severity="MÉDIA", complete=True):
    return {"status": "EVENTOS SUSPEITOS", "findings": [
        {"id": "LOG-1", "title": "Erro de memória", "severity": severity, "confidence": "MÉDIA",
         "time": "2026-10-21T00:00:00+00:00", "origin": "/private/PRIVATE_MARKER.log", "evidence": "PRIVATE_MARKER",
         "legitimate": "Pode ser legítimo", "recommendation": "Investigar"}],
        "logs_inspected": ["/private/PRIVATE_MARKER.log"], "limitations": ["logs HTTP podem omitir corpos de requisições"],
        "log_coverage": {"essential_complete": complete, "requested_since": "2026-10-01T00:00:00+00:00",
                         "requested_until": "2026-10-22T00:00:00+00:00", "observed_first": "2026-10-21T00:00:00+00:00",
                         "observed_last": "2026-10-21T00:00:00+00:00", "files_analyzed": ["/private/PRIVATE_MARKER.log"],
                         "files_skipped": [], "unknown_time_findings": 0}}


class ReportRegressionTests(unittest.TestCase):
    def test_versao_exibida_pelo_cli_e_usada_no_relatorio(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as finished:
            cli.parser().parse_args(["--version"])
        self.assertEqual(finished.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), "php-security-auditor " + VERSION)
        self.assertEqual(report.build(sample_inventory(), sample_assessed(), None)["tool_version"], VERSION)

    def test_tres_formatos_resumidos_nao_expoem_dados_privados(self):
        data = report.build(sample_inventory(), sample_assessed(), sample_investigation(),
                            {"status": "PENDENTE", "backup": "/private/PRIVATE_MARKER", "before": {"secret": "PRIVATE_MARKER"}})
        self.assertTrue(any("bytes instalados" in item for item in data["limitations"]))
        data["hostname"] = "PRIVATE_MARKER"
        data["processes"] = [{"exe": "/private/PRIVATE_MARKER"}]
        for fmt in ("json", "txt", "md"):
            with self.subTest(fmt=fmt):
                rendered = report.render(data, fmt)
                self.assertNotIn("PRIVATE_MARKER", rendered)
                self.assertNotIn("/private/", rendered)
                self.assertIn("VULNERÁVEL", rendered)
        sanitized = json.loads(report.render(data, "json"))
        self.assertFalse(set(sanitized) & {"hostname", "findings", "containers", "changes", "backups", "processes", "services"})
        self.assertEqual(sanitized["finding_severity_counts"]["MÉDIA"], 1)
        self.assertIn("PRIVATE_MARKER", report.render(data, "json", detailed=True))

    def test_resumo_nao_aceita_timestamps_e_status_arbitrarios(self):
        data = report.build(sample_inventory(), sample_assessed(), None)
        data["collected_at"] = "PRIVATE_MARKER"
        data["vulnerability_status"] = "PRIVATE_MARKER"
        data["log_coverage"] = {"requested_since": "PRIVATE_MARKER"}
        self.assertNotIn("PRIVATE_MARKER", report.render(data, "txt"))

    def test_markdown_tecnico_escapa_conteudo_ativo_do_host(self):
        inventory = sample_inventory()
        inventory["processes"] = [{"pid": 1, "ppid": 0, "uid": 33,
                                   "name": "php![x](//x.io)", "exe": "<img src=//x.io>"}]
        data = report.build(inventory, sample_assessed(), sample_investigation())
        output = report.render(data, "md", detailed=True)
        self.assertNotIn("![x]", output)
        self.assertNotIn("<img", output)
        self.assertIn(r"\!\[x\]", output)
        self.assertIn("&lt;img", output)


class ValidationRegressionTests(unittest.TestCase):
    def setUp(self):
        self.state = {"modules": {}, "services": [], "ports": []}

    def test_extensao_nao_aplicavel_com_runtime_corrigido(self):
        assessed = [{"status": "CORRIGIDO", "name": "php8.2-fpm"},
                    {"status": "NÃO APLICÁVEL", "name": "php8.2-xdebug"}]
        self.assertEqual(remediation.validate_after(self.state, self.state, assessed, []), [])

    def test_runtime_vulneravel_indeterminado_ou_ausente(self):
        for status, expected in (("VULNERÁVEL", "vulnerável"), ("INDETERMINADO", "indeterminada")):
            with self.subTest(status=status):
                self.assertTrue(any(expected in msg for msg in remediation.validate_after(
                    self.state, self.state, [{"status": status}, {"status": "NÃO APLICÁVEL"}], [])))
        self.assertTrue(remediation.validate_after(self.state, self.state, [{"status": "NÃO APLICÁVEL"}], []))


class LogRegressionTests(unittest.TestCase):
    def test_sinal_de_upload_e_compativel_sem_confirmar_exploracao(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text("2026-10-21T12:00:00+00:00 PHP_SESSION_UPLOAD_PROGRESS\n")
            found, _, _ = forensics.scan_logs(datetime(2026, 10, 1, tzinfo=timezone.utc), [path])
        self.assertEqual(len(found), 1)
        self.assertIn("compatível", found[0]["context"])
        self.assertIn("não comprovada", found[0]["context"])

    def test_timestamp_apache_nginx_php_e_offset(self):
        samples = ("127.0.0.1 - - [21/Oct/2026:09:00:00 -0300] \"POST /\" 200 1",
                   "2026-10-21T09:00:00-03:00 erro",
                   "[21-Oct-2026 12:00:00 UTC] erro")
        for line in samples:
            with self.subTest(line=line):
                self.assertEqual(forensics._stamp(line), datetime(2026, 10, 21, 12, tzinfo=timezone.utc))
        self.assertEqual(forensics._stamp("2026/10/21 12:00:00 [error]" ).year, 2026)

    def test_antigo_excluido_e_sem_data_marcado_como_desconhecido(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log"
            path.write_text("2019-01-01 00:00:00 out of memory\nout of memory\n")
            found, limits, _ = forensics.scan_logs(datetime(2026, 10, 1, tzinfo=timezone.utc), [path])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["temporal_status"], "TEMPO_DESCONHECIDO")
        self.assertEqual(found[0]["time"], "desconhecido")
        self.assertTrue(any("sem data" in item for item in limits))

    def test_rotacionado_e_cobertura_de_arquivos_ignorados(self):
        with tempfile.TemporaryDirectory() as tmp:
            rotated = Path(tmp) / "error.log.1.gz"
            with gzip.open(rotated, "wb") as out:
                out.write(b"2026-10-21T12:00:00+00:00 out of memory\n")
            oversized = Path(tmp) / "error.log.2"
            oversized.write_text("x" * 20)
            with patch.object(forensics, "MAX_LOG_SIZE", 10):
                found, limits, inspected, coverage = forensics._scan_logs_with_coverage(
                    datetime(2026, 10, 1, tzinfo=timezone.utc), [rotated, oversized], 1024)
            self.assertEqual(found, [])  # ambos excedem o limite artificial de 10 bytes
            self.assertFalse(inspected)
            self.assertEqual(len(coverage["files_skipped"]), 2)
            self.assertTrue(limits)
            found, _, _, coverage = forensics._scan_logs_with_coverage(
                datetime(2026, 10, 1, tzinfo=timezone.utc), [rotated], 1024)
            self.assertEqual(len(found), 1)
            self.assertEqual(coverage["observed_last"], "2026-10-21T12:00:00+00:00")

    def test_rotacionado_antigo_e_offset_fora_da_janela(self):
        with tempfile.TemporaryDirectory() as tmp:
            rotated = Path(tmp) / "error.log.1.gz"
            with gzip.open(rotated, "wb") as out:
                out.write(b"2019-01-01T00:00:00+00:00 out of memory\n")
                out.write(b"2026-09-30T23:00:00-03:00 out of memory\n")
            found, _, _, coverage = forensics._scan_logs_with_coverage(
                datetime(2026, 10, 1, 3, tzinfo=timezone.utc), [rotated], 1024)
            self.assertEqual(found, [])
            self.assertEqual(coverage["observed_last"], "2026-10-01T02:00:00+00:00")

    def test_log_recente_isolado_nao_comprova_cobertura_da_janela(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log"
            path.write_text("2026-10-21T12:00:00+00:00 out of memory\n")
            _, limits, _, coverage = forensics._scan_logs_with_coverage(
                datetime(2026, 10, 1, tzinfo=timezone.utc), [path], 1024)
            self.assertFalse(limits)
            self.assertFalse(coverage["essential_complete"])
            self.assertIn(str(path), coverage["file_metadata"])

    def test_falha_de_listagem_de_logs_fica_na_cobertura(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good"
            good.mkdir()
            (good / "error.log").write_text("2026-10-21T12:00:00+00:00 out of memory\n")
            denied = Path(tmp) / "denied"
            denied.mkdir()
            original = Path.iterdir

            def restricted(path):
                if path == denied:
                    raise PermissionError("sintético")
                return original(path)

            with patch.object(forensics, "LOG_DIRS", (str(good), str(denied))), patch.object(Path, "iterdir", restricted):
                _, limits, _, coverage = forensics._scan_logs_with_coverage(
                    datetime(2026, 10, 1, tzinfo=timezone.utc), None, 1024)
            self.assertTrue(any(str(denied) in item for item in limits))
            self.assertFalse(coverage["essential_complete"])


class AdditionalSecurityRegressionTests(unittest.TestCase):
    def test_origem_apt_local_mista_nao_e_oficial(self):
        policy = ("php8.2-fpm:\n  Version table:\n     8.2.35-1 500\n"
                  "        500 https://deb.debian.org/debian bookworm/main amd64 Packages\n"
                  "        release o=Debian,a=oldstable\n"
                  "        500 file:/srv/pacotes bookworm/main amd64 Packages\n"
                  "        release o=Debian,a=oldstable\n")

        class Fake:
            def run(self, args, timeout):
                return subprocess.CompletedProcess(args, 0, policy, "")

        self.assertEqual(versions.package_origin(Fake(), "php8.2-fpm", "8.2.35-1", "debian"),
                         "não comprovada")

    def test_rotacao_entre_analise_e_preservacao_recusada(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log"
            path.write_text("2026-10-21T12:00:00+00:00 out of memory\n")
            _, _, _, coverage = forensics._scan_logs_with_coverage(
                datetime(2026, 10, 1, tzinfo=timezone.utc), [path], 1024)
            old = coverage["file_metadata"][str(path)]
            path.rename(Path(tmp) / "error.log.1")
            path.write_text("novo log")
            with patch.object(backup, "_safe_root"), patch.object(backup, "_trusted_directory"):
                session = backup.BackupSession(Path(tmp) / "backup")
            with self.assertRaisesRegex(ValueError, "difere do arquivo examinado"):
                session.preserve(path, expected=old)

    def test_excesso_de_arquivos_bloqueia_antes_do_apt(self):
        current = {"approved_possible": True, "packages": ["php8.2-fpm=8.2.35"], "simulation": ["Inst php8.2-fpm"]}
        logs = [f"/logs/error.log.{index}" for index in range(40)]
        approved = dict(current, logs_inspected=logs, log_metadata={path: {} for path in logs})
        configs = [Path(f"/etc/php/8.2/fpm/test{index}.ini") for index in range(61)]
        with patch.object(remediation, "REMEDIATION_VALIDATED", True), patch.object(remediation.os, "geteuid", return_value=0), \
             patch.object(remediation, "discover", return_value=sample_inventory()), \
             patch.object(remediation, "evaluate", return_value=sample_assessed()), \
             patch.object(remediation, "plan", return_value=current), \
             patch.object(remediation, "_configs", return_value=configs), \
             patch.object(remediation, "BackupSession") as backup_session:
            with self.assertRaisesRegex(RuntimeError, "Mais de 100"):
                remediation.remediate(None, approved, investigation_reviewed=True)
        backup_session.assert_not_called()


class RemediationFlowRegressionTests(unittest.TestCase):
    def invoke(self, investigation, validated=True):
        out = io.StringIO()
        proposed = {"approved_possible": True, "packages": ["php8.2-fpm=8.2.35"],
                    "simulation": ["Inst php8.2-fpm"], "errors": [], "risks": ["APT pode reiniciar serviços"]}
        checked = []
        expected = "ATUALIZAR php8.2-fpm=8.2.35 APÓS ANALISAR " + investigation["status"]

        def answer(_prompt):
            visible = out.getvalue()
            self.assertIn("Investigação: " + investigation["status"], visible)
            self.assertIn("Erro de memória", visible)
            self.assertIn("logs HTTP podem omitir corpos", visible)
            self.assertIn("APT pode reiniciar serviços", visible)
            self.assertIn("preservação pendente", visible)
            checked.append(True)
            return expected

        with patch.object(cli, "discover", return_value=sample_inventory()), patch.object(cli, "evaluate", return_value=sample_assessed()), \
             patch.object(cli, "investigate", return_value=investigation), patch.object(cli, "plan", return_value=proposed), \
             patch.object(remediation, "REMEDIATION_VALIDATED", validated), patch.object(cli.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=answer) as prompt, patch.object(cli, "remediate", return_value={"status": "mock"}) as update, \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            result = cli.main(["remediate"])
        return result, checked, prompt, update, out.getvalue()

    def test_achados_medios_apresentados_antes_de_autorizar(self):
        result, checked, prompt, update, _ = self.invoke(sample_investigation())
        self.assertEqual(result, 0)
        self.assertTrue(checked)
        prompt.assert_called_once()
        update.assert_called_once()
        self.assertTrue(update.call_args.kwargs["investigation_reviewed"])

    def test_gravidade_alta_bloqueia_antes_da_pergunta(self):
        result, _, prompt, update, visible = self.invoke(sample_investigation("ALTA"))
        self.assertEqual(result, 2)
        self.assertIn("ALTA", visible)
        prompt.assert_not_called()
        update.assert_not_called()

    def test_coleta_incompleta_bloqueia(self):
        result, _, prompt, update, _ = self.invoke(sample_investigation(complete=False))
        self.assertEqual(result, 2)
        prompt.assert_not_called()
        update.assert_not_called()

    def test_remediacao_ainda_nao_liberada(self):
        result, _, prompt, update, _ = self.invoke(sample_investigation(), validated=False)
        self.assertEqual(result, 2)
        prompt.assert_not_called()
        update.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "indisponível"):
            remediation.remediate(None, {}, investigation_reviewed=True)


class DestinationAndPackagingTests(unittest.TestCase):
    def test_destino_git_e_publico_recusado_customizado_permitido(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "projeto"
            root.mkdir()
            (root / ".git").mkdir()
            with self.assertRaisesRegex(ValueError, "árvore Git"):
                backup._check_public_tree(root / "saida")
            with self.assertRaisesRegex(ValueError, "temporária"):
                backup._safe_root(root / "saida")
        with self.assertRaisesRegex(ValueError, "público"):
            backup._safe_root(Path("/home/exemplo/public_html/backup"))
        self.assertIsNone(backup._safe_root(Path("/var/lib/php-auditor-privado")))

    def test_manifesto_rejeita_cache_e_aceita_arquivos_publicos(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "test.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for name in (*REQUIRED, "php_security_auditor/__pycache__/x.pyc"):
                    data = b"synthetic"
                    info = tarfile.TarInfo("php_security_auditor-0.1.0/" + name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            self.assertTrue(any("gerado" in item for item in inspect(str(archive))))


class ProcessContextTests(unittest.TestCase):
    def test_executavel_temporario_sem_php_e_suspeita_geral(self):
        findings = forensics.inspect_processes([
            {"pid": 7, "ppid": 1, "name": "desconhecido", "exe": "/tmp/arquivo"}])
        self.assertEqual(findings[0]["severity"], "ALTA")
        self.assertEqual(findings[0]["context"], forensics.HOST_CONTEXT)

    def test_shell_web_e_linhagem_php_tem_contextos_distintos(self):
        processes = [
            {"pid": 1, "ppid": 0, "name": "apache2", "exe": "/usr/sbin/apache2"},
            {"pid": 2, "ppid": 1, "name": "sh", "exe": "/bin/sh"},
            {"pid": 3, "ppid": 0, "name": "php8.2-fpm", "exe": "/usr/sbin/php-fpm8.2"},
            {"pid": 4, "ppid": 3, "name": "sh", "exe": "/bin/sh"},
            {"pid": 5, "ppid": 4, "name": "worker", "exe": "/tmp/worker"},
        ]
        findings = forensics.inspect_processes(processes)
        by_pid = {int(f["evidence"].split(";")[0].split()[-1]): f for f in findings}
        self.assertEqual(by_pid[2]["context"], forensics.WEB_CONTEXT)
        self.assertEqual(by_pid[4]["context"], forensics.PHP_CONTEXT)
        self.assertEqual(by_pid[5]["context"], forensics.PHP_CONTEXT)
        self.assertTrue(all(f["severity"] == "ALTA" for f in findings))

    def test_contexto_consta_apenas_no_relatorio_detalhado(self):
        investigation = sample_investigation()
        investigation["findings"][0]["context"] = forensics.HOST_CONTEXT
        data = report.build(sample_inventory(), sample_assessed(), investigation)
        self.assertIn(forensics.HOST_CONTEXT, report.render(data, "txt", detailed=True))
        self.assertIn("Contexto: Suspeita geral do hospedeiro", report.render(data, "md", detailed=True))
        self.assertNotIn(forensics.HOST_CONTEXT, report.render(data, "txt"))
