"""Regressões de validação e cobertura com dados exclusivamente sintéticos."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from php_security_auditor import cli, discovery, remediation, report, verification
from test_plan_results import FakeSystem, inventory, php_package, dpkg_ownership


def corrected_inventory():
    entry = php_package("CORRIGIDO")
    entry["version"] = entry["fixed"]
    found = inventory(packages=[entry])
    found["os"]["name"] = "Ubuntu sintético"
    found["exposure"] = "sem serviço web PHP identificado; uso CLI possível"
    return found, [entry]


class StabilizationTests(unittest.TestCase):
    def invoke(self, found, assessed, operation="verify", outputs=None, detailed=False):
        system = FakeSystem(outputs)
        output = io.StringIO()
        captured = []

        def capture(data, directory, selected):
            captured.append(data)
            return []

        with patch.object(cli, "System", return_value=system), \
             patch.object(cli, "discover", return_value=found), \
             patch.object(cli, "evaluate", return_value=assessed), \
             patch.object(cli, "save", side_effect=capture), \
             patch.object(cli, "investigate") as investigation, \
             patch.object(cli, "remediate") as update, \
             contextlib.redirect_stdout(output):
            code = cli.main([operation, "--output", "/destino-sintetico"] +
                            (["--detailed"] if detailed else []))
        investigation.assert_not_called()
        update.assert_not_called()
        return code, captured[0], output.getvalue(), system.calls

    def test_verify_proc_incompleto_retorna_2(self):
        found, assessed = corrected_inventory()
        found["coverage"]["processos"] = "incompleta: acesso limitado ao /proc"
        code, data, _, _ = self.invoke(found, assessed)
        self.assertEqual(data["vulnerability_status"], "INDETERMINADO")
        self.assertEqual(code, 2)

    def test_falha_real_de_leitura_proc_simulada(self):
        with patch.object(discovery.Path, "iterdir", side_effect=PermissionError("PRIVATE_MARKER")):
            processes, coverage = discovery.processes()
        found, assessed = corrected_inventory()
        found["processes"] = processes
        found["coverage"]["processos"] = coverage
        code, data, output, _ = self.invoke(found, assessed)
        self.assertEqual(code, 2)
        self.assertIn("COBERTURA_ESSENCIAL_INCOMPLETA", data["verification"]["reason_codes"])
        self.assertNotIn("PRIVATE_MARKER", output)

    def test_verify_executavel_removido_retorna_2(self):
        found, assessed = corrected_inventory()
        found["processes"] = [{"pid": 123, "name": "php-fpm8.4", "exe": "/usr/sbin/php-fpm8.4 (deleted)"}]
        code, _, _, _ = self.invoke(found, assessed)
        self.assertEqual(code, 2)

    def test_limitacoes_aninhadas_presentes_no_relatorio(self):
        found, assessed = corrected_inventory()
        found["coverage"]["contêineres"] = {"podman": "incompleta: ferramenta ausente",
                                               "lxc": "incompleta: consulta falhou ou acesso indisponível"}
        data = report.build(found, assessed, None)
        self.assertTrue(any("podman" in note for note in data["limitations"]))
        self.assertTrue(any("lxc" in note for note in data["limitations"]))
        self.assertEqual(data["vulnerability_status"], "CORRIGIDO")

    def test_ferramenta_ausente_diferente_de_consulta_falha(self):
        outputs = {("docker", "ps", "--format", "{{json .}}"): (127, "", "FileNotFoundError"),
                   ("podman", "ps", "--format", "{{json .}}"): (1, "", "private-error"),
                   ("lxc-ls", "--active", "-1"): (0, "", "")}
        found, coverage = discovery.containers(FakeSystem(outputs))
        self.assertEqual(found, [])
        self.assertIn("ferramenta ausente", coverage["docker"])
        self.assertIn("consulta falhou", coverage["podman"])
        self.assertIn("nenhum contêiner relacionado", coverage["lxc"])
        self.assertNotIn("private-error", str(coverage))

    def test_verify_corrigido_com_cobertura_suficiente(self):
        found, assessed = corrected_inventory()
        found["binaries"] = [{"path": "/usr/bin/php", "target": "/usr/bin/php8.4"}]
        for detailed in (False, True):
            with self.subTest(detailed=detailed):
                code, data, output, calls = self.invoke(found, assessed, detailed=detailed,
                    outputs=dpkg_ownership("/usr/bin/php8.4", "php8.4-fpm"))
                self.assertEqual(code, 0)
                self.assertEqual(data["verification"]["status"], "SATISFATORIO_NO_ESCOPO_AUTOMATIZADO")
                self.assertFalse(data["verification"]["http_test_performed"])
                self.assertIn("HTTP não executado", output)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][0], "dpkg-query")

    def test_verify_nao_ignora_cobertura_essencial_ausente_ou_desconhecida(self):
        for source in ("pacotes", "processos", "serviços"):
            for value in (None, "indeterminada", "incompleta: indisponível"):
                with self.subTest(source=source, value=value):
                    found, assessed = corrected_inventory()
                    found["coverage"][source] = value
                    # O formato real é textual; campo ausente deve continuar conservador.
                    if value is None:
                        del found["coverage"][source]
                    code, data, _, calls = self.invoke(found, assessed)
                    self.assertEqual(code, 2)
                    self.assertIn("COBERTURA_ESSENCIAL_INCOMPLETA", data["verification"]["reason_codes"])
                    self.assertEqual(calls, [])

    def test_verify_vulneravel_ou_indeterminado(self):
        for state, expected in (("VULNERÁVEL", "INSATISFATORIO"), ("INDETERMINADO", "INCONCLUSIVO")):
            with self.subTest(state=state):
                found, assessed = corrected_inventory()
                assessed[0]["status"] = state
                code, data, _, _ = self.invoke(found, assessed)
                self.assertEqual(code, 2)
                self.assertEqual(data["verification"]["status"], expected)

    def test_verify_sem_php_ou_somente_extensao_nao_aprova_validacao(self):
        for assessed in ([], [php_package("NÃO APLICÁVEL")]):
            with self.subTest(assessed=assessed):
                found, _ = corrected_inventory()
                found["packages"] = assessed
                found["host_php"] = bool(assessed)
                code, data, _, _ = self.invoke(found, assessed)
                self.assertEqual((code, data["verification"]["status"]), (2, "INCONCLUSIVO"))

    def test_verify_extensao_nao_aplicavel_nao_invalida_runtime_corrigido(self):
        found, assessed = corrected_inventory()
        assessed.append(dict(php_package("NÃO APLICÁVEL"), name="php8.4-xdebug"))
        code, data, _, _ = self.invoke(found, assessed)
        self.assertEqual(code, 0)
        self.assertEqual(data["verification"]["reason_codes"], [])

    def test_verify_runtime_alternativo_precisa_de_proprietario_comprovado(self):
        for path in ("/srv/php/bin/php", "indeterminado"):
            with self.subTest(path=path):
                found, assessed = corrected_inventory()
                found["binaries"] = [{"path": "/usr/bin/php", "target": path}]
                outputs = dpkg_ownership(path) if path.startswith("/") else {}
                code, data, _, calls = self.invoke(found, assessed, outputs=outputs)
                self.assertEqual(code, 2)
                self.assertIn("RUNTIME_NAO_AVALIADO", data["verification"]["reason_codes"])
                self.assertFalse(any(call[0].endswith("php") for call in calls))

    def test_verify_falha_operacional_de_associacao(self):
        found, assessed = corrected_inventory()
        with patch.object(verification, "_unmatched_runtime", side_effect=OSError("PRIVATE_MARKER")):
            code, data, output, _ = self.invoke(found, assessed)
        self.assertEqual((code, data["verification"]["status"]), (2, "ERRO"))
        self.assertNotIn("PRIVATE_MARKER", output)

    def test_verify_falha_descoberta_tem_codigo_2_sem_vazar_erro(self):
        output = io.StringIO()
        with patch.object(cli, "System", return_value=FakeSystem()), \
             patch.object(cli, "discover", side_effect=PermissionError("PRIVATE_MARKER")), \
             contextlib.redirect_stderr(output):
            self.assertEqual(cli.main(["verify"]), 2)
        self.assertIn("não concluída", output.getvalue())
        self.assertNotIn("PRIVATE_MARKER", output.getvalue())

    def test_verify_falha_gravacao_relatorio_nao_retorna_sucesso(self):
        found, assessed = corrected_inventory()
        with patch.object(cli, "System", return_value=FakeSystem()), \
             patch.object(cli, "discover", return_value=found), \
             patch.object(cli, "evaluate", return_value=assessed), \
             patch.object(cli, "save", side_effect=OSError("falha sintética")), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["verify", "--output", "/destino-sintetico"]), 2)

    def test_verify_conteiner_php_nao_aprova_versao_interna(self):
        found, assessed = corrected_inventory()
        found["containers"] = [{"engine": "docker", "id": "PRIVATE_MARKER", "status": "INDETERMINADO"}]
        code, data, output, _ = self.invoke(found, assessed)
        self.assertEqual((code, data["vulnerability_status"]), (2, "INDETERMINADO"))
        self.assertIn("CONTEINER_NAO_INSPECIONADO", data["verification"]["reason_codes"])
        self.assertNotIn("PRIVATE_MARKER", output)

    def test_verify_mecanismos_opcionais_incompletos_nao_sao_vulnerabilidade(self):
        found, assessed = corrected_inventory()
        code, data, output, calls = self.invoke(found, assessed)
        self.assertEqual((code, data["vulnerability_status"]), (0, "CORRIGIDO"))
        self.assertIn("docker=COBERTURA_INCOMPLETA", output)
        self.assertTrue(any("docker" in note for note in data["limitations"]))
        self.assertEqual(calls, [])

    def test_relatorios_preservam_contagem_e_sanitizam_cobertura(self):
        found, assessed = corrected_inventory()
        found["coverage"]["contêineres"] = {"docker": "incompleta: ferramenta ausente PRIVATE_MARKER",
                                               "podman": "incompleta: consulta falhou PRIVATE_MARKER",
                                               "lxc": "nenhum contêiner relacionado identificado; interior não inspecionado"}
        _, data, _, _ = self.invoke(found, assessed)
        for fmt in ("json", "txt", "md"):
            with self.subTest(fmt=fmt):
                brief = report.render(data, fmt)
                technical = report.render(data, fmt, detailed=True).replace("\\_", "_")
                self.assertNotIn("PRIVATE_MARKER", brief)
                self.assertIn("PRIVATE_MARKER", technical)
                self.assertIn("docker", brief)
                self.assertIn("podman", brief)
                self.assertIn("lxc", brief)
                self.assertIn("SATISFATORIO_NO_ESCOPO_AUTOMATIZADO", brief)
                self.assertIn("SATISFATORIO_NO_ESCOPO_AUTOMATIZADO", technical)
        brief = json.loads(report.render(data, "json"))
        self.assertEqual(brief["limitations_count"], len(data["limitations"]))
        self.assertEqual(brief["container_coverage"]["docker"], "FERRAMENTA_AUSENTE")
        self.assertEqual(brief["container_coverage"]["podman"], "CONSULTA_FALHOU")
        self.assertEqual(brief["container_coverage"]["lxc"], "SEM_RELACIONADOS_INTERIOR_NAO_INSPECIONADO")
        self.assertEqual(brief["verification"], data["verification"])

    def test_verificacao_sanitizada_rejeita_texto_arbitrario(self):
        found, assessed = corrected_inventory()
        data = report.build(found, assessed, None)
        data["verification"] = {"status": "PRIVATE_MARKER", "reason_codes": ["PRIVATE_MARKER", {"secret": "PRIVATE_MARKER"}],
                                "http_test_performed": "PRIVATE_MARKER"}
        for fmt in ("txt", "md", "json"):
            self.assertNotIn("PRIVATE_MARKER", report.render(data, fmt))
        self.assertEqual(report.sanitized(data)["verification"]["status"], "INCONCLUSIVO")

    def test_ausencia_relacionados_diferente_de_interior_nao_inspecionado(self):
        for engine in ("docker", "podman"):
            with self.subTest(engine=engine):
                outputs = {("docker", "ps", "--format", "{{json .}}"): (0, "", ""),
                           ("podman", "ps", "--format", "{{json .}}"): (0, "", ""),
                           ("lxc-ls", "--active", "-1"): (0, "", "")}
                _, empty = discovery.containers(FakeSystem(outputs))
                self.assertIn("nenhum contêiner relacionado", empty[engine])
                outputs[(engine, "ps", "--format", "{{json .}}")] = (0, '{"ID":"synthetic","Image":"php:8.5","Command":"php-fpm"}\n', "")
                found, coverage = discovery.containers(FakeSystem(outputs))
                self.assertEqual(len(found), 1)
                self.assertIn("contêiner relacionado identificado", coverage[engine])
                self.assertIn("interior não inspecionado", coverage[engine])
                self.assertEqual(found[0]["status"], "INDETERMINADO")

    def test_metadados_invalidos_ou_excedentes_mantem_cobertura_incompleta(self):
        valid = '{"ID":"synthetic","Image":"php:8.5","Command":"php-fpm"}\n'
        for metadata in (valid + 'not-json\n', valid + '[]\n', valid + '{}\n',
                         valid + '[' * 1100 + '0' + ']' * 1100 + '\n', valid * 201):
            with self.subTest(metadata_length=len(metadata)):
                outputs = {("docker", "ps", "--format", "{{json .}}"): (0, metadata, ""),
                           ("podman", "ps", "--format", "{{json .}}"): (0, "", ""),
                           ("lxc-ls", "--active", "-1"): (0, "", "")}
                found, coverage = discovery.containers(FakeSystem(outputs))
                self.assertTrue(found)
                self.assertLessEqual(len(found), 200)
                self.assertIn("incompleta", coverage["docker"])

    def test_acesso_negado_na_execucao_da_ferramenta(self):
        outputs = {("docker", "ps", "--format", "{{json .}}"): (127, "", "PermissionError"),
                   ("podman", "ps", "--format", "{{json .}}"): (127, "", "FileNotFoundError"),
                   ("lxc-ls", "--active", "-1"): (1, "", "PRIVATE_MARKER")}
        _, coverage = discovery.containers(FakeSystem(outputs))
        self.assertIn("acesso à ferramenta negado", coverage["docker"])
        self.assertIn("consulta falhou", coverage["lxc"])
        self.assertNotIn("PRIVATE_MARKER", str(coverage))

    def test_codigos_plan_e_outros_comandos_preservados(self):
        found, assessed = corrected_inventory()
        for operation in ("audit", "report"):
            with self.subTest(operation=operation):
                code, data, _, _ = self.invoke(found, assessed, operation)
                self.assertEqual(code, 0)
                self.assertNotIn("verification", data)
        for containers, proc, expected in (([], "completa", 0), ([], "incompleta: /proc", 2),
                                           ([{"engine": "docker"}], "completa", 2)):
            with self.subTest(containers=containers, proc=proc):
                found["containers"] = containers
                found["coverage"]["processos"] = proc
                output = io.StringIO()
                with patch.object(cli, "System", return_value=FakeSystem()), \
                     patch.object(cli, "discover", return_value=found), \
                     patch.object(cli, "evaluate", return_value=assessed), contextlib.redirect_stdout(output):
                    self.assertEqual(cli.main(["plan"]), expected)
                self.assertFalse(json.loads(output.getvalue())["approved_possible"])
        self.assertFalse(remediation.REMEDIATION_VALIDATED)

    def test_sem_php_e_ferramentas_opcionais_ausentes_nao_vira_vulnerabilidade(self):
        found, _ = corrected_inventory()
        found["packages"] = []
        found["host_php"] = False
        found["coverage"]["contêineres"] = {engine: "incompleta: ferramenta ausente" for engine in ("docker", "podman", "lxc")}
        code, data, _, _ = self.invoke(found, [], operation="report")
        self.assertEqual((code, data["vulnerability_status"]), (0, "NÃO APLICÁVEL"))
        for engine in ("docker", "podman", "lxc"):
            self.assertTrue(any(engine in note for note in data["limitations"]))


if __name__ == "__main__":
    unittest.main()
