"""Resultados e códigos de saída de plan com dados exclusivamente sintéticos."""
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from php_security_auditor import cli, discovery, remediation


class FakeSystem:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.calls = []

    def run(self, args, timeout=10):
        key = tuple(args)
        self.calls.append(key)
        if key not in self.outputs:
            raise AssertionError(f"Comando inesperado: {key[0]}")
        return subprocess.CompletedProcess(args, *self.outputs[key])


def inventory(*, packages=(), binaries=(), processes=(), containers=(), coverage=None,
              distro=None, services=()):
    return {"os": distro or {"id": "ubuntu", "version": "26.04"},
            "packages": list(packages), "binaries": list(binaries),
            "processes": list(processes), "containers": list(containers),
            "services": list(services), "host_php": bool(packages or binaries or processes),
            "coverage": coverage if coverage is not None else {
                "pacotes": "completa", "processos": "completa", "serviços": "completa",
                "contêineres": {"docker": "incompleta: ferramenta indisponível"},
                "binários": "caminhos usuais; não exaustivo"},
            "methods": ["dpkg-query", "/proc", "caminhos de binários"]}


def php_package(status="VULNERÁVEL", *, origin="oficial ubuntu"):
    return {"name": "php8.4-fpm", "version": "8.4.26-1ubuntu1", "origin": origin,
            "source_package": "php8.4", "status": status, "fixed": "8.4.27-1ubuntu1"}


def dpkg_ownership(path, owner=None):
    result = (0, f"{owner}: {path}\n", "") if owner else (1, "", "não encontrado")
    return {("dpkg-query", "--search", "--", path): result}


class PlanResultTests(unittest.TestCase):
    def invoke(self, found, assessed=(), outputs=None, *, origin="oficial ubuntu", comparison=True):
        system = FakeSystem(outputs)
        output = io.StringIO()
        with patch.object(cli, "System", return_value=system), \
             patch.object(cli, "discover", return_value=found), \
             patch.object(cli, "evaluate", return_value=list(assessed)), \
             patch.object(remediation, "package_origin", return_value=origin), \
             patch.object(remediation, "compare", return_value=comparison), \
             contextlib.redirect_stdout(output):
            exit_code = cli.main(["plan"])
        return exit_code, json.loads(output.getvalue()), system.calls

    def test_sem_php_identificado_retorna_sem_acao_sem_plano_ficticio(self):
        code, data, calls = self.invoke(inventory(services=["nginx.service"]))
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (0, "SEM_ACAO", "PHP_NAO_IDENTIFICADO"))
        self.assertFalse(data["approved_possible"])
        self.assertEqual(data["packages"], [])
        self.assertEqual(data["simulation"], [])
        self.assertEqual(data["errors"], [])
        self.assertEqual(data["services"], [])
        self.assertIsNone(data["backups"])
        self.assertEqual(data["risks"], [])
        self.assertIn("pelos métodos executados", data["reason"])
        self.assertTrue(data["limitations"])
        self.assertEqual(calls, [])

    def test_falha_opcional_de_conteiner_nao_e_erro_critico_sem_indicio(self):
        code, data, calls = self.invoke(inventory())
        self.assertEqual((code, data["status"]), (0, "SEM_ACAO"))
        self.assertTrue(any("docker" in item for item in data["limitations"]))
        self.assertEqual(calls, [])

    def test_descoberta_essencial_incompleta_e_inconclusiva(self):
        for source in ("pacotes", "processos"):
            with self.subTest(source=source):
                found = inventory()
                found["coverage"][source] = "incompleta: acesso negado"
                code, data, calls = self.invoke(found)
                self.assertEqual((code, data["status"], data["reason_code"]),
                                 (2, "INCONCLUSIVO", "COBERTURA_ESSENCIAL_INCOMPLETA"))
                self.assertEqual(calls, [])

    def test_binario_php_manual_sem_pacote_e_inconclusivo(self):
        found = inventory(binaries=[{"path": "/opt/php/bin/php", "target": "/opt/php/bin/php"}])
        code, data, _ = self.invoke(found)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))

    def test_processo_php_sem_pacote_e_inconclusivo(self):
        found = inventory(processes=[{"name": "php-fpm8.4", "exe": "/opt/php/sbin/php-fpm"}])
        code, data, _ = self.invoke(found)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))

    def test_servico_php_sem_pacote_e_inconclusivo(self):
        found = inventory(services=["php8.4-fpm.service"])
        code, data, calls = self.invoke(found)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))
        self.assertEqual(calls, [])

    def test_runtime_manual_nao_e_ocultado_por_pacote_corrigido(self):
        found = inventory(packages=[php_package("CORRIGIDO")],
                          binaries=[{"path": "/usr/bin/php", "target": "/opt/php/bin/php"}])
        code, data, _ = self.invoke(found, [php_package("CORRIGIDO")],
                                    dpkg_ownership("/opt/php/bin/php"))
        self.assertEqual((code, data["status"]), (2, "INCONCLUSIVO"))

    def test_outro_ramo_em_processo_nao_e_ocultado_por_pacote_corrigido(self):
        corrected = php_package("CORRIGIDO")
        found = inventory(packages=[corrected],
                          processes=[{"name": "php-fpm8.3", "exe": "/usr/sbin/php-fpm8.3"}])
        code, data, _ = self.invoke(found, [corrected],
                                    dpkg_ownership("/usr/sbin/php-fpm8.3"))
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))

    def test_binario_php_em_srv_nao_e_coberto_por_pacote_corrigido(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cli")
        target = "/srv/php/bin/php"
        found = inventory(packages=[corrected],
                          binaries=[{"path": "/usr/bin/php", "target": target, "symlink": True}])
        code, data, calls = self.invoke(found, [corrected], dpkg_ownership(target))
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))
        self.assertIn(("dpkg-query", "--search", "--", target), calls)

    def test_processo_fpm_em_srv_nao_e_coberto_por_pacote_corrigido(self):
        corrected = php_package("CORRIGIDO")
        target = "/srv/php/sbin/php-fpm8.4"
        found = inventory(packages=[corrected],
                          processes=[{"name": "php-fpm8.4", "exe": target}])
        code, data, calls = self.invoke(found, [corrected], dpkg_ownership(target))
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))
        self.assertIn(("dpkg-query", "--search", "--", target), calls)

    def test_link_php_com_destino_indeterminado_e_inconclusivo(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cli")
        found = inventory(packages=[corrected],
                          binaries=[{"path": "/usr/bin/php", "target": "indeterminado", "symlink": True}])
        code, data, calls = self.invoke(found, [corrected])
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))
        self.assertEqual(calls, [])

    def test_alternativa_oficial_com_destino_do_pacote_corrigido_e_sem_acao(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cli")
        target = "/usr/bin/php8.4"
        found = inventory(packages=[corrected],
                          binaries=[{"path": "/usr/bin/php", "target": target, "symlink": True}])
        code, data, calls = self.invoke(found, [corrected], dpkg_ownership(target, "php8.4-cli:amd64"))
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (0, "SEM_ACAO", "PACOTES_CORRIGIDOS"))
        self.assertEqual(calls, [("dpkg-query", "--search", "--", target)])

    def test_processo_oficial_com_executavel_do_pacote_corrigido_e_sem_acao(self):
        corrected = php_package("CORRIGIDO")
        target = "/usr/sbin/php-fpm8.4"
        found = inventory(packages=[corrected],
                          processes=[{"name": "php-fpm8.4", "exe": target}],
                          services=["php8.4-fpm.service"])
        code, data, calls = self.invoke(found, [corrected], dpkg_ownership(target, "php8.4-fpm"))
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (0, "SEM_ACAO", "PACOTES_CORRIGIDOS"))
        self.assertEqual(calls, [("dpkg-query", "--search", "--", target)])

    def test_processo_php_ativo_sem_executavel_permanece_inconclusivo(self):
        corrected = php_package("CORRIGIDO")
        found = inventory(packages=[corrected], processes=[
            {"name": "php-fpm8.4", "exe": "indisponível", "state": "S"}])
        code, data, calls = self.invoke(found, [corrected])
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))
        self.assertEqual(calls, [])

    def test_processo_php_zumbi_nao_bloqueia_plano_de_pacote_vulneravel(self):
        package = php_package()
        found = inventory(packages=[package], processes=[
            {"name": "php-fpm8.4", "exe": "indisponível", "state": "Z"}])
        outputs = {
            ("apt-cache", "policy", package["name"]): (0, "Candidate: 8.4.27-1ubuntu1\n", ""),
            ("apt-get", "-s", "--no-remove", "--only-upgrade", "install",
             "php8.4-fpm=8.4.27-1ubuntu1"): (
                 0, "Inst php8.4-fpm [8.4.26] (8.4.27-1ubuntu1 Ubuntu:26.04 [amd64])\n", ""),
        }
        code, data, calls = self.invoke(found, [package], outputs)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (0, "PLANO_DISPONIVEL", "ATUALIZACAO_ELEGIVEL"))
        self.assertFalse(any(call[0] == "dpkg-query" for call in calls))

    def test_servico_php_ativo_sem_runtime_vivo_permanece_inconclusivo(self):
        corrected = php_package("CORRIGIDO")
        found = inventory(packages=[corrected], processes=[
            {"name": "php-fpm8.4", "exe": "indisponível", "state": "Z"}],
            services=["php8.4-fpm.service"])
        code, data, calls = self.invoke(found, [corrected])
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))
        self.assertEqual(calls, [])

    def test_servico_php_cgi_com_apenas_zumbi_permanece_inconclusivo(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cli")
        found = inventory(packages=[corrected], processes=[
            {"name": "php-cgi", "exe": "indisponível", "state": "Z"}],
            services=["php-cgi.service"])
        code, data, calls = self.invoke(found, [corrected])
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))
        self.assertEqual(calls, [])

    def test_servico_php_cgi_com_processo_vivo_nao_comprovado_e_inconclusivo(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cgi")
        target = "/srv/php/bin/php-cgi"
        found = inventory(packages=[corrected], processes=[
            {"name": "php-cgi", "exe": target, "state": "S"}],
            services=["php-cgi.service"])
        code, data, calls = self.invoke(found, [corrected], dpkg_ownership(target))
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))
        self.assertIn(("dpkg-query", "--search", "--", target), calls)

    def test_servico_php_cgi_com_processo_do_pacote_corrigido_e_sem_acao(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cgi")
        target = "/usr/bin/php-cgi8.4"
        found = inventory(packages=[corrected], processes=[
            {"name": "php-cgi8.4", "exe": target, "state": "S"}],
            services=["php-cgi8.4.service"])
        code, data, calls = self.invoke(found, [corrected], dpkg_ownership(target, "php8.4-cgi"))
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (0, "SEM_ACAO", "PACOTES_CORRIGIDOS"))
        self.assertIn(("dpkg-query", "--search", "--", target), calls)

    def test_servico_php_cgi_generico_aceita_processo_versionado_com_pacote(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cgi")
        target = "/usr/bin/php-cgi8.4"
        found = inventory(packages=[corrected], processes=[
            {"name": "php-cgi8.4", "exe": target, "state": "S"}],
            services=["php-cgi.service"])
        code, data, calls = self.invoke(found, [corrected], dpkg_ownership(target, "php8.4-cgi"))
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (0, "SEM_ACAO", "PACOTES_CORRIGIDOS"))
        self.assertIn(("dpkg-query", "--search", "--", target), calls)

    def test_servico_php_cgi_generico_aceita_plano_para_pacote_vulneravel(self):
        package = dict(php_package(), name="php8.4-cgi")
        target = "/usr/bin/php-cgi8.4"
        found = inventory(packages=[package], processes=[
            {"name": "php-cgi8.4", "exe": target, "state": "S"}],
            services=["php-cgi.service"])
        outputs = dpkg_ownership(target, "php8.4-cgi")
        outputs[("apt-cache", "policy", package["name"])] = (0, "Candidate: 8.4.27-1ubuntu1\n", "")
        outputs[("apt-get", "-s", "--no-remove", "--only-upgrade", "install",
                 "php8.4-cgi=8.4.27-1ubuntu1")] = (
                     0, "Inst php8.4-cgi [8.4.26] (8.4.27-1ubuntu1 Ubuntu:26.04 [amd64])\n", "")
        code, data, calls = self.invoke(found, [package], outputs)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (0, "PLANO_DISPONIVEL", "ATUALIZACAO_ELEGIVEL"))
        self.assertIn(("dpkg-query", "--search", "--", target), calls)

    def test_servico_php_cgi_versionado_nao_aceita_outro_ramo(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cgi")
        found = inventory(packages=[corrected], processes=[
            {"name": "php-cgi8.3", "exe": "/usr/bin/php-cgi8.3", "state": "S"}],
            services=["php-cgi8.4.service"])
        code, data, calls = self.invoke(found, [corrected])
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))
        self.assertEqual(calls, [])

    def test_runtime_oficial_vulneravel_ainda_pode_ter_plano(self):
        package = php_package()
        target = "/usr/sbin/php-fpm8.4"
        found = inventory(packages=[package],
                          processes=[{"name": "php-fpm8.4", "exe": target}],
                          services=["php8.4-fpm.service"])
        outputs = dpkg_ownership(target, "php8.4-fpm")
        outputs[("apt-cache", "policy", package["name"])] = (0, "Candidate: 8.4.27-1ubuntu1\n", "")
        outputs[("apt-get", "-s", "--no-remove", "--only-upgrade", "install",
                 "php8.4-fpm=8.4.27-1ubuntu1")] = (
                     0, "Inst php8.4-fpm [8.4.26] (8.4.27-1ubuntu1 Ubuntu:26.04 [amd64])\n", "")
        code, data, calls = self.invoke(found, [package], outputs)
        self.assertEqual((code, data["status"]), (0, "PLANO_DISPONIVEL"))
        self.assertIn(("dpkg-query", "--search", "--", target), calls)

    def test_pacote_proprietario_divergente_nao_comprova_runtime(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cli")
        target = "/usr/bin/php8.4"
        found = inventory(packages=[corrected], binaries=[{"path": target, "target": target}])
        code, data, _ = self.invoke(found, [corrected], dpkg_ownership(target, "php8.3-cli"))
        self.assertEqual((code, data["status"]), (2, "INCONCLUSIVO"))

    def test_falha_dpkg_query_nao_comprova_runtime(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cli")
        target = "/usr/bin/php8.4"
        found = inventory(packages=[corrected], binaries=[{"path": target, "target": target}])
        code, data, _ = self.invoke(found, [corrected],
                                    {("dpkg-query", "--search", "--", target): (127, "", "falha")})
        self.assertEqual((code, data["status"]), (2, "INCONCLUSIVO"))

    def test_multiplos_proprietarios_nao_comprovam_runtime(self):
        corrected = dict(php_package("CORRIGIDO"), name="php8.4-cli")
        target = "/usr/bin/php8.4"
        found = inventory(packages=[corrected], binaries=[{"path": target, "target": target}])
        output = f"php8.4-cli, outro-pacote: {target}\n"
        code, data, _ = self.invoke(found, [corrected],
                                    {("dpkg-query", "--search", "--", target): (0, output, "")})
        self.assertEqual((code, data["status"]), (2, "INCONCLUSIVO"))

    def test_frankenphp_nao_e_ocultado_por_pacote_corrigido(self):
        corrected = php_package("CORRIGIDO")
        found = inventory(packages=[corrected], services=["frankenphp.service"])
        code, data, _ = self.invoke(found, [corrected])
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "RUNTIME_NAO_AVALIADO"))

    def test_conteiner_com_php_indicado_bloqueia_conclusao_do_host(self):
        found = inventory(containers=[{"engine": "docker", "image": "php:8.4", "status": "INDETERMINADO"}])
        code, data, calls = self.invoke(found)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "CONTEINER_NAO_INSPECIONADO"))
        self.assertEqual(calls, [])

    def test_pacotes_corrigidos_nao_simulam_atualizacao(self):
        found = inventory(packages=[php_package("CORRIGIDO")])
        code, data, calls = self.invoke(found, [php_package("CORRIGIDO")])
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (0, "SEM_ACAO", "PACOTES_CORRIGIDOS"))
        self.assertEqual(calls, [])
        self.assertIsNone(data["backups"])

    def test_extensao_nao_aplicavel_nao_vira_runtime_vulneravel(self):
        extension = {"name": "php8.4-xdebug", "status": "NÃO APLICÁVEL"}
        code, data, calls = self.invoke(inventory(packages=[extension]), [extension])
        self.assertEqual((code, data["status"]), (0, "SEM_ACAO"))
        self.assertEqual(calls, [])

    def test_origem_indeterminada_nao_e_sem_acao(self):
        uncertain = php_package("INDETERMINADO", origin="não comprovada")
        code, data, calls = self.invoke(inventory(packages=[uncertain]), [uncertain])
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "INCONCLUSIVO", "VERSAO_INDETERMINADA"))
        self.assertEqual(calls, [])

    def test_cobertura_essencial_incompleta_bloqueia_ate_candidato_valido(self):
        package = php_package()
        found = inventory(packages=[package])
        found["coverage"]["processos"] = "incompleta: acesso limitado ao /proc"
        code, data, calls = self.invoke(found, [package])
        self.assertEqual((code, data["status"]), (2, "INCONCLUSIVO"))
        self.assertEqual(calls, [])

    def test_pacote_marcado_vulneravel_sem_origem_comprovada_e_bloqueado(self):
        package = php_package(origin="não comprovada")
        code, data, calls = self.invoke(inventory(packages=[package]), [package])
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "BLOQUEADO", "ORIGEM_NAO_COMPROVADA"))
        self.assertEqual(calls, [])

    def test_candidato_oficial_simulado_disponibiliza_plano(self):
        package = php_package()
        apt_policy = ("apt-cache", "policy", package["name"])
        apt_simulation = ("apt-get", "-s", "--no-remove", "--only-upgrade", "install",
                          "php8.4-fpm=8.4.27-1ubuntu1")
        outputs = {apt_policy: (0, "Candidate: 8.4.27-1ubuntu1\n", ""),
                   apt_simulation: (0, "Inst php8.4-fpm [8.4.26] (8.4.27-1ubuntu1 Ubuntu:26.04 [amd64])\n", "")}
        code, data, calls = self.invoke(inventory(packages=[package]), [package], outputs)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (0, "PLANO_DISPONIVEL", "ATUALIZACAO_ELEGIVEL"))
        self.assertTrue(data["approved_possible"])
        self.assertEqual(data["packages"], ["php8.4-fpm=8.4.27-1ubuntu1"])
        self.assertIn(apt_simulation, calls)
        self.assertIn("não autoriza remediação", data["reason"])

    def test_vulneravel_sem_candidato_nao_e_sem_acao(self):
        package = php_package()
        outputs = {("apt-cache", "policy", package["name"]): (0, "Candidate: (none)\n", "")}
        code, data, calls = self.invoke(inventory(packages=[package]), [package], outputs)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "BLOQUEADO", "CANDIDATO_AUSENTE"))
        self.assertFalse(data["approved_possible"])
        self.assertFalse(any(call[0] == "apt-get" for call in calls))

    def test_consulta_apt_falha_com_estado_erro(self):
        package = php_package()
        outputs = {("apt-cache", "policy", package["name"]): (127, "", "indisponível")}
        code, data, _ = self.invoke(inventory(packages=[package]), [package], outputs)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "ERRO", "FALHA_CONSULTA_APT"))

    def test_resposta_apt_sem_candidato_unico_e_erro(self):
        package = php_package()
        outputs = {("apt-cache", "policy", package["name"]): (0, "Version table:\n", "")}
        code, data, _ = self.invoke(inventory(packages=[package]), [package], outputs)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "ERRO", "RESPOSTA_APT_INVALIDA"))

    def test_candidato_sem_origem_oficial_e_bloqueado(self):
        package = php_package()
        outputs = {("apt-cache", "policy", package["name"]): (0, "Candidate: 8.4.27-1ubuntu1\n", "")}
        code, data, _ = self.invoke(inventory(packages=[package]), [package], outputs,
                                    origin="não comprovada")
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "BLOQUEADO", "CANDIDATO_NAO_COMPROVADO"))

    def test_comparacao_dpkg_indisponivel_e_erro(self):
        package = php_package()
        outputs = {("apt-cache", "policy", package["name"]): (0, "Candidate: 8.4.27-1ubuntu1\n", "")}
        code, data, _ = self.invoke(inventory(packages=[package]), [package], outputs,
                                    comparison=None)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "ERRO", "FALHA_COMPARACAO_DPKG"))

    def test_simulacao_apt_falha_sem_aprovar_plano(self):
        package = php_package()
        outputs = {("apt-cache", "policy", package["name"]): (0, "Candidate: 8.4.27-1ubuntu1\n", ""),
                   ("apt-get", "-s", "--no-remove", "--only-upgrade", "install",
                    "php8.4-fpm=8.4.27-1ubuntu1"): (100, "", "falha sintética")}
        code, data, _ = self.invoke(inventory(packages=[package]), [package], outputs)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "ERRO", "FALHA_SIMULACAO_APT"))
        self.assertFalse(data["approved_possible"])
        self.assertNotIn("falha sintética", json.dumps(data))

    def test_simulacao_que_instala_apenas_dependencia_nao_aprova_plano(self):
        package = php_package()
        outputs = {("apt-cache", "policy", package["name"]): (0, "Candidate: 8.4.27-1ubuntu1\n", ""),
                   ("apt-get", "-s", "--no-remove", "--only-upgrade", "install",
                    "php8.4-fpm=8.4.27-1ubuntu1"):
                       (0, "Inst php8.4-common [8.4.26] (8.4.27-1ubuntu1 Ubuntu:26.04 [amd64])\n", "")}
        code, data, _ = self.invoke(inventory(packages=[package]), [package], outputs)
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "BLOQUEADO", "SIMULACAO_INCOMPLETA"))
        self.assertFalse(data["approved_possible"])

    def test_distribuicao_sem_plano_validado_e_bloqueada(self):
        code, data, calls = self.invoke(inventory(distro={"id": "outra", "version": "1"}))
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "BLOQUEADO", "DISTRIBUICAO_NAO_SUPORTADA"))
        self.assertEqual(calls, [])

    def test_falha_inesperada_no_planejamento_vira_json_e_codigo_2(self):
        output = io.StringIO()
        with patch.object(cli, "discover", return_value=inventory()), \
             patch.object(cli, "evaluate", return_value=[]), \
             patch.object(cli, "plan", side_effect=OSError("detalhe privado")), \
             contextlib.redirect_stdout(output):
            code = cli.main(["plan"])
        data = json.loads(output.getvalue())
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "ERRO", "FALHA_PLANEJAMENTO"))
        self.assertNotIn("detalhe privado", output.getvalue())

    def test_falha_inesperada_na_descoberta_vira_json_e_codigo_2(self):
        output = io.StringIO()
        with patch.object(cli, "discover", side_effect=OSError("dado sensível")), \
             contextlib.redirect_stdout(output):
            code = cli.main(["plan"])
        data = json.loads(output.getvalue())
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (2, "ERRO", "FALHA_DESCOBERTA_OU_AVALIACAO"))
        self.assertNotIn("dado sensível", output.getvalue())

    def test_remediacao_operacional_permanece_bloqueada(self):
        self.assertFalse(remediation.REMEDIATION_VALIDATED)
        with self.assertRaisesRegex(RuntimeError, "Remediação indisponível"):
            remediation.remediate(FakeSystem(), {"approved_possible": True})


class ProcessCoverageTests(unittest.TestCase):
    def snapshot(self, status, stat=None, comm="kthreadd"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "2"
            task.mkdir()
            (task / "comm").write_text(comm + "\n", encoding="utf-8")
            (task / "status").write_text(status, encoding="utf-8")
            if stat is not None:
                (task / "stat").write_text(stat, encoding="utf-8")
            with patch.object(discovery, "Path", side_effect=lambda value: root if value == "/proc" else Path(value)):
                return discovery.processes()

    def test_thread_kernel_sem_campo_kthread_usa_flags(self):
        status = "Name:\tkthreadd\nState:\tS (sleeping)\nPPid:\t0\nUid:\t0\t0\t0\t0\n"
        stat = "2 (kthreadd) S 0 0 0 0 0 2097152 0 0 0\n"
        records, coverage = self.snapshot(status, stat)
        self.assertEqual(coverage, "completa")
        self.assertEqual(records[0]["exe"], "indisponível")
        code, data, _ = PlanResultTests().invoke(inventory(coverage={"pacotes": "completa",
                                                                "processos": coverage}))
        self.assertEqual((code, data["status"]), (0, "SEM_ACAO"))

    def test_thread_kernel_com_campo_kthread(self):
        status = "Name:\tkthreadd\nState:\tS (sleeping)\nKthread:\t1\nPPid:\t0\nUid:\t0\t0\t0\t0\n"
        _, coverage = self.snapshot(status)
        self.assertEqual(coverage, "completa")

    def test_nome_de_thread_nao_dispensa_prova_de_kernel(self):
        status = "Name:\tkthreadd\nState:\tS (sleeping)\nKthread:\t0\nPPid:\t0\nUid:\t0\t0\t0\t0\n"
        stat = "2 (kthreadd) S 0 0 0 0 0 0 0 0 0\n"
        _, coverage = self.snapshot(status, stat)
        self.assertIn("incompleta", coverage)

    def test_stat_invalido_nao_oculta_falha_de_acesso(self):
        status = "Name:\tkthreadd\nState:\tS (sleeping)\nPPid:\t0\nUid:\t0\t0\t0\t0\n"
        _, coverage = self.snapshot(status, "dados inválidos")
        self.assertIn("incompleta", coverage)

    def test_zumbi_sem_exe_nao_indica_falha_de_acesso(self):
        status = "Name:\tphp-fpm8.4\nState:\tZ (zombie)\nPPid:\t1\nUid:\t33\t33\t33\t33\n"
        records, coverage = self.snapshot(status, comm="php-fpm8.4")
        self.assertEqual(coverage, "completa")
        self.assertEqual(records[0]["state"], "Z")
        corrected = php_package("CORRIGIDO")
        code, data, calls = PlanResultTests().invoke(
            inventory(packages=[corrected], processes=records), [corrected])
        self.assertEqual((code, data["status"], data["reason_code"]),
                         (0, "SEM_ACAO", "PACOTES_CORRIGIDOS"))
        self.assertEqual(calls, [])


class BinaryDiscoveryTests(unittest.TestCase):
    def test_cadeia_de_links_resolve_ate_o_executavel_final(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "php8.4"
            target.write_bytes(b"arquivo sintetico")
            alternative = root / "etc/alternatives/php"
            alternative.parent.mkdir(parents=True)
            alternative.symlink_to(target)
            link = root / "usr/bin/php"
            link.parent.mkdir(parents=True)
            link.symlink_to(alternative)
            with patch.object(discovery, "BIN_GLOBS", (str(link),)):
                found = discovery.binaries()
            self.assertEqual(found, [{"path": str(link), "target": str(target), "symlink": True}])

    def test_link_sem_destino_resolvido_permanece_indeterminado(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = root / "php"
            link.symlink_to(root / "destino-inexistente")
            with patch.object(discovery, "BIN_GLOBS", (str(link),)):
                found = discovery.binaries()
            self.assertEqual(found, [{"path": str(link), "target": "indeterminado"}])


if __name__ == "__main__":
    unittest.main()
