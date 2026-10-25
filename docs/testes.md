# Testes e evidências de validação

Os testes automatizados usam objetos simulados, arquivos temporários e processos locais limitados por timeout. Não conectam a servidores de produção nem executam instalação APT. Para reproduzir a suíte no diretório do projeto:

```bash
python3 -m unittest discover -s tests -q
python3 -m compileall -q php_security_auditor tests tools
python3 -m php_security_auditor.cli --help
```

A suíte atual contém 151 testes e também é executada em cópia sem `.git`. Os testes de timeout executam somente processos Python locais de duração limitada; não chamam APT para instalar pacotes. A sintaxe Python e o conteúdo de pacotes gerados devem ser verificados novamente antes de distribuir a ferramenta.

O workflow `.github/workflows/ci.yml` executa a suíte, a sintaxe Python, a consistência entre a versão da CLI e `pyproject.toml` e a ajuda da CLI em Python 3.10 e 3.12, no runner `ubuntu-24.04`. Ele roda em PRs para `main`, pushes em `main` e acionamento manual, com token limitado a `contents: read`. Não usa APT, não instala dependências Python nem executa auditoria ou remediação no runner. O pacote de fontes continua sujeito à conferência separada antes de distribuição; CI local ou remoto não demonstra funcionamento operacional nas distribuições suportadas.

| Cenário | Evidência automatizada |
|---|---|
| Sem PHP, PHP corrigido, PHP vulnerável, versões simultâneas e uso apenas CLI | Descoberta e avaliação com saídas `dpkg` simuladas |
| Apache mod_php, PHP-FPM e contêiner | Serviços e metadados de contêiner simulados; nenhum `exec` no contêiner |
| Backport, versão desconhecida e origem enganosa | Comparação `dpkg` simulada e política APT com fontes oficiais e terceiras |
| Logs ausentes, rotacionados e linhas maliciosas | Arquivos temporários, gzip e teste de ausência de execução |
| Falta de acesso, disco cheio, falha de backup e link simbólico | Respostas simuladas e arquivos temporários com manifesto e SHA-256 |
| Interrupção do APT e erro de validação/módulos | Timeout local e transação APT simulada que para na falha |
| Solicitação de rollback | Sessão inválida recusada; a operação não restaura configurações nesta versão |
| Auditoria padrão sem alteração | `cli.main([])` com descoberta simulada; backup e remediação não são chamados |
| Revisão antes da autorização | Mock comprova que investigação, limites e riscos aparecem antes da pergunta; achado alto e coleta insuficiente bloqueiam |
| Relatórios sanitizados | Marcadores sintéticos não aparecem em TXT, JSON e Markdown resumidos; permanecem no JSON técnico privado |
| Período e cobertura | Datas Apache/PHP/Nginx, offset, registro antigo, ausência de data, gzip e arquivo ignorado |
| Destinos e pacote de fontes | Árvore Git fictícia isolada e pasta pública recusadas; manifesto de TAR.GZ sintético rejeita `.pyc` |
| Origem, cobertura e preservação | Testes sintéticos cobrem fonte APT local misturada, falha de listagem, cobertura temporal insuficiente, rotação de log, limite de preservação e Markdown ativo |
| Versionamento | CLI `--version` e versão registrada no relatório usam a mesma constante |
| Contexto dos achados | Processos do hospedeiro, serviço web e linhagem PHP têm contexto distinto; sinal de upload não confirma exploração |
| Metadados e falhas de leitura | Política APT global e por pacote, runtime manual com extensão não aplicável, ciclo de vida e interrupção de subprocessos, gzip válido/truncado/corrompido e expansão limitada |
| Formatos e limites de entrada | Cabeçalhos APT com distribuição gradual e anotações inválidas, linha longa em log comum e gzip, falha excepcional ao colher subprocesso |
| Estados de `plan` | JSON e códigos de saída para ausência de PHP, cobertura parcial, runtime manual, contêiner, pacote corrigido, candidato válido ou ausente, origem incerta, falhas APT e remediação bloqueada |
| Cobertura de processos | Thread de kernel sem `exe` comprovada por metadados, processo zumbi, processo de usuário inacessível e dados malformados de `/proc` |
| Associação de runtimes | Binário e processo em `/srv`, link sem destino, cadeia de alternativas, proprietário oficial, proprietário divergente, resposta ambígua e falha de consulta `dpkg` |

Esses testes automatizados não demonstram funcionamento operacional nas distribuições anunciadas, nem substituem teste de aplicação web e revisão humana de incidente. A execução de `remediate` permanece bloqueada.

## Validação operacional em Debian 13

Validação operacional realizada em ambiente isolado com Debian 13 Trixie. Os cenários abaixo registram as configurações, a cobertura e os resultados observados na auditoria e no planejamento.

| Cenário | Configuração e cobertura | Auditoria | Planejamento | Motivo estruturado | Saída de `plan` |
|---|---|---|---|---|---|
| A — Sem PHP instalado no ambiente | Nenhum pacote PHP instalado; nenhum PHP identificado pelos métodos executados | `NÃO APLICÁVEL` | `SEM_ACAO` | `PHP_NAO_IDENTIFICADO` | `0` |
| B — PHP exclusivamente CLI | PHP `8.4.27-1~deb13u1`, pacotes oficiais Debian corrigidos, nenhum serviço web PHP identificado | `CORRIGIDO` | `SEM_ACAO` | — | `0` |
| C — Apache com PHP-FPM | PHP `8.4.27-1~deb13u1`, Apache e FPM ativos, integração HTTP funcional confirmada manualmente; exposição `HTTP provável` | `CORRIGIDO` | `SEM_ACAO` | — | `0` |
| D — Sem privilégios administrativos | Pacotes identificados e corrigidos, mas cobertura de processos incompleta por restrições de acesso a `/proc` | `INDETERMINADO` | `INCONCLUSIVO` | `COBERTURA_ESSENCIAL_INCOMPLETA` | `2` |

O cenário A não demonstra ausência de instalações em todos os caminhos possíveis ou no interior de contêineres. A confirmação HTTP do cenário C foi manual; `verify` não a executa automaticamente. Esses ensaios não incluem atualização real de pacotes vulneráveis, falhas de atualização, recuperação ou validação operacional em outras distribuições. As evidências originais e os detalhes do ambiente permanecem privados.

## Pendências observadas em laboratório

- `verify` pode retornar código `0` com validação interna incompleta. O operador deve ler o resultado e verificar cobertura, runtimes, serviços e aplicação; o código isolado não aprova atualização nem confirma segurança. Não há teste funcional HTTP automático.
- O relatório de auditoria não contabiliza corretamente todas as limitações aninhadas de Docker, Podman e LXC. A cobertura detalhada deve ser examinada; `plan` apresenta as limitações de forma estruturada.

Essas limitações devem ser tratadas em versões posteriores, com testes de regressão. A remediação operacional permanece bloqueada; consulte os detalhes em [limitações conhecidas](limitacoes.md).

## Ensaios pendentes para uma liberação futura

Em ambientes **descartáveis e isolados**, preparar instalações representativas de Debian 12/13 e de cada Ubuntu LTS anunciado, com versões PHP vulneráveis, corrigidas e extensões de outros pacotes-fonte. Registrar snapshot, versões, serviços e aplicações de teste antes de cada transação. Com autorização específica para o laboratório, verificar plano APT, origem e dependências; testar FPM, mod_php e CLI, módulos instalados, portas e respostas HTTP funcionais inofensivas. Observar reinícios realizados pelos pacotes, workers antigos, logs de erro, falhas/interrupções do APT, manifesto SHA-256 e recuperação manual das configurações. Comparar estado antes e depois, registrar limites e descartar os ambientes de teste. Antes de propor liberação, definir critérios verificáveis de cobertura essencial de logs, preservação, resultado pós-atualização e falhas aceitáveis por distribuição e integração; uma confirmação manual genérica não substitui esses critérios. A liberação do bloqueio requer revisão separada dos resultados e decisão do responsável; nenhum servidor de produção serve como bancada de teste.

## Créditos

Projeto PHP Security Auditor.
