# Guia de utilização

Valide estes comandos em um ambiente de testes isolado antes de aplicá-los a um servidor administrado. A auditoria padrão lê estado local; relatórios e preservação só criam arquivos quando solicitados.

```bash
python3 -m php_security_auditor.cli
python3 -m php_security_auditor.cli audit --days 30 --detailed
python3 -m php_security_auditor.cli report --output "$HOME/relatorios-php"
python3 -m php_security_auditor.cli plan
```

`--days` aceita 1 a 365. Sem `--detailed`, TXT, JSON e Markdown exibem apenas campos selecionados: status, contagens e período observado. O relatório detalhado contém caminhos, processos e evidências resumidas; trate-o como privado. Revise inclusive o resumo antes de compartilhar. `--output` grava os três formatos em diretório 0700, com arquivos 0600. Destinos sob árvores Git, webroots e pastas públicas conhecidas são recusados; outras formas de sincronização exigem verificação manual. `audit --preserve` cria uma sessão de backup dos logs examinados, com manifesto SHA-256.

O período padrão de 30 dias é apenas uma triagem inicial. Para PHP exposto, avalie ampliar `--days` de modo a examinar registros desde 01/08/2026, se disponíveis, conforme a [orientação da Sophos](https://www.sophos.com/pt-br/security-advisories/sophos-sa-20261021-php2shell). Datas observadas indicam o intervalo encontrado nos arquivos lidos; não provam cobertura contínua. Achados sem data ficam identificados como de tempo desconhecido.

### Interpretação

`VULNERÁVEL` indica pacote oficial abaixo do limiar publicado para aquele sistema. `CORRIGIDO` indica que as versões dos pacotes avaliados atingem o limiar conhecido e a cobertura disponível não indica outro runtime; não comprova que todos os workers foram substituídos. `INDETERMINADO` pede verificação manual de origem, versões internas de contêineres ou cobertura. `NÃO APLICÁVEL` significa que não se identificou instalação de PHP nos ambientes efetivamente avaliados; um pacote isolado de extensão também pode ter esse status individual, pois sua versão não representa a do PHP principal. A investigação usa uma classificação separada; “sem indícios identificados” não comprova ausência de comprometimento.

### Correção assistida

`plan` produz JSON com `status`, `reason_code`, `reason`, `issues`, `coverage` e `limitations`. O campo `approved_possible` informa a elegibilidade técnica do plano. `reason_code` e os códigos em `issues` são estáveis para automação; `reason` e `errors` explicam o resultado ao operador.

| Estado de `plan` | Significado | Saída |
|---|---|---|
| `PLANO_DISPONIVEL` | Candidato oficial e dependências foram verificados na simulação. `approved_possible=true` indica elegibilidade técnica, não autorização. | `0` |
| `SEM_ACAO` | Nenhuma atualização aplicável: pacotes avaliáveis corrigidos ou nenhum runtime PHP identificado pelos métodos executados. | `0` |
| `INCONCLUSIVO` | Runtime manual, contêiner não inspecionado, versão indeterminada ou cobertura essencial insuficiente. | `2` |
| `BLOQUEADO` | Atualização necessária sem candidato seguro, distribuição não suportada, remoção ou dependência não comprovada. | `2` |
| `ERRO` | Falha operacional, como consulta ou simulação APT malsucedida. | `2` |

O código `0` significa que `plan` concluiu a avaliação disponível; não comprova ausência de PHP, comprometimento ou necessidade futura de atualização. Quando `status=SEM_ACAO`, `packages`, `simulation`, `services`, `checks` e `risks` ficam vazios; `applications`, `backups` e `recovery` ficam nulos. O resultado preserva ressalvas da descoberta. A busca de binários não é exaustiva e o interior dos contêineres não é inspecionado. Falha opcional de acesso a um mecanismo de contêiner aparece em `limitations`; falha de cobertura essencial de pacotes ou processos torna o plano inconclusivo.

Quando há binário ou processo PHP observado e pacote avaliado que poderia cobri-lo, `plan` consulta a propriedade do executável final em `dpkg-query`. Links de alternativas são seguidos até o destino; destino indeterminado, pacote proprietário não avaliado ou consulta malsucedida resultam em `INCONCLUSIVO`. Nome e ramo iguais aos de um pacote corrigido não bastam para associar o runtime. Essa consulta não verifica a integridade dos bytes do executável.

Quando há `PLANO_DISPONIVEL`, o JSON informa candidatos, dependências da simulação e riscos, inclusive scripts dos pacotes, possíveis reinícios e o uso de `DEBIAN_FRONTEND=noninteractive`. **A execução de `remediate` está bloqueada** até ensaios ponta a ponta e liberação explícita. O fluxo apresenta a investigação e os limites antes de qualquer confirmação; achados graves ou coleta essencial insuficiente impõem bloqueio adicional. Preserve evidências e acione a resposta a incidentes quando houver indícios relevantes. `--non-interactive` também bloqueia remediação.

```bash
python3 -m php_security_auditor.cli verify
python3 -m php_security_auditor.cli rollback-config --session /caminho/para/sessao
```

Em `0.1.0`, `verify` pode retornar código `0` mesmo quando apresenta `VALIDAÇÃO INCOMPLETA`. Leia o resultado e a cobertura; não use esse código isoladamente para aprovar uma atualização ou confirmar segurança. O comando não executa teste HTTP funcional automático. O relatório de auditoria também não contabiliza corretamente todas as limitações aninhadas de contêineres; examine a cobertura detalhada e as limitações estruturadas de `plan`. Consulte os detalhes em [limitações conhecidas](limitacoes.md).

O último caminho é um **EXEMPLO**; substitua pelo caminho da sessão criada. `rollback-config` valida o manifesto e informa que esta versão não altera configurações, portanto não há restauração automática. Nunca use downgrade para voltar a uma versão vulnerável.

## Créditos

Projeto PHP Security Auditor; referências de fornecedor em [pesquisa](pesquisa.md).
