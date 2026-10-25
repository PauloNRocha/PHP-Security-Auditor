# Propriedades de segurança e riscos residuais

Os controles abaixo orientam a leitura do código e a avaliação dos limites da ferramenta. A evidência automatizada utiliza dados sintéticos e ambientes isolados, conforme o [guia de testes](testes.md). Ela não comprova segurança em produção ou funcionamento de uma atualização real.

## Controles por área

| Área | Controle implementado |
|---|---|
| Backup | Ancestrais graváveis por grupo ou outros são recusados, e o proprietário deve ser confiável, reduzindo o risco de troca de diretórios durante a cópia. |
| APT | A avaliação exige metadados de origem e hostname de arquivo Debian/Ubuntu reconhecido. Cada dependência da simulação com linha `Inst` precisa de versão e origem comprovadas. Fontes locais ou desconhecidas misturadas à versão mantêm a origem indeterminada. |
| Inventário | Runtime sem pacote avaliado permanece indeterminado; a versão de uma extensão de outro pacote-fonte não representa a do PHP principal. |
| Logs | Abertura com `O_NOFOLLOW` e `O_NONBLOCK`, comparação de dispositivo, inode e tipo para reduzir trocas por links ou arquivos especiais. Falhas de acesso e de listagem aparecem como limitações. |
| Manifesto | Leitura limitada a 1 MiB, até 100 entradas, cópias de até 20 MiB e hashing em blocos. |
| Terminal e Markdown | Caracteres de controle são escapados na saída de texto, e marcação ativa proveniente do sistema auditado é escapada no relatório Markdown técnico. |
| Módulos PHP | A checagem prevista no fluxo de remediação usa o CLI oficial sob `nobody`; esse fluxo permanece bloqueado. |

## Preservação e cobertura

A preservação compara dispositivo, inode, tamanho e horário dos logs com os metadados registrados na leitura. Rotação ou mudança detectada exige nova coleta. O fluxo de remediação bloqueado também recusa transações em que mais de 100 arquivos precisariam de preservação.

Datas observadas não demonstram continuidade dos registros. A coleta automática não declara cobertura essencial comprovada para liberar atualização. Consulte a [metodologia](metodologia.md) e a [política de backups](backups.md) para limites e tratamento de falhas.

## Confidencialidade dos relatórios

TXT, JSON e Markdown resumidos usam seleção explícita de campos. Dados técnicos completos ficam no relatório detalhado privado. O comando bruto de contêiner não é incluído no relatório, pois pode conter segredos.

Destinos sob árvores Git, webroots e pastas públicas ou sincronizadas reconhecidas são recusados. A detecção não cobre toda forma de sincronização; confira o destino e revise o conteúdo antes de compartilhar qualquer relatório.

## Riscos residuais

Um sistema comprometido pode falsificar saídas locais. Metadados APT e hostname de arquivo comprovam a disponibilidade da versão no arquivo oficial, mas não a origem ou integridade dos bytes instalados. Um pacote instalado manualmente com a mesma versão continua sendo um risco residual.

A comparação de metadados reduz trocas acidentais entre análise e preservação, mas não prova a identidade criptográfica do conteúdo lido nem resiste a um administrador malicioso. O verificador de pacote de fontes examina nomes e tipos; o conteúdo ainda exige revisão antes de publicação.

Não há validação ponta a ponta da transação APT nas distribuições contempladas, prova da versão efetiva em cada worker web, correlação forense completa ou restauração automática. A remediação permanece bloqueada. Os limites de `verify` e da contabilização de limitações de contêineres estão descritos em [limitações conhecidas](limitacoes.md).

## Créditos

Projeto PHP Security Auditor.
