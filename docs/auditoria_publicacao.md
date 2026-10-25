# Auditoria pré-publicação

Execute este procedimento localmente antes da primeira publicação e repita-o quando o escopo de uma versão mudar. A auditoria é somente leitura; nenhum resultado autoriza commit, push ou release. Registre conclusões sanitizadas, sem reproduzir segredos.

## 1. Escopo e estado Git

Confirme a raiz com `git rev-parse --show-toplevel`. Em pacotes de fontes sem metadados Git, marque histórico, branches, tags e staging como **INCONCLUSIVOS**; não invente uma revisão de histórico. Em uma árvore Git, examine `git status --short`, `git ls-files`, `git diff --cached --name-only`, `git log --all --oneline`, branches, tags e remotes. Revise também arquivos não rastreados. O `.gitignore` não protege arquivos já rastreados.

## 2. Conteúdo e confidencialidade

Revise nomes e conteúdo dos arquivos públicos, inclusive documentação, exemplos, fixtures, relatórios e artefatos grandes. Procure credenciais, dados pessoais, infraestrutura privada, logs reais, backups, evidências forenses e registros operacionais internos. Revise também relatórios resumidos; o modo `--detailed` é privado. Confirme que destinos de `--output` e `--backup-dir` não estão em árvores Git ou pastas sincronizadas publicamente; a detecção automática é limitada. Use detector local de segredos, como Gitleaks, se já estiver disponível; confirme manualmente seus alertas e não trate a ausência deles como garantia. Não instale ferramentas nem envie conteúdo a serviços externos sem autorização. Se houver dados sensíveis no histórico, interrompa a preparação e proponha o tratamento ao responsável, sem reescrever histórico por conta própria.

## 3. Qualidade e segurança

- Confira `LICENSE`, permissões de arquivos e dependências declaradas em `pyproject.toml`.
- Execute os testes automatizados em ambiente isolado e registre os resultados reais; se faltarem ambientes de integração, declare a limitação.
- Confira README, `SECURITY.md`, `CHANGELOG.md`, guias, links e compatibilidade entre documentação e código.
- Revise scripts de instalação, comandos externos, backup, atualização e remediação quanto a autorização, origem dos pacotes, limites e recuperação.
- Verifique a integridade dos artefatos que serão publicados e confirme a ausência de materiais PRIVADOS e RESTRITOS.
- Para um sdist já gerado localmente, execute `python3 tools/check_sdist.py CAMINHO_DO_ARQUIVO.tar.gz`; o caminho é um **EXEMPLO**. Confira também manualmente os nomes e conteúdos. Essa inspeção não autoriza publicação.

## 4. Resultado

Classifique como **APROVADO** somente quando todos os itens aplicáveis tiverem evidência suficiente e não houver bloqueios; **APROVADO COM RESSALVAS** quando restarem limites documentados que o responsável possa aceitar; **REPROVADO** quando houver exposição ou risco impeditivo; **INCONCLUSIVO** quando faltar evidência essencial. Registre escopo, data, verificações feitas, lacunas e responsável pela decisão. Mesmo um resultado APROVADO exige autorização explícita do responsável antes de publicar.

## Créditos

Projeto PHP Security Auditor.
