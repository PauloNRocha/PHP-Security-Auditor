# Repository Guidelines

## Estrutura do projeto

O código fica em `php_security_auditor/`: descoberta, versões, triagem, backup, remediação, relatórios e CLI têm módulos próprios. Regras offline: `php_security_auditor/data/advisories.json`. Testes: `tests/test_*.py`. Guias: `docs/`. Empacotamento: `pyproject.toml`.

## Desenvolvimento e comandos

Use Python 3.10 ou superior. A partir da raiz:

```bash
python3 -m php_security_auditor.cli --help
python3 -m unittest discover -s tests -q
python3 -m compileall -q php_security_auditor tests
```

Os comandos mostram a interface, executam testes isolados e verificam sintaxe. Audite em laboratório com `python3 -m php_security_auditor.cli audit`. Ensaios de remediação exigem um ambiente de testes isolado e representativo, com recuperação verificável e autorização específica; não use produção como laboratório.

## Versionamento

Versões finais seguem SemVer (`X.Y.Z`) e versões de desenvolvimento seguem PEP 440 (`X.Y.Z.devN`). `php_security_auditor.VERSION` é a fonte única para a CLI e os metadados do pacote; confira ambos antes de distribuir. A entrada `[0.1.0] — Versão inicial` em `CHANGELOG.md` descreve a primeira entrega, sem implicar que foi publicada. Após o primeiro lançamento, registre alterações relevantes à próxima versão em **Não lançado** e transfira-as para uma entrada versionada quando a release for aprovada. Não incremente a versão por cada pequena correção, não invente datas nem inclua registros operacionais internos. Tags, releases e publicação de pacotes exigem autorização específica.

## Estilo e nomenclatura

Use quatro espaços, `snake_case` em módulos/funções/variáveis, `PascalCase` em classes e maiúsculas em constantes. Mensagens ao operador ficam em português brasileiro. Não há linter configurado; preserve o estilo existente.

## Testes

Use `unittest`, arquivos `test_*.py` e métodos `test_*`. Simule comandos externos com `FakeSystem` ou mocks; cubra falhas de permissão, backup e atualização. Declare somente testes executados e resultados observados. Testes isolados não provam funcionamento em serviços reais.

## Segurança

Mantenha a auditoria padrão não destrutiva e privilégios mínimos. Trate logs e metadados como não confiáveis; nunca execute evidências nem provas de conceito contra sistemas reais. Preserve evidências, valide antes/depois de mudanças e faça backups verificáveis. Remediação exige plano simulado, autorização explícita e recuperação documentada. Não remova proteções para facilitar testes. Cite fonte primária e data nas regras de vulnerabilidade.

## Commits e pull requests

Use commits curtos em português brasileiro, como `docs: esclarecer limites da auditoria`. Propostas devem explicar risco, testes e limites. **Commit, remoto, push, release e publicação de pacotes exigem autorização específica.**

## Confidencialidade e publicação

Classifique dados conforme [governança](docs/governanca_publicacao.md). Use testes sintéticos. Nunca adicione ao Git segredos, infraestrutura privada, evidências reais, backups, logs sensíveis ou registros operacionais internos. Resultados reais exigem revisão, sanitização e autorização expressa. Documente decisões técnicas e limites sem diálogos internos. Se houver exposição, interrompa a publicação e informe o responsável; não reescreva histórico automaticamente.

## Autonomia e decisões reservadas

Contribuidores podem implementar decisões compatíveis com requisitos aprovados, sem dependências injustificadas. Exigem aprovação explícita: remover proteções; mudar auditoria não destrutiva, autorização, evidências ou backup; automatizar remediação sem confirmação; quebrar a interface pública; operar em produção; ou publicar. A [auditoria pré-publicação](docs/auditoria_publicacao.md) não autoriza envio.

## Comunicação ao concluir

Informe mudanças, motivos, testes e resultados, riscos e decisões pendentes, sem dados confidenciais. `CHANGELOG.md` registra mudanças relevantes para usuários, não registros operacionais internos.
