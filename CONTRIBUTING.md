# Guia de contribuição

Contribuições devem preservar o caráter defensivo do PHP Security Auditor e apresentar evidências reproduzíveis. Antes de propor alterações, consulte o [README](README.md), as [limitações conhecidas](docs/limitacoes.md) e as [diretrizes do repositório](AGENTS.md).

## Propostas e alterações

Prefira mudanças pequenas, com objetivo e impacto claros. Justifique novas dependências e atualize a documentação afetada. Mudanças nas regras de vulnerabilidade ou na avaliação de pacotes devem citar fontes primárias e respectivas datas de consulta.

A remediação operacional permanece bloqueada. Não remova mecanismos de proteção nem altere o fluxo de autorização, evidências ou recuperação sem aprovação explícita do responsável.

## Testes

Execute, a partir da raiz do projeto:

```bash
python3 -m unittest discover -s tests -q
python3 -m compileall -q php_security_auditor tests tools
python3 -m php_security_auditor.cli --help
```

Informe as versões e os ambientes efetivamente testados, os resultados e as limitações observadas. Use dados sintéticos e ambientes isolados; testes automatizados não substituem validação operacional representativa. Confirme que a auditoria padrão não modifica pacotes, serviços, configurações nem firewall.

## Segurança e confidencialidade

Não inclua credenciais, dados pessoais, infraestrutura privada, logs reais, backups ou evidências sensíveis. Revise qualquer resultado antes de compartilhar e siga a [governança das informações](docs/governanca_publicacao.md). Para relatar vulnerabilidades, consulte [SECURITY.md](SECURITY.md) e verifique se há um canal privado habilitado. Enquanto não houver canal disponível, não publique detalhes sensíveis de exploração em issues públicas.

## Commits, versões e pull requests

Use mensagens de commit curtas, em português brasileiro. Em cada proposta, descreva a motivação, os riscos, os testes executados e a documentação modificada.

O [changelog](CHANGELOG.md) apresenta a versão inaugural `0.1.0`; após o primeiro lançamento, registre alterações relevantes para versões futuras sob **Não lançado** até sua aprovação. Uma versão identificada no código não significa que exista uma release publicada.

A criação de commits, o envio ao remoto, o merge, a criação de tags e a publicação dependem das autorizações aplicáveis do responsável. A [auditoria de publicação](docs/auditoria_publicacao.md) prepara a decisão, mas não autoriza essas operações.

## Créditos

Projeto PHP Security Auditor.
