# Governança e classificação das informações

Este projeto destina-se à distribuição pública. O responsável define objetivos, autoriza decisões críticas e controla a publicação. Contribuidores podem tomar decisões rotineiras de implementação dentro dos requisitos aprovados; mudanças fundamentais exigem autorização explícita conforme `AGENTS.md`.

## Classificação

| Classe | Destino | Exemplos |
|---|---|---|
| **PÚBLICO** | Repositório do projeto | Código, documentação, testes sintéticos, decisões técnicas sanitizadas, limitações, changelog e resultados de validação revisados |
| **PRIVADO** | Armazenamento interno separado | Notas operacionais internas, rascunhos, hipóteses não validadas, depuração e resultados detalhados de experimentos |
| **RESTRITO** | Armazenamento privado com controle reforçado, somente se indispensável | Credenciais, dados pessoais, configurações e backups reais, evidências forenses e auditorias que revelem infraestrutura |

Não coloque materiais PRIVADOS ou RESTRITOS na árvore destinada ao Git. Relatórios gerados pela ferramenta podem conter caminhos, identificadores e achados sensíveis mesmo na versão resumida; classifique-os antes de compartilhar. Não copie dados RESTRITOS apenas para reorganizá-los. Em dúvida, mantenha a informação fora da publicação e solicite avaliação do responsável.

## Separação e retenção

Se forem necessários registros internos, use um diretório privado **fora da raiz Git e de qualquer árvore sincronizada publicamente**. Confirme antes a localização, o proprietário e a ausência de sincronização externa; restrinja permissões, organize por finalidade, evite duplicação e não guarde credenciais em texto puro. Não crie esse diretório sem material que justifique seu uso. Evidências originais de sistemas reais permanecem privadas e protegidas. Resultados reais só podem entrar na documentação pública após revisão, sanitização e autorização expressa.

A ausência de registros internos no repositório não deve prejudicar a manutenção: documente publicamente as decisões de arquitetura e segurança, suas razões e limitações, sem publicar diálogos, hipóteses descartadas ou detalhes de ambientes reais.

## Publicação e incidentes

Desenvolver e testar localmente não autoriza commit, push, criação de remoto, release, pacote publicado ou envio de arquivos a serviços externos. Essas operações dependem de autorização específica. A [auditoria de publicação](auditoria_publicacao.md) prepara a decisão, mas não a substitui.

Se houver exposição acidental, interrompa a publicação e informe o responsável. Avalie alcance, revogação de credenciais e remoção segura. Não oculte o incidente nem reescreva histórico automaticamente.

## Créditos

Projeto PHP Security Auditor.
