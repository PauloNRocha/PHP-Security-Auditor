# Política de backups e evidências

Por padrão, root usa `/root/backup/php-security-auditor/`; um usuário comum usa `$HOME/backup/php-security-auditor/`. `--backup-dir` permite outra raiz absoluta, que deve pertencer ao usuário efetivo, ter modo 0700 e ficar fora de webroots, áreas temporárias e árvores Git detectáveis. Nomes conhecidos de pastas públicas ou sincronizadas também são recusados. Essa checagem não detecta toda sincronização externa: confirme manualmente o destino. Ancestrais não podem ser graváveis por grupo ou outros. Cada sessão recebe hostname, UTC e sufixo exclusivo; subpastas separam os materiais.

Cada arquivo preservado é regular, tem no máximo 20 MiB e é aberto sem seguir link simbólico. Metadados de origem (UID, GID, modo, horário e tamanho) ficam no manifesto; a cópia fica com modo 0600. O programa calcula e verifica SHA-256 da cópia, não altera a origem, recusa fonte que muda durante a cópia e não sobrescreve sessões. O manifesto registra usuário original informado por `SUDO_USER`, UID efetivo, sistema e operações. A origem pode ser sensível; não compartilhe a pasta indiscriminadamente. A ferramenta não apaga backups.

`audit --preserve` permite preservar os logs examinados antes de qualquer mudança. A ferramenta compara dispositivo, inode, tamanho e horário registrados na leitura; se o arquivo mudou ou foi rotacionado, a cópia é recusada e deve ser feita nova coleta. Logs parcialmente analisados podem ser preservados se a identidade do arquivo permaneceu estável. O caminho preparado para remediação preservaria configurações `.ini` usuais sob `/etc/php` e todos os logs examinados, bloqueando a transação quando o total exceder 100 arquivos; a atualização continua bloqueada até validação operacional. Banco de dados e conteúdo arbitrário de aplicações não são copiados. Espaço livre mínimo é verificado antes de criar a sessão, mas pode mudar depois.

## Créditos

Projeto PHP Security Auditor.
