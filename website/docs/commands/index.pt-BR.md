# Lista de Comandos

## Comandos de Análise:
* `computer-metrics`: Exibe o número de eventos com base nos nomes dos computadores.
* `eid-metrics`: Exibe o número e a porcentagem de eventos com base no Event ID.
* `expand-list`: Extrai os marcadores `expand` da pasta `rules`.
* `extract-base64`: Extrai e decodifica strings base64 dos eventos.
* `log-metrics`: Exibe métricas de arquivos de log.
* `logon-summary`: Exibe um resumo dos eventos de logon.
* `pivot-keywords-list`: Exibe uma lista de palavras-chave suspeitas para usar como pivô.
* `search`: Pesquisa todos os eventos por palavra(s)-chave ou expressões regulares

## Comandos de Configuração:
* `config-critical-systems`: Encontra sistemas críticos como controladores de domínio e servidores de arquivos.

## Comandos de Linha do Tempo de DFIR:
* `dfir-timeline`: Salva a linha do tempo no formato CSV.
* `dfir-timeline`: Salva a linha do tempo no formato JSON/JSONL.
* `level-tuning`: Ajusta de forma personalizada o `level` dos alertas.
* `list-profiles`: Lista os perfis de saída disponíveis.
* `set-default-profile`: Altera o perfil padrão.
* `update-rules`: Sincroniza as regras com as regras mais recentes do repositório GitHub [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

## Comandos Gerais:
* `help`: Exibe esta mensagem ou a ajuda do(s) subcomando(s) informado(s)
* `list-contributors`: Exibe a lista de contribuidores
