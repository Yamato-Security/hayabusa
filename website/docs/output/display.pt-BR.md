# Exibição e Resumo da Saída

## Barra de Progresso

A barra de progresso só funciona com múltiplos arquivos evtx.
Ela exibe em tempo real o número e a porcentagem de arquivos evtx cuja análise foi concluída.

## Saída Colorida

Os alertas serão exibidos em cores com base no `level` do alerta.
Você pode alterar as cores padrão no arquivo de configuração em `./config/level_color.txt`, no formato `level,(RGB 6-digit ColorHex)`.
Se quiser desativar a saída colorida, você pode usar a opção `-K, --no-color`.

## Resumo dos Resultados

O total de eventos, o número de eventos com detecções, métricas de redução de dados, total de detecções e detecções únicas, datas com mais detecções, principais computadores com detecções e principais alertas são exibidos após cada varredura.

### Linha do Tempo de Frequência de Detecções

Se você adicionar a opção `-T, --visualize-timeline`, o recurso Event Frequency Timeline exibe uma linha do tempo de frequência em formato sparkline dos eventos detectados.
Observação: É necessário haver mais de 5 eventos. Além disso, os caracteres não serão renderizados corretamente no Prompt de Comando ou no Prompt do PowerShell padrão, portanto utilize um terminal como o Windows Terminal, iTerm2, etc...
