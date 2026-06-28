# Recursos

* Suporte multiplataforma: Windows, Linux, macOS.
* Desenvolvido em Rust para ser seguro em memória e rápido.
* Suporte a múltiplas threads, entregando uma melhoria de velocidade de até 5x.
* Cria linhas do tempo únicas e fáceis de analisar para investigações forenses e resposta a incidentes.
* Caça a ameaças baseada em assinaturas de IoC escritas em regras hayabusa baseadas em YML, fáceis de ler/criar/editar.
* Suporte a regras Sigma para converter regras sigma em regras hayabusa.
* Atualmente suporta a maior quantidade de regras sigma em comparação com outras ferramentas similares e ainda suporta regras de contagem e novos agregadores como `|equalsfield` e `|endswithfield`.
* Métricas de computadores. (Útil para filtrar a favor/contra determinados computadores com uma grande quantidade de eventos.)
* Métricas de Event ID. (Útil para obter uma visão de quais tipos de eventos existem e para ajustar as configurações de log.)
* Configuração de ajuste de regras excluindo regras desnecessárias ou ruidosas.
* Mapeamento de táticas do MITRE ATT&CK.
* Ajuste de nível de regra.
* Cria uma lista de palavras-chave de pivô únicas para identificar rapidamente usuários, hostnames, processos anormais, etc... bem como correlacionar eventos.
* Exibe todos os campos para investigações mais aprofundadas.
* Resumo de logons bem-sucedidos e malsucedidos.
* Caça a ameaças e DFIR em toda a empresa em todos os endpoints com o [Velociraptor](https://docs.velociraptor.app/).
* Saída para CSV, JSON/JSONL e Relatórios de Resumo em HTML.
* Atualizações diárias de regras Sigma.
* Suporte para entrada de logs em formato JSON.
* Normalização de campos de log. (Convertendo múltiplos campos com diferentes convenções de nomenclatura no mesmo nome de campo.)
* Enriquecimento de logs adicionando informações de GeoIP (ASN, cidade, país) a endereços IP.
* Pesquisa todos os eventos por palavras-chave ou expressões regulares.
* Mapeamento de dados de campo. (Ex: `0xc0000234` -> `ACCOUNT LOCKED`)
* Carving de registros evtx a partir do slack space do evtx.
* Deduplicação de eventos na saída. (Útil quando a recuperação de registros está habilitada ou quando você inclui arquivos evtx de backup, arquivos evtx do VSS, etc...)
* Assistente de configuração de varredura para ajudar a escolher quais regras habilitar mais facilmente. (Para reduzir falsos positivos, etc...)
* Análise e extração de campos de logs clássicos do PowerShell.
* Baixo uso de memória. (Observação: isso é possível por não ordenar os resultados. Ideal para execução em agentes ou big data.)
* Filtragem por Channels e Rules para o desempenho mais eficiente.
* Detecta, extrai e decodifica strings Base64 encontradas em logs.
* Ajuste de nível de alerta com base em sistemas críticos.
