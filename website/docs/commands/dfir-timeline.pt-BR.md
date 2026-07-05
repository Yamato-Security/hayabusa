# Comandos de Linha do Tempo DFIR

## Assistente de Varredura

Os comandos `csv-timeline` e `json-timeline` agora têm um assistente de varredura habilitado por padrão.
Isso tem o objetivo de ajudar os usuários a escolher facilmente quais regras de detecção desejam habilitar de acordo com suas necessidades e preferências.
Os conjuntos de regras de detecção a serem carregados são baseados nas listas oficiais do projeto Sigma.
Os detalhes são explicados [neste post do blog](https://blog.sigmahq.io/introducing-sigma-rule-packages-releases-76043ce42e81).
Você pode desativar facilmente o assistente e usar o Hayabusa de sua forma tradicional adicionando a opção `-w, --no-wizard`.

### Regras Core

O conjunto de regras `core` habilita regras que têm um status de `test` ou `stable` e um nível de `high` ou `critical`.
Essas são regras de alta qualidade, com alto grau de confiança e relevância, e não devem produzir muitos falsos positivos.
O status da regra é `test` ou `stable`, o que significa que nenhum falso positivo foi relatado por mais de 6 meses.
As regras corresponderão a técnicas de atacantes, atividades suspeitas genéricas ou comportamentos maliciosos.
É o mesmo que usar as opções `--exclude-status deprecated,unsupported,experimental --min-level high`.

### Regras Core+

O conjunto de regras `core+` habilita regras que têm um status de `test` ou `stable` e um nível de `medium` ou superior.
As regras `medium` geralmente precisam de ajustes adicionais, pois certas aplicações, comportamentos legítimos de usuários ou scripts de uma organização podem ser correspondidos.
É o mesmo que usar as opções `--exclude-status deprecated,unsupported,experimental --min-level medium`.

### Regras Core++

O conjunto de regras `core++` habilita regras que têm um status de `experimental`, `test` ou `stable` e um nível de `medium` ou superior.
Essas regras são de ponta.
Elas são validadas contra os arquivos evtx de referência disponíveis no projeto SigmaHQ e revisadas por múltiplos engenheiros de detecção.
Fora isso, são praticamente não testadas a princípio.
Use-as se você quiser detectar ameaças o mais cedo possível, ao custo de gerenciar um limite mais alto de falsos positivos.
É o mesmo que usar as opções `--exclude-status deprecated,unsupported --min-level medium`.

### Regras Complementares de Ameaças Emergentes (Emerging Threats - ET)

O conjunto de regras `Emerging Threats (ET)` habilita regras que têm uma tag de `detection.emerging_threats`.
Essas regras têm como alvo ameaças específicas e são especialmente úteis para ameaças atuais sobre as quais ainda não há muita informação disponível.
Essas regras não devem ter muitos falsos positivos, mas perderão relevância com o tempo.
Quando essas regras não estão habilitadas, é o mesmo que usar a opção `--exclude-tag detection.emerging_threats`.
Ao executar o Hayabusa de forma tradicional sem o assistente, essas regras serão incluídas por padrão.

### Regras Complementares de Caça a Ameaças (Threat Hunting - TH)

O conjunto de regras `Threat Hunting (TH)` habilita regras que têm uma tag de `detection.threat_hunting`.
Essas regras podem detectar atividades maliciosas desconhecidas, no entanto, normalmente terão mais falsos positivos.
Quando essas regras não estão habilitadas, é o mesmo que usar a opção `--exclude-tag detection.threat_hunting`.
Ao executar o Hayabusa de forma tradicional sem o assistente, essas regras serão incluídas por padrão.

## Filtragem de regras e registros de eventos baseada em Channel

A partir do Hayabusa v2.16.0, habilitamos um filtro baseado em Channel ao carregar arquivos `.evtx` e regras `.yml`.
O objetivo é tornar a varredura o mais eficiente possível, carregando apenas o que é necessário.
Embora seja possível haver múltiplos provedores em um único registro de eventos, não é comum ter múltiplos canais dentro de um único arquivo evtx.
(A única vez que vimos isso foi quando alguém mesclou artificialmente dois arquivos evtx diferentes para o projeto [sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx).)
Podemos usar isso a nosso favor verificando primeiro o campo `Channel` no primeiro registro de cada arquivo `.evtx` especificado para ser varrido.
Também verificamos quais regras `.yml` usam quais canais especificados no campo `Channel` da regra.
Com essas duas listas, carregamos apenas regras que usam canais que estão de fato presentes dentro dos arquivos `.evtx`.

Então, por exemplo, se um usuário quiser varrer `Security.evtx`, apenas regras que especificam `Channel: Security` serão usadas.
Não faz sentido carregar outras regras de detecção, por exemplo, regras que buscam apenas eventos no log `Application`, etc...
Observe que os campos de canal (Ex: `Channel: Security`) não são definidos **explicitamente** dentro das regras Sigma originais.
Para regras Sigma, os campos de canal e IDs de eventos são definidos **implicitamente** com os campos `service` e `category` sob `logsource`. (Ex: `service: security`)
Ao curar regras Sigma no repositório [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules), nós desabstratimos o campo `logsource` e definimos explicitamente os campos de canal e ID de evento.
Explicamos como e por que fazemos isso em profundidade [aqui](https://github.com/Yamato-Security/sigma-to-hayabusa-converter).

Atualmente, existem apenas duas regras de detecção que não têm `Channel` definido e que se destinam a varrer todos os arquivos `.evtx`, que são as seguintes:

- [Possible Hidden Shellcode](https://github.com/Yamato-Security/hayabusa-rules/blob/main/hayabusa/builtin/UnkwnChannEID_Med_PossibleHiddenShellcode.yml)
- [Mimikatz Use](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml)

Se você quiser usar essas duas regras e varrer todas as regras contra os arquivos `.evtx` carregados, então você precisará adicionar a opção `-A, --enable-all-rules` nos comandos `csv-timeline` e `json-timeline`.
Em nossos benchmarks, a filtragem de regras geralmente proporciona uma melhoria de velocidade de 20% a 10x, dependendo de quais arquivos estão sendo varridos e, é claro, usa menos memória.

A filtragem de canal também é usada ao carregar arquivos `.evtx`.
Por exemplo, se você especificar uma regra que busca eventos com um canal de `Security`, então não faz sentido carregar arquivos `.evtx` que não são do log `Security`.
Em nossos benchmarks, isso proporciona um benefício de velocidade de cerca de 10% com varreduras normais e um aumento de desempenho de até mais de 60% ao varrer com uma única regra.
Se você tiver certeza de que múltiplos canais estão sendo usados dentro de um único arquivo `.evtx`, por exemplo, alguém usou uma ferramenta para mesclar múltiplos arquivos `.evtx`, então você pode desativar essa filtragem com a opção `-a, --scan-all-evtx-files` nos comandos `csv-timeline` e `json-timeline`.

> Nota: A filtragem de canal funciona apenas com arquivos `.evtx` e você receberá um erro se tentar carregar registros de eventos de um arquivo JSON com `-J, --json-input` e também especificar `-A` ou `-a`.

## Comando `csv-timeline`

O comando `csv-timeline` criará uma linha do tempo forense de eventos no formato CSV.

```
Usage: csv-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -M, --multiline                    Output event field information in multiple rows
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in CSV format (ex: results.csv)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)
  -S, --tab-separator                Separate event field information by tabs

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### Exemplos do comando `csv-timeline`

* Execute o hayabusa contra um arquivo de registro de eventos do Windows com o perfil `standard` padrão:

```
hayabusa.exe csv-timeline -f eventlog.evtx
```

* Execute o hayabusa contra o diretório sample-evtx com múltiplos arquivos de registro de eventos do Windows com o perfil verbose:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -p verbose
```

* Exporte para um único arquivo CSV para análise posterior com LibreOffice, Timeline Explorer, Elastic Stack, etc... e inclua todas as informações de campo (Atenção: o tamanho do seu arquivo de saída se tornará muito maior com o perfil `super-verbose`!):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -o results.csv -p super-verbose
```

* Habilite o filtro EID (Event ID):

> Nota: Habilitar o filtro EID acelerará a análise em cerca de 10-15% em nossos testes, mas há a possibilidade de perder alertas.

```
hayabusa.exe csv-timeline -E -d .\hayabusa-sample-evtx -o results.csv
```

* Execute apenas as regras do hayabusa (o padrão é executar todas as regras em `-r .\rules`):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa -o results.csv -w
```

* Execute apenas as regras do hayabusa para logs que estão habilitados por padrão no Windows:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin -o results.csv -w
```

* Execute apenas as regras do hayabusa para logs do sysmon:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\sysmon -o results.csv -w
```

* Execute apenas as regras sigma:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\sigma -o results.csv -w
```

* Habilite regras descontinuadas (aquelas com `status` marcado como `deprecated`) e regras ruidosas (aquelas cujo ID de regra está listado em `.\rules\config\noisy_rules.txt`):

> Nota: Recentemente, regras descontinuadas agora estão localizadas em um diretório separado no repositório sigma, então não são mais incluídas por padrão no Hayabusa.
> Portanto, você provavelmente não tem necessidade de habilitar regras descontinuadas.

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx --enable-noisy-rules --enable-deprecated-rules -o results.csv -w
```

* Execute apenas regras para analisar logons e gere a saída no fuso horário UTC:

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -r .\rules\hayabusa\builtin\Security\LogonLogoff\Logon -U -o results.csv -w
```

* Execute em uma máquina Windows ao vivo (requer privilégios de Administrador) e detecte apenas alertas (comportamento potencialmente malicioso):

```
hayabusa.exe csv-timeline -l -m low
```

* Imprima informações detalhadas (útil para determinar quais arquivos demoram para processar, erros de análise, etc...):

```
hayabusa.exe csv-timeline -d .\hayabusa-sample-evtx -v
```

* Exemplo de saída detalhada:

Carregando regras:

```
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_run_folder.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_execution_mssql_xp_cmdshell_stored_procedure.yml
Loaded rule: rules/sigma/builtin/deprecated/proc_creation_win_susp_squirrel_lolbin.yml
Loaded rule: rules/sigma/builtin/win_alert_mimikatz_keywords.yml
```

Erros durante a varredura:
```
[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58471

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Rdms-UI%4Operational.evtx
Error: Failed to parse record number 58470

[ERROR] Failed to parse event file.
EventFile: ../logs/Microsoft-Windows-AppxPackaging%4Operational.evtx
Error: An error occurred while trying to serialize binary xml to output.
```

* Gere a saída em um formato CSV compatível para importar no [Timesketch](https://timesketch.org/):

```
hayabusa.exe csv-timeline -d ../hayabusa-sample-evtx --RFC-3339 -o timesketch-import.csv -p timesketch -U
```

* Modo de erro silencioso:
Por padrão, o hayabusa salvará mensagens de erro em arquivos de log de erro.
Se você não quiser salvar mensagens de erro, por favor adicione `-Q`.

### Avançado - Enriquecimento de Log com GeoIP

Você pode adicionar informações de GeoIP (organização ASN, cidade e país) aos campos SrcIP (IP de origem) e aos campos TgtIP (IP de destino) com os dados gratuitos de geolocalização GeoLite2.

Etapas:

1. Primeiro, cadastre-se em uma conta MaxMind [aqui](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Baixe os três arquivos `.mmdb` da [página de download](https://www.maxmind.com/en/accounts/current/geoip/downloads) e salve-os em um diretório. Os nomes dos arquivos devem ser `GeoLite2-ASN.mmdb`,	`GeoLite2-City.mmdb` e `GeoLite2-Country.mmdb`.
3. Ao executar os comandos `csv-timeline` ou `json-timeline`, adicione a opção `-G` seguida do diretório com os bancos de dados MaxMind.

* Quando `csv-timeline` é usado, as 6 colunas a seguir serão adicionalmente geradas: `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry`.
* Quando `json-timeline` é usado, os mesmos campos `SrcASN`, `SrcCity`, `SrcCountry`, `TgtASN`, `TgtCity`, `TgtCountry` serão adicionados ao objeto `Details`, mas apenas se contiverem informações.

* Quando `SrcIP` ou `TgtIP` é localhost (`127.0.0.1`, `::1`, etc...), `SrcASN` ou `TgtASN` será gerado como `Local`.
* Quando `SrcIP` ou `TgtIP` é um endereço IP privado (`10.0.0.0/8`, `fe80::/10`, etc...), `SrcASN` ou `TgtASN` será gerado como `Private`.

#### Arquivo de configuração do GeoIP

Os nomes dos campos que contêm endereços IP de origem e destino que são consultados nos bancos de dados GeoIP são definidos em `rules/config/geoip_field_mapping.yaml`.
Você pode adicionar a esta lista se necessário.
Há também uma seção de filtro neste arquivo que determina de quais eventos extrair informações de endereço IP.

#### Atualizações automáticas dos bancos de dados GeoIP

Os bancos de dados GeoIP da MaxMind são atualizados a cada 2 semanas.
Você pode instalar a ferramenta `geoipupdate` da MaxMind [aqui](https://github.com/maxmind/geoipupdate) para atualizar automaticamente esses bancos de dados.

Etapas no macOS:

1. `brew install geoipupdate`
2. Edite `/usr/local/etc/GeoIP.conf` ou `/opt/homebrew/etc/GeoIP.conf`: Coloque seu `AccountID` e `LicenseKey` que você cria após fazer login no site da MaxMind. Certifique-se de que a linha `EditionIDs` diga `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Execute `geoipupdate`.
4. Adicione `-G /usr/local/var/GeoIP` ou `-G /opt/homebrew/var/GeoIP` quando quiser adicionar informações de GeoIP.

Etapas no Windows:

1. Baixe o binário mais recente do Windows (Ex: `geoipupdate_4.10.0_windows_amd64.zip`) da página de [Releases](https://github.com/maxmind/geoipupdate/releases).
2. Edite `\ProgramData\MaxMind/GeoIPUpdate\GeoIP.conf`: Coloque seu `AccountID` e `LicenseKey` que você cria após fazer login no site da MaxMind. Certifique-se de que a linha `EditionIDs` diga `EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country`.
3. Execute o executável `geoipupdate`.

Etapas no Linux:

1. Instale com `sudo apt install geoip-update`.
2. Edite o arquivo de configuração com `sudo nano /etc/GeoIP.conf`.
3. Atualize os arquivos do banco de dados com `sudo geoipupdate`.
4. Adicione `-G /var/lib/GeoIP/` quando quiser adicionar informações de GeoIP.

### Arquivos de configuração do comando `csv-timeline`

`./rules/config/channel_abbreviations.txt`: Mapeamentos de nomes de canais e suas abreviações.

`./rules/config/default_details.txt`: O arquivo de configuração para quais informações de campo padrão (campo `%Details%`) devem ser geradas se nenhuma linha `details:` for especificada em uma regra.
Isso é baseado no nome do provedor e nos IDs de eventos.

`./rules/config/eventkey_alias.txt`: Este arquivo tem os mapeamentos de aliases de nomes curtos para campos e seus nomes de campo originais mais longos.

Exemplo:
```
InstanceID,Event.UserData.UMDFHostDeviceArrivalBegin.InstanceId
IntegrityLevel,Event.EventData.IntegrityLevel
IpAddress,Event.EventData.IpAddress
```

Se um campo não estiver definido aqui, o Hayabusa verificará automaticamente o campo sob `Event.EventData`.

`./rules/config/exclude_rules.txt`: Este arquivo tem uma lista de IDs de regras que serão excluídas do uso.
Normalmente, isso ocorre porque uma regra substituiu outra ou a regra não pode ser usada de qualquer forma.
Assim como firewalls e IDSes, qualquer ferramenta baseada em assinaturas exigirá algum ajuste para se adequar ao seu ambiente, então você pode precisar excluir permanente ou temporariamente certas regras.
Você pode adicionar um ID de regra (Exemplo: `4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6`) a `./rules/config/exclude_rules.txt` para ignorar qualquer regra que você não precise ou que não possa ser usada.

`./rules/config/noisy_rules.txt`: Este arquivo tem uma lista de IDs de regras que estão desabilitadas por padrão, mas podem ser habilitadas ao habilitar regras ruidosas com a opção `-n, --enable-noisy-rules`.
Essas regras são geralmente ruidosas por natureza ou devido a falsos positivos.

`./rules/config/target_event_IDs.txt`: Apenas os IDs de eventos especificados neste arquivo serão varridos se o filtro EID estiver habilitado.
Por padrão, o Hayabusa varrerá todos os eventos, mas se você quiser melhorar o desempenho, por favor use a opção `-E, --EID-filter`.
Isso geralmente resulta em uma melhoria de velocidade de 10~25%.

## Comando `json-timeline`

O comando `json-timeline` criará uma linha do tempo forense de eventos no formato JSON ou JSONL.
Gerar a saída em JSONL será mais rápido e terá um tamanho de arquivo menor do que JSON, então é bom se você for apenas importar os resultados para outra ferramenta como o Elastic Stack.
JSON é melhor se você for analisar manualmente os resultados com um editor de texto.
A saída CSV é boa para importar linhas do tempo menores (geralmente menos de 2GB) em ferramentas como LibreOffice ou Timeline Explorer.
JSON é melhor para uma análise mais detalhada de dados (incluindo arquivos de resultados grandes) com ferramentas como `jq`, pois os campos `Details` são separados para facilitar a análise.
(Na saída CSV, todos os campos do registro de eventos ficam em uma grande coluna `Details`, tornando a ordenação de dados, etc... mais difícil.)

```
Usage: json-timeline <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file
  -l, --live-analysis    Analyze the local C:\Windows\System32\winevt\Logs folder

General Options:
  -C, --clobber                        Overwrite files when saving
  -h, --help                           Show the help menu
  -J, --JSON-input                     Scan JSON formatted logs instead of .evtx (.json or .jsonl)
  -w, --no-wizard                      Do not ask questions. Scan for all events and alerts
  -Q, --quiet-errors                   Quiet errors mode: do not save error logs
  -x, --recover-records                Carve evtx records from slack space (default: disabled)
  -r, --rules <DIR/FILE>               Specify a custom rule directory or file (default: ./rules)
  -c, --rules-config <DIR>             Specify custom rule config directory (default: ./rules/config)
  -s, --sort                           Sort events before saving the file. (warning: this uses much more memory!)
  -t, --threads <NUMBER>               Number of threads (default: optimal number for performance)
      --target-file-ext <FILE-EXT...>  Specify additional evtx file extensions (ex: evtx_data)

Filtering:
  -E, --EID-filter                      Scan only common EIDs for faster speed (./rules/config/target_event_IDs.txt)
  -A, --enable-all-rules                Enable all rules regardless of loaded evtx files (disable channel filter for rules)
  -D, --enable-deprecated-rules         Enable rules with a status of deprecated
  -n, --enable-noisy-rules              Enable rules set to noisy (./rules/config/noisy_rules.txt)
  -u, --enable-unsupported-rules        Enable rules with a status of unsupported
  -e, --exact-level <LEVEL>             Only load rules with a specific level (informational, low, medium, high, critical)
      --exclude-category <CATEGORY...>  Do not load rules with specified logsource categories (ex: process_creation,pipe_created)
      --exclude-computer <COMPUTER...>  Do not scan specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --exclude-eid <EID...>            Do not scan specific EIDs for faster speed (ex: 1) (ex: 1,4688)
      --exclude-status <STATUS...>      Do not load rules according to status (ex: experimental) (ex: stable,test)
      --exclude-tag <TAG...>            Do not load rules with specific tags (ex: sysmon)
      --include-category <CATEGORY...>  Only load rules with specified logsource categories (ex: process_creation,pipe_created)
      --include-computer <COMPUTER...>  Scan only specified computer names (ex: ComputerA) (ex: ComputerA,ComputerB)
      --include-eid <EID...>            Scan only specified EIDs for faster speed (ex: 1) (ex: 1,4688)
      --include-status <STATUS...>      Only load rules with specific status (ex: experimental) (ex: stable,test)
      --include-tag <TAG...>            Only load rules with specific tags (ex: attack.execution,attack.discovery)
  -m, --min-level <LEVEL>               Minimum level for rules to load (default: informational)
  -P, --proven-rules                    Scan with only proven rules for faster speed (./rules/config/proven_rules.txt)
  -a, --scan-all-evtx-files             Scan all evtx files regardless of loaded rules (disable channel filter for evtx files)
      --time-offset <OFFSET>            Scan recent events based on an offset (ex: 1y, 3M, 30d, 24h, 30m)
      --timeline-end <DATE>             End time of the event logs to load (ex: "2022-02-22 23:59:59 +09:00")
      --timeline-start <DATE>           Start time of the event logs to load (ex: "2020-02-22 00:00:00 +09:00")

Output:
  -b, --disable-abbreviations        Disable abbreviations
  -G, --GeoIP <MAXMIND-DB-DIR>       Add GeoIP (ASN, city, country) info to IP addresses
  -H, --HTML-report <FILE>           Save Results Summary details to an HTML report (ex: results.html)
  -L, --JSONL-output                 Save the timeline in JSONL format (ex: -L -o results.jsonl)
  -F, --no-field-data-mapping        Disable field data mapping
      --no-pwsh-field-extraction     Disable field extraction of PowerShell classic logs
  -o, --output <FILE>                Save the timeline in JSON format (ex: results.json)
  -p, --profile <PROFILE>            Specify output profile
  -R, --remove-duplicate-data        Duplicate field data will be replaced with "DUP"
  -X, --remove-duplicate-detections  Remove duplicate detections (default: disabled)

Display Settings:
  -K, --no-color            Disable color output
  -N, --no-summary          Do not display Results Summary for faster speed
  -q, --quiet               Quiet mode: do not display the launch banner
  -v, --verbose             Output verbose information
  -T, --visualize-timeline  Output event frequency timeline (terminal needs to support unicode)

Time Format:
      --European-time     Output timestamp in European time format (ex: 22-02-2022 22:00:00.123 +02:00)
  -O, --ISO-8601          Output timestamp in original ISO-8601 format (ex: 2022-02-22T10:10:10.1234567Z) (Always UTC)
      --RFC-2822          Output timestamp in RFC 2822 format (ex: Fri, 22 Feb 2022 22:00:00 -0600)
      --RFC-3339          Output timestamp in RFC 3339 format (ex: 2022-02-22 22:00:00.123456-06:00)
      --US-military-time  Output timestamp in US military time format (ex: 02-22-2022 22:00:00.123 -06:00)
      --US-time           Output timestamp in US time format (ex: 02-22-2022 10:00:00.123 PM -06:00)
  -U, --UTC               Output time in UTC format (default: local time)
```

### Exemplos e arquivos de configuração do comando `json-timeline`

As opções e arquivos de configuração para `json-timeline` são os mesmos que `csv-timeline`, mas com uma opção extra `-L, --JSONL-output` para gerar a saída no formato JSONL.

## Comando `level-tuning`

O comando `level-tuning` permitirá que você ajuste os níveis de alerta das regras, aumentando ou diminuindo o nível de risco conforme desejar.
Este comando usa um arquivo de configuração para sobrescrever os níveis de risco (o campo `level`) das regras na pasta `rules`.

> Atenção: toda vez que você executar o comando `update-rules`, o nível de risco será retornado ao valor original, então você precisará executar o comando `level-tuning` novamente em seguida.

```
Usage: level-tuning [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -f, --file <FILE>  Tune alert levels (default: ./rules/config/level_tuning.txt)
  -h, --help         Show the help menu
```

### Exemplos do comando `level-tuning`

* Uso normal: `hayabusa.exe level-tuning`
* Ajuste os níveis de alerta das regras com base no seu arquivo de configuração personalizado: `hayabusa.exe level-tuning -f ./config/level_tuning.txt`

### Arquivo de configuração do `level-tuning`

Os autores de regras do Hayabusa e do Sigma estimarão o nível de risco apropriado do alerta ao escrever suas regras.
No entanto, às vezes os níveis de risco não são consistentes e também o nível de risco real pode diferir de acordo com o seu ambiente.
A Yamato Security fornece e mantém um arquivo de configuração em `./rules/config/level_tuning.txt` que você também pode usar para ajustar suas regras.

Amostra de `./rules/config/level_tuning.txt`:

```csv
id,new_level
570ae5ec-33dc-427c-b815-db86228ad43e,informational # 'Application Uninstalled' - Originally low.
b6ce0b2f-593b-5e1c-e137-d30b2974e30e,high # 'Suspicious Double Extension File Execution' - Sysmon 1 - Originally critical
452b2159-5e6e-c494-63b9-b385d6195f58,high # 'Suspicious Double Extension File Execution' - Security 4688 - Originally critical
51ba8477-86a4-6ff0-35fa-7b7f1b1e3f83,high # 'CobaltStrike Service Installations - System' - System 7045 - Originally critical
daad2203-665f-294c-6d2f-f9272c3214f2,critical # 'Mimikatz DC Sync' - Security 4662 - Originally high
8b061ac2-31c7-659d-aa1b-36ceed1b03f1,high # 'HackTool - Rubeus Execution' - Sysmon 1 - Originally critical
be670d5c-31eb-7391-4d2e-d122c89cd5bb,high # 'HackTool - Rubeus Execution' - Security 4688 - Originally critical
```

Neste caso, o nível de risco da regra com um `id` de `570ae5ec-33dc-427c-b815-db86228ad43e` no diretório de regras terá seu `level` reescrito para `informational`.
Os níveis possíveis de definir são `critical`, `high`, `medium`, `low` e `informational`.

> Atenção: O arquivo de configuração `./rules/config/level_tuning.txt` também será atualizado para a versão mais recente no repositório hayabusa-rules toda vez que você executar `update-rules`.
> Portanto, se você fizer alterações neste arquivo, perderá essas alterações!
> Se você quiser manter um arquivo de configuração para você, então crie um arquivo de configuração em `./config/level_tuning.txt` e execute `hayabusa.exe level-tuning -f ./config/level_tuning.txt`.
> Você também pode primeiro fazer o ajuste de nível com o arquivo de configuração fornecido pela Yamato Security e depois ajustar ainda mais com seu próprio arquivo de configuração.

## Comando `list-profiles`

```
Usage: list-profiles [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

## Comando `set-default-profile`

```
Usage: set-default-profile [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help               Show the help menu
  -p, --profile <PROFILE>  Specify output profile
```

### Exemplos do comando `set-default-profile`

* Defina o perfil padrão como `minimal`: `hayabusa.exe set-default-profile minimal`
* Defina o perfil padrão como `super-verbose`: `hayabusa.exe set-default-profile super-verbose`

## Comando `update-rules`

O comando `update-rules` sincronizará a pasta `rules` com o [repositório github de regras do Hayabusa](https://github.com/Yamato-Security/hayabusa-rules), atualizando as regras e os arquivos de configuração.

```
Usage: update-rules [OPTIONS]

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help              Show the help menu
  -r, --rules <DIR/FILE>  Specify a custom rule directory or file (default: ./rules)
```

### Exemplo do comando `update-rules`

Você normalmente apenas executará isto: `hayabusa.exe update-rules`
