# Curadoria de Regras Sigma para Logs de Eventos do Windows

Esta página documenta como a Yamato Security faz a curadoria das regras [Sigma](https://github.com/SigmaHQ/sigma) originais para logs de eventos do Windows, transformando-as em um formato mais utilizável ao desabstrair o campo `logsource` e filtrar as regras que são inutilizáveis ou difíceis de usar. Isso é feito com a ferramenta [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter), usada principalmente para criar o conjunto de regras Sigma curadas hospedado no [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules). Esse conjunto de regras é usado pelo [Hayabusa](https://github.com/Yamato-Security/hayabusa) e pelo [Velociraptor](https://github.com/Velocidex/velociraptor).

!!! info "Origem"
    Esta documentação é mantida junto com a ferramenta de conversão em [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter). Esperamos que essas informações também sejam úteis para outros projetos que queiram usar regras Sigma para detectar ataques em logs de eventos do Windows. Veja também [Criando arquivos de regras](creating-rules.md) e [Modificadores de campo](field-modifiers.md).

## TL;DR

* Desabstrair o campo `logsource` e criar novos arquivos de regra `.yml` tanto para as regras integradas (built-in) quanto para as regras originais baseadas no Sysmon torna o suporte completo a eventos integrados mais fácil para as regras Sigma, além de deixar as regras mais fáceis de ler pelos analistas.
* Ao escrever regras Sigma para logs de eventos do Windows, é importante entender as diferenças entre os logs originais baseados no Sysmon e os logs integrados compatíveis e, idealmente, escrever suas regras de forma que sejam compatíveis com ambos.
* Muitas organizações não conseguem ou não querem instalar e manter agentes do Sysmon em todos os seus endpoints Windows, seja porque não têm recursos dedicados para lidar com isso, seja porque querem evitar o risco de lentidões ou travamentos causados pelo Sysmon. Por isso, é importante habilitar o maior número possível de logs de eventos integrados e usar ferramentas capazes de detectar ataques nesses logs integrados.

## Desafios com as regras Sigma originais para logs de eventos do Windows

O principal desafio para criar um analisador (parser) Sigma nativo para logs de eventos do Windows, em nossa experiência, tem sido dar suporte ao campo `logsource`. Atualmente, essa é uma das poucas coisas que o Hayabusa ainda não suporta nativamente, pois continua sendo muito complexa e é um trabalho em andamento. Por enquanto, contornamos isso convertendo as regras originais para um formato mais fácil de usar, conforme explicado em detalhes abaixo.

### Sobre o campo `logsource`

Nas regras Sigma para logs de eventos do Windows, o campo `product` é definido como `windows`, seguido por um campo `service` ou um campo `category`.

Exemplo de campo `service`:

```yaml
logsource:
    product: windows
    service: application
```

Exemplo de campo `category`:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Campos service

Os campos `service` são relativamente simples de tratar e informam ao backend que estiver usando a regra Sigma para pesquisar em um único canal ou em vários canais com base no campo `Channel` do log de eventos XML do Windows.

**Exemplo de canal único**

`service: application` é a mesma coisa que adicionar uma condição de seleção `Channel: Application` à regra Sigma.

**Exemplo de múltiplos canais**

`service: applocker` atualmente cria a maior quantidade de canais para pesquisar, pois o AppLocker salva informações em quatro logs diferentes. Para pesquisar corretamente apenas os logs do AppLocker, é necessário adicionar a seguinte condição à lógica da regra Sigma:

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**Lista atual de mapeamentos de service**

| Service                                    | Channel                                                                                                                             |
|--------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| application                                | Application                                                                                                                         |
| application-experience                     | Microsoft-Windows-Application-Experience/Program-Telemetry, Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant |
| applocker                                  | Microsoft-Windows-AppLocker/MSI and Script, Microsoft-Windows-AppLocker/EXE and DLL, Microsoft-Windows-AppLocker/Packaged app-Deployment, Microsoft-Windows-AppLocker/Packaged app-Execution |
| appmodel-runtime                           | Microsoft-Windows-AppModel-Runtime/Admin                                                                                            |
| appxpackaging-om                           | Microsoft-Windows-AppxPackaging/Operational                                                                                         |
| bits-client                                | Microsoft-Windows-Bits-Client/Operational                                                                                           |
| capi2                                      | Microsoft-Windows-CAPI2/Operational                                                                                                 |
| certificateservicesclient-lifecycle-system | Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational                                                            |
| codeintegrity-operational                  | Microsoft-Windows-CodeIntegrity/Operational                                                                                         |
| diagnosis-scripted                         | Microsoft-Windows-Diagnosis-Scripted/Operational                                                                                    |
| dhcp                                       | Microsoft-Windows-DHCP-Server/Operational                                                                                           |
| dns-client                                 | Microsoft-Windows-DNS Client Events/Operational                                                                                     |
| dns-server                                 | DNS Server                                                                                                                          |
| dns-server-analytic                        | Microsoft-Windows-DNS-Server/Analytical                                                                                             |
| driver-framework                           | Microsoft-Windows-DriverFrameworks-UserMode/Operational                                                                             |
| firewall-as                                | Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                                                  |
| hyper-v-worker                             | Microsoft-Windows-Hyper-V-Worker                                                                                                     |
| kernel-event-tracing                       | Microsoft-Windows-Kernel-EventTracing                                                                                               |
| kernel-shimengine                          | Microsoft-Windows-Kernel-ShimEngine/Operational, Microsoft-Windows-Kernel-ShimEngine/Diagnostic                                     |
| ldap_debug                                 | Microsoft-Windows-LDAP-Client/Debug                                                                                                 |
| lsa-server                                 | Microsoft-Windows-LSA/Operational                                                                                                   |
| microsoft-servicebus-client                | Microsoft-ServiceBus-Client                                                                                                         |
| msexchange-management                      | MSExchange Management                                                                                                               |
| ntfs                                       | Microsoft-Windows-Ntfs/Operational                                                                                                  |
| ntlm                                       | Microsoft-Windows-NTLM/Operational                                                                                                  |
| openssh                                    | OpenSSH/Operational                                                                                                                 |
| powershell                                 | Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational                                                                |
| powershell-classic                         | Windows PowerShell                                                                                                                  |
| printservice-admin                         | Microsoft-Windows-PrintService/Admin                                                                                                |
| printservice-operational                   | Microsoft-Windows-PrintService/Operational                                                                                          |
| security                                   | Security                                                                                                                            |
| security-mitigations                       | Microsoft-Windows-Security-Mitigations*                                                                                             |
| shell-core                                 | Microsoft-Windows-Shell-Core/Operational                                                                                            |
| smbclient-connectivity                     | Microsoft-Windows-SmbClient/Connectivity                                                                                            |
| smbclient-security                         | Microsoft-Windows-SmbClient/Security                                                                                                |
| system                                     | System                                                                                                                              |
| sysmon                                     | Microsoft-Windows-Sysmon/Operational                                                                                                |
| taskscheduler                              | Microsoft-Windows-TaskScheduler/Operational                                                                                         |
| terminalservices-localsessionmanager       | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                                                  |
| vhdmp                                      | Microsoft-Windows-VHDMP/Operational                                                                                                 |
| wmi                                        | Microsoft-Windows-WMI-Activity/Operational                                                                                          |
| windefend                                  | Microsoft-Windows-Windows Defender/Operational                                                                                      |

**Fontes dos mapeamentos de service**

Criamos arquivos de mapeamento em YAML que associam services a nomes de canais, os quais mantemos e hospedamos periodicamente no repositório da ferramenta de conversão. Eles são baseados nas informações de mapeamento de service do [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml): embora esse não pareça ser um arquivo de configuração genérico oficial para uso público, parece ser o mais atualizado.

#### Campos category

A maioria dos campos `category` simplesmente adiciona uma condição para verificar determinados event IDs no campo `EventID`, além de pesquisar por um `Channel` específico. Os nomes das categorias baseiam-se principalmente nos eventos do [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), com algumas categorias adicionais para os logs integrados do PowerShell e do Windows Defender.

**Exemplo de campo category**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**Lista atual de mapeamentos de category**

Algumas categorias mapeiam para mais de um service/EventID (mostradas em **negrito**).

| Category                  | Service            | EventIDs                                                               |
|---------------------------|--------------------|-----------------------------------------------------------------------|
| antivirus                 | windefend          | 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116 |
| clipboard_change          | sysmon             | 24                                                                    |
| create_remote_thread      | sysmon             | 8                                                                     |
| create_stream_hash        | sysmon             | 15                                                                    |
| dns_query                 | sysmon             | 22                                                                    |
| driver_load               | sysmon             | 6                                                                     |
| file_block_executable     | sysmon             | 27                                                                    |
| file_block_shredding      | sysmon             | 28                                                                    |
| file_change               | sysmon             | 2                                                                     |
| file_creation             | sysmon             | 11                                                                    |
| file_delete               | sysmon             | 23, 26                                                                |
| file_delete_detected      | sysmon             | 26                                                                    |
| file_executable_detected  | sysmon             | 29                                                                    |
| image_load                | sysmon             | 7                                                                     |
| **network_connection**    | sysmon             | 3                                                                     |
| **network_connection**    | security           | 5156                                                                  |
| pipe_created              | sysmon             | 17, 18                                                                |
| process_access            | sysmon             | 10                                                                    |
| **process_creation**      | sysmon             | 1                                                                     |
| **process_creation**      | security           | 4688                                                                  |
| process_tampering         | sysmon             | 25                                                                    |
| process_termination       | sysmon             | 5                                                                     |
| ps_classic_provider_start | powershell-classic | 600                                                                   |
| ps_classic_start          | powershell-classic | 400                                                                   |
| ps_module                 | powershell         | 4103                                                                  |
| ps_script                 | powershell         | 4104                                                                  |
| raw_access_thread         | sysmon             | 9                                                                     |
| **registry_add**          | sysmon             | 12                                                                    |
| **registry_add**          | security           | 4657                                                                  |
| registry_delete           | sysmon             | 12                                                                    |
| **registry_event**        | sysmon             | 12, 13, 14                                                            |
| **registry_event**        | security           | 4657                                                                  |
| registry_rename           | sysmon             | 14                                                                    |
| **registry_set**          | sysmon             | 13                                                                    |
| **registry_set**          | security           | 4657                                                                  |
| sysmon_error              | sysmon             | 255                                                                   |
| sysmon_status             | sysmon             | 4, 16                                                                 |
| wmi_event                 | sysmon             | 19, 20, 21                                                            |

**Desafios dos campos category**

Como mostrado acima, a mesma `category` pode usar múltiplos services e event IDs (indicados em **negrito**). Isso significa que é possível usar algumas regras Sigma projetadas para `sysmon` com logs de eventos integrados `security` similares do Windows, se os campos que a regra usa também existirem no log de eventos integrado. Nesse caso, os nomes dos campos — e às vezes também os valores — podem precisar ser convertidos para corresponder aos nomes de campos e valores do log de eventos `security` integrado. Embora isso possa ser tão simples quanto renomear alguns nomes de campos para determinadas categorias, para outras categorias pode exigir diversas conversões também nos valores dos campos. Como fazemos essa conversão e a compatibilidade entre os logs `sysmon` e os logs `security` são explicadas em detalhes [abaixo](#sysmon-builtin-comparison).

**Fontes dos mapeamentos de category**

Os arquivos de mapeamento em YAML para as categorias também são hospedados no repositório da ferramenta de conversão e também se baseiam nas informações do [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml).

## Benefícios e desafios de abstrair a fonte de log

Abstrair a fonte de log e criar mapeamentos para diferentes `Channel`, `EventID` e campos no backend traz tanto benefícios quanto desafios.

### Benefícios

1. Pode ser mais fácil converter os nomes de campo `Channel` e `EventID` para os nomes de campo apropriados do backend ao converter regras Sigma para outras consultas de backend.
2. É possível consolidar duas regras em uma. Por exemplo, eventos de criação de processo podem ser registrados tanto no `Sysmon 1` quanto no `Security 4688`. Em vez de escrever duas regras que examinam canais, event IDs e campos diferentes, mas que, no restante, contêm a mesma lógica, é possível padronizar os campos para o que o Sysmon usa e, então, fazer com que um conversor de backend adicione os campos `Channel` e `EventID` e converta outras informações de campo, se necessário. Isso facilita a manutenção das regras, pois há menos regras a manter.
3. Embora seja muito raro, se uma fonte de log passar a registrar seus dados em um `Channel` ou `EventID` diferente, apenas a lógica de mapeamento precisa ser atualizada, em vez de atualizar todas as regras Sigma, facilitando a manutenção.

### Desafios

1. O que acontece se a regra Sigma original baseada no Sysmon usar um campo que não existe nos logs integrados para filtrar falsos positivos? Você deve criar a regra mesmo assim, priorizando a possível detecção, ou ignorá-la para priorizar menos falsos positivos? Idealmente, seriam necessárias duas regras com `severity`, `status` e informações de falsos positivos diferentes, para que o usuário possa lidar melhor com isso.
2. Isso torna a filtragem de regras mais difícil, pois não é possível filtrar apenas com base nos campos `Channel` ou `EventID` do arquivo `.yml` ou no caminho do arquivo da regra se o arquivo ainda não tiver sido criado — porque se trata de uma regra derivada para um log integrado, em vez da regra original do Sysmon. Além disso, como o ID da regra é o mesmo, não é possível filtrar por IDs de regra.
3. Isso torna a confirmação do alerta mais difícil quando o alerta vem de uma regra para logs integrados que foi derivada de um log do Sysmon. Os nomes e valores dos campos não vão coincidir, portanto o analista precisa entender o processo de conversão, que é um tanto complexo.
4. Isso torna a criação da lógica do backend mais complexa.

Embora não possamos fazer nada quanto ao primeiro problema, além de criar e manter novas regras quando houver um caso de uso significativo que justifique o esforço, para resolver os problemas de 2 a 4 decidimos desabstrair o campo `logsource` e criar dois conjuntos de regras para qualquer regra que possa gerar múltiplas regras. As regras que conseguem detectar ataques em logs integrados são geradas no diretório `builtin`, e as regras para o Sysmon são geradas no diretório `sysmon`.

## Exemplo de conversão

Aqui está um exemplo simples para entender melhor o processo de conversão.

**Antes da conversão** — a regra Sigma original:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**Depois da conversão** — uma regra compatível com o Hayabusa para logs do Sysmon:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 1
    selection:
        - Image|endswith: '.exe'
    condition: process_creation and selection
```

...e uma regra compatível com o Hayabusa para logs integrados do Windows:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        - NewProcessName|endswith: '.exe'
    condition: process_creation and selection
```

Como você pode ver, duas regras foram criadas: uma para os logs do Sysmon 1 e outra para os logs integrados do Security 4688. Uma nova condição `process_creation` foi adicionada com as informações de canal e event ID, e ela foi incluída no campo `condition` para exigir essa condição. Além disso, o nome do campo original `Image` foi alterado para `NewProcessName`.

## Aspectos comuns da conversão

Antes de explicar em detalhes como convertemos categorias específicas, aqui está a parte da conversão que se aplica a todas as regras.

1. Qualquer regra que tenha um ID em `ignore-uuid-list.txt` é ignorada. Atualmente, ignoramos apenas as regras que causam falsos positivos no Windows Defender por conterem palavras-chave como `mimikatz`.
2. Regras "placeholder" são ignoradas porque não podem ser usadas como estão. São regras colocadas na pasta [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) no repositório do Sigma.
3. Regras que usam modificadores de campo incompatíveis são descartadas. O Hayabusa suporta a maioria dos modificadores de campo, portanto o conversor não gera nenhuma regra que use um modificador diferente desses, a fim de evitar erros de análise (veja [Modificadores de campo](field-modifiers.md)):

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. Regras com erros de sintaxe não são convertidas.
5. As tags em regras `deprecated` e `unsupported` são atualizadas do formato V1 para o formato V2, que usa `-` em vez de `_`, a fim de manter tudo consistente e lidar mais facilmente com abreviações no Hayabusa. Exemplo: `initial_access` torna-se `initial-access`.
6. Como estamos adicionando informações de `Channel` e `EventID` às regras, criamos um novo ID UUIDv4 usando o hash MD5 do ID original, especificamos o ID original no campo `related` e marcamos o `type` como `derived`. Para regras que podem ser convertidas em múltiplas regras (`sysmon` e `builtin`), também precisamos criar novos IDs de regra para as regras `builtin` derivadas. Para isso, calculamos um hash MD5 do ID da regra `sysmon` e o usamos como ID UUIDv4. Por exemplo:

    Regra Sigma original:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    Nova regra `sysmon`:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    Nova regra `builtin`:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. Regras que detectam eventos em logs de eventos integrados do Windows são geradas no diretório `builtin`, enquanto regras que dependem de logs do Sysmon são geradas no diretório `sysmon`, com subdiretórios correspondentes aos diretórios do repositório Sigma original.

## Limitações da conversão

No momento, há apenas um [bug conhecido](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2): linhas de comentário nas regras Sigma não serão incluídas nas regras geradas, a menos que os comentários venham depois de algum código-fonte.

## Comparação de eventos do Sysmon e integrados e conversão de regras { #sysmon-builtin-comparison }

### Criação de processo

* Category: `process_creation`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `1`
* Log integrado
    * Channel: `Security`
    * Event ID: `4688`

**Comparação**

![Comparação de criação de processo](../assets/rules-doc/process_creation_comparison.png)

**Notas de conversão**

1. As informações do campo `User` precisam ser separadas nos campos `SubjectUserName` e `SubjectDomainName`.
2. O nome do campo `LogonId` muda para `SubjectLogonId`, e todas as letras no valor hexadecimal precisam ficar em minúsculas.
3. O nome do campo `ProcessId` muda para `NewProcessId`, e o valor precisa ser convertido para hexadecimal.
4. O nome do campo `Image` muda para `NewProcessName`.
5. O nome do campo `ParentProcessId` muda para `ProcessId`, e o valor precisa ser convertido para hexadecimal.
6. O nome do campo `ParentImage` muda para `ParentProcessName`.
7. O nome do campo `IntegrityLevel` muda para `MandatoryLabel`, e a seguinte conversão de valor é necessária:
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. Se a regra contiver os seguintes campos que só existem nos eventos `Security 4688`, então não criamos uma regra `Sysmon 1`:
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. Se a regra contiver os seguintes campos que só existem nos eventos `Sysmon 1`, então não criamos uma regra `Security 4688`:
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. Há uma exceção aos itens 8 e 9: mesmo que seja usado um campo que só existe em um dos eventos de log, se esse campo estiver em uma condição `OR`, você ainda deve criar essa regra. Por exemplo, a regra a seguir **não** deve gerar uma regra `Security 4688`, porque o campo `OriginalFileName` é obrigatório (lógica `AND` dentro da seleção):

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    No entanto, uma regra com a condição a seguir **deve** criar uma regra `Security 4688`, porque `OriginalFileName` é opcional (lógica `OR` dentro da seleção):

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    As coisas ficam difíceis porque seu analisador (parser) precisa entender não apenas a lógica dentro das seleções, mas também dentro do campo `condition`. Por exemplo, a regra a seguir **não deve** criar uma regra `Security 4688`, porque usa lógica `AND`:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    No entanto, a regra a seguir **deve** criar uma regra `Security 4688`, porque usa lógica `OR`:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**Outras notas**

* O campo `SubjectUserSid` no `Security 4688` mostra o SID; no entanto, na `Message` renderizada do log de eventos, ele é convertido para `DOMAIN\User`.
* Os eventos `Security 4688` podem não incluir as informações das opções de linha de comando em `CommandLine`, dependendo das configurações.
* `TokenElevationType` é exibido como está na `Message` e não é renderizado.
* `S-1-16-4096`, etc. dentro de `MandatoryLabel` é convertido para `Mandatory Label\Low Mandatory Level`, etc. na `Message` renderizada.

**Configurações do log integrado**

!!! warning "Não habilitado por padrão"
    Os importantes logs de eventos de criação de processo integrados `Security 4688` não são habilitados por padrão. Você precisa habilitar tanto os eventos `4688` quanto o registro das opções de linha de comando para poder usar a maioria das regras Sigma.

*Habilitando por política de grupo:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*Habilitando pela linha de comando:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### Conexão de rede

* Category: `network_connection`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `3`
* Log integrado
    * Channel: `Security`
    * Event ID: `5156`

**Comparação**

![Comparação de conexão de rede](../assets/rules-doc/network_connection_comparison.png)

**Notas de conversão**

1. O nome do campo `ProcessId` muda para `ProcessID`.
2. O nome do campo `Image` muda para `Application`, e `C:\` muda para `\device\harddiskvolume?\`. (Observação: como não sabemos o número do volume do disco rígido, nós o substituímos por um curinga de caractere único `?`.)
3. O valor `tcp` do campo `Protocol` muda para `6` e `udp` muda para `17`.
4. O nome do campo `Initiated` muda para `Direction`, e o valor `true` muda para `%%14593` e `false` muda para `%%14592`.
5. O nome do campo `SourceIp` muda para `SourceAddress`.
6. O nome do campo `DestinationIp` muda para `DestAddress`.
7. O nome do campo `DestinationPort` muda para `DestPort`.

**Configurações do log integrado**

!!! warning "Não habilitado por padrão"
    Os logs de conexão de rede integrados `Security 5156` não são habilitados por padrão. Eles geram uma grande quantidade de logs, o que pode sobrescrever outros logs importantes no log de eventos `Security` e, potencialmente, deixar o sistema mais lento se ele tiver um número elevado de conexões de rede. Certifique-se de que o tamanho máximo de arquivo do log `Security` esteja alto e faça testes para garantir que não haja efeitos adversos ao sistema.

*Habilitando por política de grupo:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*Habilitando pela linha de comando:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...ou o seguinte, caso você esteja usando uma localidade que não seja em inglês:

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "Veja também"
    Para saber mais sobre como habilitar os logs de eventos integrados do Windows necessários para capturar as evidências das quais essas regras dependem, consulte [Logs do Windows e Sysmon](../resources/logging.md) e o projeto [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

## Conselhos para escrever regras Sigma

!!! tip
    Se você usar qualquer campo que exista em um log `sysmon`, mas não em um log `builtin`, certifique-se de tornar esse campo opcional, para que ainda seja possível usar a regra em logs `builtin`.

Por exemplo:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

Esta seleção procura por quando o processo (`Image`) tem o nome `addinutil.exe`. O problema é que um atacante poderia simplesmente renomear o arquivo para contornar a regra. O campo `OriginalFileName`, que só existe nos logs do Sysmon, é o nome de arquivo que fica embutido no binário no momento da compilação. Mesmo que um atacante renomeie o arquivo, o nome embutido não muda, portanto essa regra pode detectar ataques em que o atacante tenha renomeado o arquivo ao usar o Sysmon, e também pode detectar ataques em que o nome do arquivo não tenha sido alterado ao usar os logs integrados padrão.

## Regras Sigma pré-convertidas

As regras Sigma curadas da maneira descrita nesta página — desabstraindo o campo `logsource` — são hospedadas no repositório [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules), na pasta `sigma`.

## Ambiente da ferramenta

Se você quiser converter regras Sigma para o formato compatível com o Hayabusa localmente, primeiro precisa instalar o [Poetry](https://python-poetry.org/). Consulte a [documentação de instalação](https://python-poetry.org/docs/#installation) oficial do Poetry.

## Uso da ferramenta

`sigma-to-hayabusa-converter.py` é nossa principal ferramenta para converter o campo `logsource` das regras Sigma para o formato compatível com o Hayabusa. Execute as seguintes tarefas para rodá-la:

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

Após executar os comandos acima, as regras convertidas para o formato compatível com o Hayabusa serão geradas no diretório `./converted_sigma_rules`.

## Autores

Este documento foi criado por Zach Mathis (@yamatosecurity) e traduzido para o japonês por Fukusuke Takahashi (@fukusuket).

A implementação e a manutenção da ferramenta `sigma-to-hayabusa-converter.py` são feitas por Fukusuke Takahashi.

A ferramenta de conversão original, que dependia da agora obsoleta ferramenta `sigmac`, foi implementada por ItiB ([@itiB_S144](https://x.com/itib_s144)) e James Takai / hachiyone (@hach1yon).
