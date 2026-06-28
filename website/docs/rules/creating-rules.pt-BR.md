# Criando Arquivos de Regras

## Sobre o Hayabusa-Rules

Este é um repositório que contém regras sigma curadas que detectam ataques em registros de eventos do Windows.
Ele é usado principalmente para as regras de detecção e arquivos de configuração do [Hayabusa](https://github.com/Yamato-Security/hayabusa), bem como para a detecção sigma integrada do [Velociraptor](https://github.com/Velocidex/velociraptor).
A vantagem de usar este repositório em vez do [repositório sigma upstream](https://github.com/SigmaHQ/sigma) é que incluímos apenas regras que a maioria das ferramentas sigma-native deve conseguir interpretar.
Também desabstraímos o campo `logsource` adicionando os campos `Channel`, `EventID`, etc... necessários às regras, para facilitar o entendimento do que a regra está filtrando e, mais importante, para reduzir falsos positivos.
Também criamos novas regras com nomes de campos e valores convertidos para regras `process_creation` e regras baseadas em `registry`, de modo que as regras sigma não detectem apenas em logs do Sysmon, mas também em logs integrados do Windows.

## Sobre a criação de arquivos de regras

As regras de detecção do Hayabusa são escritas no formato [YAML](https://en.wikipedia.org/wiki/YAML) com a extensão de arquivo `.yml`. (Arquivos `.yaml` serão ignorados.)
Elas são um subconjunto das regras sigma, mas também contêm alguns recursos adicionais.
Estamos tentando torná-las o mais próximas possível das regras sigma, para que seja fácil converter as regras do Hayabusa de volta para sigma e contribuir com a comunidade.
As regras do Hayabusa podem expressar regras de detecção complexas combinando não apenas a correspondência simples de strings, mas também expressões regulares, condições `AND`, `OR` e outras.
Nesta seção, explicaremos como escrever regras de detecção do Hayabusa.

### Formato do arquivo de regra

Exemplo:

```yaml
#Author section
author: Zach Mathis
date: 2022-03-22
modified: 2022-04-17

#Alert section
title: Possible Timestomping
details: 'Path: %TargetFilename% ¦ Process: %Image% ¦ User: %User% ¦ CreationTime: %CreationUtcTime% ¦ PreviousTime: %PreviousCreationUtcTime% ¦ PID: %PID% ¦ PGUID: %ProcessGuid%'
description: |
    The Change File Creation Time Event is registered when a file creation time is explicitly modified by a process.
    This event helps tracking the real creation time of a file.
    Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
    Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.

#Rule section
id: f03e34c4-6432-4a30-9ae2-76ae6329399a
level: low
status: stable
logsource:
    product: windows
    service: sysmon
    definition: Sysmon needs to be installed and configured.
detection:
    selection_basic:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 2
    condition: selection_basic
falsepositives:
    - unknown
tags:
    - t1070.006
    - attack.stealth
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
    - https://attack.mitre.org/techniques/T1070/006/
ruletype: Hayabusa

#Sample XML Event
sample-message: |
    File creation time changed:
    RuleName: technique_id=T1099,technique_name=Timestomp
    UtcTime: 2022-04-12 22:52:00.688
    ProcessGuid: {43199d79-0290-6256-3704-000000001400}
    ProcessId: 9752
    Image: C:\TMP\mim.exe
    TargetFilename: C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1
    CreationUtcTime: 2016-05-16 09:13:50.950
    PreviousCreationUtcTime: 2022-04-12 22:52:00.563
    User: ZACH-LOG-TEST\IEUser
sample-evtx: |
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
            <EventID>2</EventID>
            <Version>5</Version>
            <Level>4</Level>
            <Task>2</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="2022-04-12T22:52:00.689654600Z" />
            <EventRecordID>8946</EventRecordID>
            <Correlation />
            <Execution ProcessID="3408" ThreadID="4276" />
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>Zach-log-test</Computer>
            <Security UserID="S-1-5-18" />
        </System>
        <EventData>
            <Data Name="RuleName">technique_id=T1099,technique_name=Timestomp</Data>
            <Data Name="UtcTime">2022-04-12 22:52:00.688</Data>
            <Data Name="ProcessGuid">{43199d79-0290-6256-3704-000000001400}</Data>
            <Data Name="ProcessId">9752</Data>
            <Data Name="Image">C:\TMP\mim.exe</Data>
            <Data Name="TargetFilename">C:\Users\IEUser\AppData\Local\Temp\Quest Software\PowerGUI\51f5c69c-5d16-47e1-9864-038c8510d919\mk.ps1</Data>
            <Data Name="CreationUtcTime">2016-05-16 09:13:50.950</Data>
            <Data Name="PreviousCreationUtcTime">2022-04-12 22:52:00.563</Data>
            <Data Name="User">ZACH-LOG-TEST\IEUser</Data>
        </EventData>
    </Event>
```

> ## Seção do autor

- **author [obrigatório]**: Nome do(s) autor(es).
- **date [obrigatório]**: Data em que a regra foi criada.
- **modified** [opcional]: Data em que a regra foi atualizada.

> ## Seção de alerta

- **title [obrigatório]**: Título do arquivo de regra. Este também será o nome do alerta exibido, então quanto mais breve, melhor. (Não deve ter mais de 85 caracteres.)
- **details** [opcional]: Os detalhes do alerta que são exibidos. Por favor, gere quaisquer campos do registro de eventos do Windows que sejam úteis para análise. Os campos são separados por `" ¦ "`. Os marcadores de campo são delimitados por um `%` (Exemplo: `%MemberName%`) e precisam ser definidos em `rules/config/eventkey_alias.txt`. (Explicado abaixo.)
- **description** [opcional]: Uma descrição da regra. Isto não é exibido, então você pode torná-la longa e detalhada.

> ## Seção da regra

- **id [obrigatório]**: Um UUID versão 4 gerado aleatoriamente, usado para identificar a regra de forma exclusiva. Você pode gerar um [aqui](https://www.uuidgenerator.net/version4).
- **level [obrigatório]**: Nível de severidade baseado na [definição do sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). Por favor, escreva um dos seguintes: `informational`,`low`,`medium`,`high`,`critical`
- **status[obrigatório]**: Status baseado na [definição do sigma](https://github.com/SigmaHQ/sigma/wiki/Specification). Por favor, escreva um dos seguintes: `deprecated`, `experimental`, `test`, `stable`.
- **logsource [obrigatório]**: Embora isso não seja realmente usado pelo Hayabusa no momento, definimos logsource da mesma forma que o sigma, a fim de ser compatível com as regras sigma.
- **detection  [obrigatório]**: A lógica de detecção vem aqui. (Explicado abaixo.)
- **falsepositives [obrigatório]**: As possibilidades de falsos positivos. Por exemplo: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`. Se for desconhecido, por favor escreva `unknown`.
- **tags** [opcional]: Se a técnica for uma técnica [LOLBINS/LOLBAS](https://lolbas-project.github.io/), por favor adicione a tag `lolbas`. Se o alerta puder ser mapeado para uma técnica no framework [MITRE ATT&CK](https://attack.mitre.org/), por favor adicione o ID da tática (Exemplo: `attack.t1098`) e quaisquer táticas aplicáveis abaixo:
  - `attack.reconnaissance` -> Reconhecimento (Recon)
  - `attack.resource-development` -> Desenvolvimento de Recursos  (ResDev)
  - `attack.initial-access` -> Acesso Inicial (InitAccess)
  - `attack.execution` -> Execução (Exec)
  - `attack.persistence` -> Persistência (Persis)
  - `attack.privilege-escalation` -> Escalonamento de Privilégios (PrivEsc)
  - `attack.stealth` -> Furtividade (Stealth)
  - `attack.defense-impairment` -> Comprometimento de Defesas (DefImpair)
  - `attack.credential-access` -> Acesso a Credenciais (CredAccess)
  - `attack.discovery` -> Descoberta (Disc)
  - `attack.lateral-movement` -> Movimento Lateral (LatMov)
  - `attack.collection` -> Coleta (Collect)
  - `attack.command-and-control` -> Comando e Controle (C2)
  - `attack.exfiltration` -> Exfiltração (Exfil)
  - `attack.impact` -> Impacto (Impact)
- **references** [opcional]: Quaisquer links para referências.
- **ruletype [obrigatório]**: `Hayabusa` para regras do hayabusa. Regras convertidas automaticamente a partir de regras sigma do Windows serão `Sigma`.

> ## Evento XML de exemplo

- **sample-message [obrigatório]**: A partir de agora, pedimos aos autores de regras que incluam mensagens de exemplo para suas regras. Esta é a mensagem renderizada que o Visualizador de Eventos do Windows exibe.
- **sample-evtx [obrigatório]**: A partir de agora, pedimos aos autores de regras que incluam eventos XML de exemplo para suas regras.
