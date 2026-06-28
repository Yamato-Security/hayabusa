# Erstellen von Regeldateien

## Über Hayabusa-Rules

Dies ist ein Repository, das kuratierte Sigma-Regeln enthält, die Angriffe in Windows-Ereignisprotokollen erkennen.
Es wird hauptsächlich für [Hayabusa](https://github.com/Yamato-Security/hayabusa)-Erkennungsregeln und Konfigurationsdateien sowie für die integrierte Sigma-Erkennung von [Velociraptor](https://github.com/Velocidex/velociraptor) verwendet.
Der Vorteil der Verwendung dieses Repositorys gegenüber dem [vorgelagerten Sigma-Repository](https://github.com/SigmaHQ/sigma) besteht darin, dass wir nur Regeln einbeziehen, die die meisten Sigma-nativen Tools parsen können sollten.
Wir entabstrahieren außerdem das Feld `logsource`, indem wir die notwendigen Felder `Channel`, `EventID` usw. zu den Regeln hinzufügen, um es einfacher zu machen zu verstehen, worauf die Regel filtert, und – noch wichtiger – um Fehlalarme zu reduzieren.
Wir erstellen außerdem neue Regeln mit konvertierten Feldnamen und Werten für `process_creation`-Regeln und `registry`-basierte Regeln, sodass die Sigma-Regeln nicht nur Sysmon-Protokolle erkennen, sondern auch integrierte Windows-Protokolle erkennen.

## Über das Erstellen von Regeldateien

Hayabusa-Erkennungsregeln werden im [YAML](https://en.wikipedia.org/wiki/YAML)-Format mit der Dateierweiterung `.yml` geschrieben. (`.yaml`-Dateien werden ignoriert.)
Sie sind eine Teilmenge von Sigma-Regeln, enthalten aber auch einige zusätzliche Funktionen.
Wir versuchen, sie so nah wie möglich an Sigma-Regeln zu halten, damit es einfach ist, Hayabusa-Regeln wieder in Sigma zu konvertieren, um sie der Community zurückzugeben.
Hayabusa-Regeln können komplexe Erkennungsregeln ausdrücken, indem sie nicht nur einfachen Zeichenkettenabgleich, sondern auch reguläre Ausdrücke, `AND`-, `OR`- und andere Bedingungen kombinieren.
In diesem Abschnitt erklären wir, wie man Hayabusa-Erkennungsregeln schreibt.

### Format der Regeldatei

Beispiel:

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

> ## Autorenabschnitt

- **author [required]**: Name des Autors bzw. der Autoren.
- **date [required]**: Datum, an dem die Regel erstellt wurde.
- **modified** [optional]: Datum, an dem die Regel aktualisiert wurde.

> ## Alarmabschnitt

- **title [required]**: Titel der Regeldatei. Dies ist auch der Name des angezeigten Alarms, also je kürzer desto besser. (Sollte nicht länger als 85 Zeichen sein.)
- **details** [optional]: Die Details des angezeigten Alarms. Bitte geben Sie alle Felder im Windows-Ereignisprotokoll aus, die für die Analyse nützlich sind. Felder werden durch `" ¦ "` getrennt. Feldplatzhalter werden mit einem `%` eingeschlossen (Beispiel: `%MemberName%`) und müssen in `rules/config/eventkey_alias.txt` definiert werden. (Unten erklärt.)
- **description** [optional]: Eine Beschreibung der Regel. Diese wird nicht angezeigt, sodass Sie sie lang und detailliert gestalten können.

> ## Regelabschnitt

- **id [required]**: Eine zufällig generierte Version-4-UUID, die zur eindeutigen Identifizierung der Regel verwendet wird. Sie können eine [hier](https://www.uuidgenerator.net/version4) generieren.
- **level [required]**: Schweregrad basierend auf [Sigmas Definition](https://github.com/SigmaHQ/sigma/wiki/Specification). Bitte schreiben Sie eines der folgenden: `informational`,`low`,`medium`,`high`,`critical`
- **status[required]**: Status basierend auf [Sigmas Definition](https://github.com/SigmaHQ/sigma/wiki/Specification). Bitte schreiben Sie eines der folgenden: `deprecated`, `experimental`, `test`, `stable`.
- **logsource [required]**: Obwohl dies derzeit nicht tatsächlich von Hayabusa verwendet wird, definieren wir logsource auf die gleiche Weise wie Sigma, um mit Sigma-Regeln kompatibel zu sein.
- **detection  [required]**: Die Erkennungslogik kommt hierhin. (Unten erklärt.)
- **falsepositives [required]**: Die Möglichkeiten für Fehlalarme. Zum Beispiel: `system administrator`, `normal user usage`, `normal system usage`, `legacy application`, `security team`, `none`. Falls es unbekannt ist, schreiben Sie bitte `unknown`.
- **tags** [optional]: Wenn die Technik eine [LOLBINS/LOLBAS](https://lolbas-project.github.io/)-Technik ist, fügen Sie bitte das Tag `lolbas` hinzu. Wenn der Alarm einer Technik im [MITRE ATT&CK](https://attack.mitre.org/)-Framework zugeordnet werden kann, fügen Sie bitte die Taktik-ID (Beispiel: `attack.t1098`) und alle zutreffenden Taktiken unten hinzu:
  - `attack.reconnaissance` -> Reconnaissance (Recon)
  - `attack.resource-development` -> Resource Development  (ResDev)
  - `attack.initial-access` -> Initial Access (InitAccess)
  - `attack.execution` -> Execution (Exec)
  - `attack.persistence` -> Persistence (Persis)
  - `attack.privilege-escalation` -> Privilege Escalation (PrivEsc)
  - `attack.stealth` -> Stealth (Stealth)
  - `attack.defense-impairment` -> Defense Impairment (DefImpair)
  - `attack.credential-access` -> Credential Access (CredAccess)
  - `attack.discovery` -> Discovery (Disc)
  - `attack.lateral-movement` -> Lateral Movement (LatMov)
  - `attack.collection` -> Collection (Collect)
  - `attack.command-and-control` -> Command and Control (C2)
  - `attack.exfiltration` -> Exfiltration (Exfil)
  - `attack.impact` -> Impact (Impact)
- **references** [optional]: Beliebige Links zu Referenzen.
- **ruletype [required]**: `Hayabusa` für Hayabusa-Regeln. Regeln, die automatisch aus Sigma-Windows-Regeln konvertiert werden, sind `Sigma`.

> ## Beispiel-XML-Ereignis

- **sample-message [required]**: Ab sofort bitten wir Regelautoren, Beispielnachrichten für ihre Regeln einzubeziehen. Dies ist die gerenderte Nachricht, die der Windows-Ereignisanzeige anzeigt.
- **sample-evtx [required]**: Ab sofort bitten wir Regelautoren, Beispiel-XML-Ereignisse für ihre Regeln einzubeziehen.
