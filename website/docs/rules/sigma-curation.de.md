# Kuratieren von Sigma-Regeln für Windows-Ereignisprotokolle

Diese Seite dokumentiert, wie Yamato Security die stromaufwärts liegenden [Sigma](https://github.com/SigmaHQ/sigma)-Regeln für Windows-Ereignisprotokolle in eine besser nutzbare Form kuratiert, indem das Feld `logsource` entabstrahiert und Regeln herausgefiltert werden, die unbrauchbar oder schwer zu verwenden sind. Dies geschieht mit dem Werkzeug [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter), das hauptsächlich zur Erstellung des kuratierten Sigma-Regelsatzes verwendet wird, der in [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) gehostet wird. Dieser Regelsatz wird von [Hayabusa](https://github.com/Yamato-Security/hayabusa) und [Velociraptor](https://github.com/Velocidex/velociraptor) genutzt.

!!! info "Quelle"
    Diese Dokumentation wird zusammen mit dem Konverter-Werkzeug unter [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) gepflegt. Wir hoffen, dass diese Informationen auch für andere Projekte nützlich sind, die Sigma-Regeln zur Erkennung von Angriffen in Windows-Ereignisprotokollen verwenden möchten. Siehe auch [Regeldateien erstellen](creating-rules.md) und [Feldmodifikatoren](field-modifiers.md).

## TL;DR

* Das Entabstrahieren des Feldes `logsource` und das Erstellen neuer `.yml`-Regeldateien sowohl für integrierte Regeln als auch für die ursprünglichen Sysmon-basierten Regeln erleichtert die vollständige Unterstützung integrierter Ereignisse für Sigma-Regeln und macht die Regeln für Analysten leichter lesbar.
* Beim Schreiben von Sigma-Regeln für Windows-Ereignisprotokolle ist es wichtig, die Unterschiede zwischen den ursprünglichen Sysmon-basierten Protokollen und den kompatiblen integrierten Protokollen zu verstehen und die Regeln idealerweise so zu schreiben, dass sie mit beiden kompatibel sind.
* Viele Organisationen können oder wollen keine Sysmon-Agenten auf allen ihren Windows-Endpunkten installieren und pflegen, weil sie nicht über die dafür nötigen dedizierten Ressourcen verfügen oder das Risiko von Verlangsamungen oder Abstürzen durch Sysmon vermeiden möchten. Deshalb ist es wichtig, so viele integrierte Ereignisprotokolle wie möglich zu aktivieren und Werkzeuge zu verwenden, die Angriffe in diesen integrierten Protokollen erkennen können.

## Herausforderungen mit stromaufwärts liegenden Sigma-Regeln für Windows-Ereignisprotokolle

Die größte Herausforderung bei der Erstellung eines nativen Sigma-Regel-Parsers für Windows-Ereignisprotokolle bestand unserer Erfahrung nach darin, das Feld `logsource` zu unterstützen. Derzeit ist dies eines der wenigen Dinge, die Hayabusa noch nicht nativ unterstützt, da es nach wie vor sehr komplex ist und sich noch in Arbeit befindet. Vorläufig umgehen wir dies, indem wir die stromaufwärts liegenden Regeln in ein leichter nutzbares Format konvertieren, wie unten ausführlich erläutert.

### Über das Feld `logsource`

In Sigma-Regeln für Windows-Ereignisprotokolle wird das Feld `product` auf `windows` gesetzt, gefolgt entweder von einem `service`-Feld oder einem `category`-Feld.

Beispiel für ein `service`-Feld:

```yaml
logsource:
    product: windows
    service: application
```

Beispiel für ein `category`-Feld:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Service-Felder

`service`-Felder sind relativ einfach zu handhaben und weisen das jeweilige Backend, das die Sigma-Regel verwendet, an, anhand des Feldes `Channel` im Windows-XML-Ereignisprotokoll nach einem einzelnen Kanal oder mehreren Kanälen zu suchen.

**Beispiel für einen einzelnen Kanal**

`service: application` ist dasselbe wie das Hinzufügen einer Auswahlbedingung `Channel: Application` zur Sigma-Regel.

**Beispiel für mehrere Kanäle**

`service: applocker` erzeugt derzeit die meisten zu durchsuchenden Kanäle, da AppLocker Informationen in vier verschiedenen Protokollen speichert. Um korrekt nur die AppLocker-Protokolle zu durchsuchen, muss die folgende Bedingung zur Logik der Sigma-Regel hinzugefügt werden:

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**Aktuelle Liste der Service-Zuordnungen**

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

**Quellen der Service-Zuordnungen**

Wir haben YAML-Zuordnungsdateien für Services zu Kanalnamen erstellt, die wir regelmäßig pflegen und im Konverter-Repository hosten. Sie basieren auf den Service-Zuordnungsinformationen aus [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml): Obwohl dies keine offizielle generische Konfigurationsdatei zur allgemeinen Nutzung zu sein scheint, scheint sie die aktuellste zu sein.

#### Category-Felder

Die meisten `category`-Felder fügen einfach eine Bedingung hinzu, die zusätzlich zur Suche nach einem bestimmten `Channel` auf bestimmte Ereignis-IDs im Feld `EventID` prüft. Die Kategorienamen basieren größtenteils auf [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)-Ereignissen, mit einigen zusätzlichen Kategorien für integrierte PowerShell-Protokolle und Windows Defender.

**Beispiel für ein `category`-Feld**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**Aktuelle Liste der Kategorie-Zuordnungen**

Einige Kategorien werden mehr als einem Service bzw. einer EventID zugeordnet (in **Fettdruck** dargestellt).

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

**Herausforderungen bei `category`-Feldern**

Wie oben gezeigt, kann dieselbe `category` mehrere Services und Ereignis-IDs verwenden (in **Fettdruck** angezeigt). Das bedeutet, dass es möglich ist, einige für `sysmon` konzipierte Sigma-Regeln mit ähnlichen integrierten Windows-`security`-Ereignisprotokollen zu verwenden, sofern die von der Regel genutzten Felder auch im integrierten Ereignisprotokoll vorhanden sind. In diesem Fall müssen die Feldnamen — und manchmal auch die Werte — möglicherweise umgewandelt werden, um mit den Feldnamen und Werten des integrierten `security`-Ereignisprotokolls übereinzustimmen. Auch wenn dies für bestimmte Kategorien so einfach sein kann wie das Umbenennen einiger Feldnamen, kann es für andere Kategorien verschiedene Umwandlungen auch bei den Feldwerten erfordern. Wie wir diese Umwandlung durchführen und die Kompatibilität zwischen `sysmon`-Protokollen und `security`-Protokollen werden [weiter unten](#sysmon-builtin-comparison) ausführlich erläutert.

**Quellen der Kategorie-Zuordnungen**

Die YAML-Zuordnungsdateien für Kategorien werden ebenfalls im Konverter-Repository gehostet und basieren ebenfalls auf den Informationen aus [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml).

## Vorteile und Herausforderungen der Abstraktion der Protokollquelle

Die Abstraktion der Protokollquelle und die Erstellung von Zuordnungen für verschiedene `Channel`-, `EventID`- und Felder im Backend bringen sowohl Vorteile als auch Herausforderungen mit sich.

### Vorteile

1. Es kann einfacher sein, die Feldnamen `Channel` und `EventID` in die passenden Backend-Feldnamen umzuwandeln, wenn Sigma-Regeln in andere Backend-Abfragen konvertiert werden.
2. Es ist möglich, zwei Regeln zu einer zusammenzufassen. Beispielsweise können Prozesserstellungsereignisse sowohl in `Sysmon 1` als auch in `Security 4688` protokolliert werden. Anstatt zwei Regeln zu schreiben, die unterschiedliche Kanäle, Ereignis-IDs und Felder betrachten, ansonsten aber dieselbe Logik enthalten, ist es möglich, die Felder auf das zu standardisieren, was Sysmon verwendet, und dann einen Backend-Konverter die Felder `Channel` und `EventID` hinzufügen und bei Bedarf weitere Feldinformationen umwandeln zu lassen. Dies erleichtert die Pflege der Regeln, da weniger Regeln zu pflegen sind.
3. Auch wenn dies sehr selten vorkommt: Wenn eine Protokollquelle beginnt, ihre Daten in einem anderen `Channel` oder unter einer anderen `EventID` zu protokollieren, muss nur die Zuordnungslogik aktualisiert werden, statt alle Sigma-Regeln zu aktualisieren, was die Pflege erleichtert.

### Herausforderungen

1. Was passiert, wenn die ursprüngliche, auf Sysmon basierende Sigma-Regel ein Feld verwendet, das in den integrierten Protokollen zum Herausfiltern von Fehlalarmen nicht existiert? Sollte man die Regel trotzdem erstellen und mögliche Erkennung priorisieren, oder sie ignorieren, um weniger Fehlalarme zu priorisieren? Idealerweise müssten zwei Regeln mit unterschiedlichen `severity`-, `status`- und Fehlalarm-Informationen erstellt werden, damit der Benutzer damit besser umgehen kann.
2. Es erschwert das Filtern von Regeln, da man nicht einfach anhand der Felder `Channel` oder `EventID` in der `.yml`-Datei oder anhand des Dateipfads der Regel filtern kann, falls die Datei noch nicht erstellt wurde — denn es handelt sich um eine abgeleitete Regel für ein integriertes Protokoll anstelle der ursprünglichen Sysmon-Regel. Da die Regel-ID zudem identisch ist, kann man nicht nach Regel-IDs filtern.
3. Es erschwert die Bestätigung des Alarms, wenn der Alarm von einer Regel für integrierte Protokolle stammt, die von einem Sysmon-Protokoll abgeleitet wurde. Die Feldnamen und -werte stimmen nicht überein, sodass der Analyst den etwas komplexen Umwandlungsprozess verstehen muss.
4. Es macht die Erstellung der Backend-Logik komplexer.

Während wir gegen das erste Problem nichts unternehmen können, außer neue Regeln zu erstellen und zu pflegen, wenn es einen wesentlichen Anwendungsfall gibt, der den Aufwand rechtfertigt, haben wir uns zur Bewältigung der Probleme 2–4 entschieden, das Feld `logsource` zu entabstrahieren und für jede Regel, die mehrere Regeln erzeugen kann, zwei Regelsätze zu erstellen. Regeln, die Angriffe in integrierten Protokollen erkennen können, werden in das Verzeichnis `builtin` ausgegeben, und Regeln für Sysmon werden in das Verzeichnis `sysmon` ausgegeben.

## Umwandlungsbeispiel

Hier ist ein einfaches Beispiel, um den Umwandlungsprozess besser zu verstehen.

**Vor der Umwandlung** — die ursprüngliche Sigma-Regel:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**Nach der Umwandlung** — eine Hayabusa-kompatible Regel für Sysmon-Protokolle:

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

...und eine Hayabusa-kompatible Regel für integrierte Windows-Protokolle:

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

Wie man sieht, wurden zwei Regeln erstellt: eine für Sysmon-1-Protokolle und eine für die integrierten Security-4688-Protokolle. Eine neue `process_creation`-Bedingung mit den Kanal- und Ereignis-ID-Informationen wurde hinzugefügt und dem Feld `condition` hinzugefügt, um diese Bedingung zu erzwingen. Außerdem wurde der ursprüngliche Feldname `Image` in `NewProcessName` geändert.

## Gemeinsamkeiten der Umwandlung

Bevor wir im Detail erklären, wie wir bestimmte Kategorien umwandeln, folgt hier der Teil der Umwandlung, der für alle Regeln gilt.

1. Jede Regel, deren ID in `ignore-uuid-list.txt` steht, wird ignoriert. Derzeit ignorieren wir nur Regeln, die Fehlalarme bei Windows Defender verursachen, weil sie Schlüsselwörter wie `mimikatz` enthalten.
2. „Platzhalter“-Regeln werden ignoriert, da sie nicht so verwendet werden können, wie sie sind. Dies sind Regeln, die im Ordner [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) im Sigma-Repository abgelegt sind.
3. Regeln, die inkompatible Feldmodifikatoren verwenden, werden verworfen. Hayabusa unterstützt die Mehrzahl der Feldmodifikatoren, daher gibt der Konverter keine Regel aus, die einen anderen als diese Modifikatoren verwendet, um Parsing-Fehler zu vermeiden (siehe [Feldmodifikatoren](field-modifiers.md)):

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. Regeln mit Syntaxfehlern werden nicht konvertiert.
5. Tags in `deprecated`- und `unsupported`-Regeln werden vom V1-Format auf das V2-Format aktualisiert, das `-` anstelle von `_` verwendet, um alles konsistent zu halten und Abkürzungen in Hayabusa einfacher zu handhaben. Beispiel: `initial_access` wird zu `initial-access`.
6. Da wir den Regeln `Channel`- und `EventID`-Informationen hinzufügen, erstellen wir eine neue UUIDv4-ID, indem wir den MD5-Hash der ursprünglichen ID verwenden, geben die ursprüngliche ID im Feld `related` an und kennzeichnen den `type` als `derived`. Für Regeln, die in mehrere Regeln (`sysmon` und `builtin`) umgewandelt werden können, müssen wir auch für die abgeleiteten `builtin`-Regeln neue Regel-IDs erstellen. Dazu berechnen wir einen MD5-Hash der `sysmon`-Regel-ID und verwenden diesen für die UUIDv4-ID. Zum Beispiel:

    Ursprüngliche Sigma-Regel:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    Neue `sysmon`-Regel:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    Neue `builtin`-Regel:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. Regeln, die Dinge in integrierten Windows-Ereignisprotokollen erkennen, werden in das Verzeichnis `builtin` ausgegeben, während Regeln, die auf Sysmon-Protokolle angewiesen sind, in das Verzeichnis `sysmon` ausgegeben werden, mit Unterverzeichnissen, die den Verzeichnissen im stromaufwärts liegenden Sigma-Repository entsprechen.

## Einschränkungen der Umwandlung

Derzeit gibt es nur einen [bekannten Fehler](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2): Kommentarzeilen in Sigma-Regeln werden nicht in die Ausgaberegeln übernommen, es sei denn, die Kommentare folgen auf Quellcode.

## Vergleich von Sysmon- und integrierten Ereignissen sowie Regelumwandlung { #sysmon-builtin-comparison }

### Prozesserstellung

* Category: `process_creation`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `1`
* Integriertes Protokoll
    * Channel: `Security`
    * Event ID: `4688`

**Vergleich**

![Vergleich der Prozesserstellung](../assets/rules-doc/process_creation_comparison.png)

**Hinweise zur Umwandlung**

1. Die Informationen des Feldes `User` müssen in die Felder `SubjectUserName` und `SubjectDomainName` aufgeteilt werden.
2. Der Feldname `LogonId` ändert sich zu `SubjectLogonId`, und alle Buchstaben im Hex-Wert müssen kleingeschrieben werden.
3. Der Feldname `ProcessId` ändert sich zu `NewProcessId`, und der Wert muss in Hex umgewandelt werden.
4. Der Feldname `Image` ändert sich zu `NewProcessName`.
5. Der Feldname `ParentProcessId` ändert sich zu `ProcessId`, und der Wert muss in Hex umgewandelt werden.
6. Der Feldname `ParentImage` ändert sich zu `ParentProcessName`.
7. Der Feldname `IntegrityLevel` ändert sich zu `MandatoryLabel`, und die folgende Wertumwandlung ist erforderlich:
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. Wenn die Regel die folgenden Felder enthält, die nur in `Security 4688`-Ereignissen existieren, erstellen wir keine `Sysmon 1`-Regel:
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. Wenn die Regel die folgenden Felder enthält, die nur in `Sysmon 1`-Ereignissen existieren, erstellen wir keine `Security 4688`-Regel:
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. Es gibt eine Ausnahme zu Nr. 8 und Nr. 9: Selbst wenn ein Feld verwendet wird, das nur in einem der Protokollereignisse existiert, sollten Sie diese Regel dennoch erstellen, wenn sich dieses Feld in einer `OR`-Bedingung befindet. Beispielsweise sollte die folgende Regel **keine** `Security 4688`-Regel erzeugen, da das Feld `OriginalFileName` erforderlich ist (`AND`-Logik innerhalb der Auswahl):

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    Eine Regel mit der folgenden Bedingung **sollte** hingegen eine `Security 4688`-Regel erstellen, da `OriginalFileName` optional ist (`OR`-Logik innerhalb der Auswahl):

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    Es wird insofern schwierig, als Ihr Parser nicht nur die Logik innerhalb der Auswahlen, sondern auch innerhalb des Feldes `condition` verstehen muss. Beispielsweise **sollte** die folgende Regel **keine** `Security 4688`-Regel erstellen, da sie `AND`-Logik verwendet:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    Die folgende Regel **sollte** hingegen eine `Security 4688`-Regel erstellen, da sie `OR`-Logik verwendet:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**Weitere Hinweise**

* Das Feld `SubjectUserSid` in `Security 4688` zeigt die SID an; im gerenderten Ereignisprotokoll-`Message` wird es jedoch in `DOMAIN\User` umgewandelt.
* `Security 4688`-Ereignisse enthalten je nach Einstellung möglicherweise keine Befehlszeilenoptions-Informationen in `CommandLine`.
* `TokenElevationType` wird unverändert im `Message` angezeigt und nicht gerendert.
* `S-1-16-4096` usw. innerhalb von `MandatoryLabel` wird im gerenderten `Message` in `Mandatory Label\Low Mandatory Level` usw. umgewandelt.

**Einstellungen für integrierte Protokolle**

!!! warning "Standardmäßig nicht aktiviert"
    Die wichtigen integrierten `Security 4688`-Prozesserstellungs-Ereignisprotokolle sind standardmäßig nicht aktiviert. Sie müssen sowohl die `4688`-Ereignisse als auch die Protokollierung von Befehlszeilenoptionen aktivieren, um die Mehrzahl der Sigma-Regeln nutzen zu können.

*Aktivierung über Gruppenrichtlinie:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*Aktivierung über die Befehlszeile:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### Netzwerkverbindung

* Category: `network_connection`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `3`
* Integriertes Protokoll
    * Channel: `Security`
    * Event ID: `5156`

**Vergleich**

![Vergleich der Netzwerkverbindung](../assets/rules-doc/network_connection_comparison.png)

**Hinweise zur Umwandlung**

1. Der Feldname `ProcessId` ändert sich zu `ProcessID`.
2. Der Feldname `Image` ändert sich zu `Application`, und `C:\` ändert sich zu `\device\harddiskvolume?\`. (Hinweis: Da wir die Festplatten-Volumenummer nicht kennen, ersetzen wir sie durch den Einzelzeichen-Platzhalter `?`.)
3. Der Wert `tcp` des Feldes `Protocol` ändert sich zu `6` und `udp` ändert sich zu `17`.
4. Der Feldname `Initiated` ändert sich zu `Direction`, und der Wert `true` ändert sich zu `%%14593` und `false` ändert sich zu `%%14592`.
5. Der Feldname `SourceIp` ändert sich zu `SourceAddress`.
6. Der Feldname `DestinationIp` ändert sich zu `DestAddress`.
7. Der Feldname `DestinationPort` ändert sich zu `DestPort`.

**Einstellungen für integrierte Protokolle**

!!! warning "Standardmäßig nicht aktiviert"
    Integrierte `Security 5156`-Netzwerkverbindungsprotokolle sind standardmäßig nicht aktiviert. Sie erzeugen eine große Menge an Protokollen, die andere wichtige Protokolle im `Security`-Ereignisprotokoll überschreiben und das System potenziell verlangsamen können, wenn es eine hohe Anzahl an Netzwerkverbindungen aufweist. Stellen Sie sicher, dass die maximale Dateigröße für das `Security`-Protokoll hoch ist, und testen Sie, ob es keine negativen Auswirkungen auf das System gibt.

*Aktivierung über Gruppenrichtlinie:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*Aktivierung über die Befehlszeile:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...oder das Folgende, wenn Sie ein nicht-englisches Gebietsschema verwenden:

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "Siehe auch"
    Weitere Informationen zum Aktivieren der integrierten Windows-Ereignisprotokolle, die zur Erfassung der von diesen Regeln benötigten Beweise erforderlich sind, finden Sie unter [Windows-Protokollierung & Sysmon](../resources/logging.md) und im Projekt [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings).

## Ratschläge zum Schreiben von Sigma-Regeln

!!! tip
    Wenn Sie ein Feld verwenden, das in einem `sysmon`-Protokoll, aber nicht in einem `builtin`-Protokoll existiert, stellen Sie sicher, dass Sie dieses Feld optional machen, damit die Regel weiterhin für `builtin`-Protokolle verwendet werden kann.

Zum Beispiel:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

Diese Auswahl sucht danach, wenn der Prozess (`Image`) den Namen `addinutil.exe` trägt. Das Problem ist, dass ein Angreifer die Datei einfach umbenennen könnte, um die Regel zu umgehen. Das Feld `OriginalFileName`, das nur in Sysmon-Protokollen existiert, ist der Dateiname, der zur Kompilierzeit in die Binärdatei eingebettet wird. Selbst wenn ein Angreifer die Datei umbenennt, ändert sich der eingebettete Name nicht, sodass diese Regel bei Verwendung von Sysmon Angriffe erkennen kann, bei denen der Angreifer die Datei umbenannt hat, und bei Verwendung der standardmäßigen integrierten Protokolle auch Angriffe erkennen kann, bei denen der Dateiname nicht geändert wurde.

## Vorkonvertierte Sigma-Regeln

Sigma-Regeln, die auf die auf dieser Seite beschriebene Weise kuratiert wurden — durch Entabstrahieren des Feldes `logsource` —, werden im Repository [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) im Ordner `sigma` gehostet.

## Werkzeugumgebung

Wenn Sie Sigma-Regeln lokal in ein Hayabusa-kompatibles Format konvertieren möchten, müssen Sie zuerst [Poetry](https://python-poetry.org/) installieren. Bitte beachten Sie die offizielle Poetry-[Installationsdokumentation](https://python-poetry.org/docs/#installation).

## Verwendung des Werkzeugs

`sigma-to-hayabusa-converter.py` ist unser Hauptwerkzeug, um das Feld `logsource` von Sigma-Regeln in ein Hayabusa-kompatibles Format zu konvertieren. Führen Sie die folgenden Aufgaben aus, um es zu starten:

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

Nach der Ausführung der obigen Befehle werden die in das Hayabusa-kompatible Format konvertierten Regeln in das Verzeichnis `./converted_sigma_rules` ausgegeben.

## Autoren

Dieses Dokument wurde von Zach Mathis (@yamatosecurity) erstellt und von Fukusuke Takahashi (@fukusuket) ins Japanische übersetzt.

Die Implementierung und Pflege des Werkzeugs `sigma-to-hayabusa-converter.py` erfolgt durch Fukusuke Takahashi.

Das ursprüngliche Umwandlungswerkzeug, das auf dem inzwischen veralteten Werkzeug `sigmac` basierte, wurde von ItiB ([@itiB_S144](https://x.com/itib_s144)) und James Takai / hachiyone (@hach1yon) implementiert.
