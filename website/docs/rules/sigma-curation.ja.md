# Windowsイベントログ向けのSigmaルールのキュレーション

このページでは、Yamato SecurityがWindowsイベントログ用の上流[Sigma](https://github.com/SigmaHQ/sigma)ルールを、`logsource`フィールドの抽象化を解除し、使用できない、または使いづらいルールを除外することで、より使いやすい形にキュレーションする方法を説明します。これは[`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)ツールで行われ、主に[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)でホスティングされている、キュレートされたSigmaルールセットを作成するために使用されています。このルールセットは[Hayabusa](https://github.com/Yamato-Security/hayabusa)と[Velociraptor](https://github.com/Velocidex/velociraptor)で使用されています。

!!! info "出典"
    このドキュメントは、コンバータツール[Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)とともにメンテナンスされています。この情報が、Windowsイベントログで攻撃を検出するためにSigmaルールを使用しようとしている他のプロジェクトにとっても役立つことを願っています。[ルールファイルの作成](creating-rules.md)と[フィールド修飾子](field-modifiers.md)も参照してください。

## 要約

* `logsource`フィールドの抽象化を解除し、組み込みルールや元のSysmonベースのルールのために新しい`.yml`ルールファイルを作成することで、Sigmaルールの完全な組み込みイベントサポートが容易になり、アナリストにとってルールの読みやすさが向上します。
* WindowsイベントログのためにSigmaルールを書く際には、元のSysmonベースのログと互換性のある組み込みログの違いを理解し、理想的には両方に対応するようにルールを書くことが重要です。
* 多くの組織は、SysmonエージェントをすべてのWindowsエンドポイントにインストールし、維持するための専用リソースがない、またはSysmonによる遅延やクラッシュのリスクを避けたいという理由で、Sysmonエージェントを導入したくない、またはできません。そのため、できるだけ多くの組み込みイベントログを有効にし、それらの組み込みログで攻撃を検出できるツールを使用することが重要です。

## Windowsイベントログに関する上流のSigmaルールの課題

私たちの経験では、Windowsイベントログ用のネイティブSigmaルールパーサーを作成する際の主な課題は、`logsource`フィールドのサポートです。現在、これはHayabusaがまだネイティブでサポートしていない数少ない機能の一つであり、非常に複雑で、現在も進行中の作業です。当面の間、この問題を回避するために、上流のルールを以下で詳しく説明するように、より使いやすい形式に変換しています。

### `logsource`フィールドについて

Windowsイベントログ用のSigmaルールでは、`product`フィールドに`windows`が設定され、その後に`service`フィールドまたは`category`フィールドが続きます。

`service`フィールドの例:

```yaml
logsource:
    product: windows
    service: application
```

`category`フィールドの例:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Serviceフィールド

`service`フィールドは比較的扱いやすく、Sigmaルールを使用するバックエンドに対して、Windows XMLイベントログの`Channel`フィールドに基づいて、単一または複数のチャンネルを検索するよう指示します。

**単一チャンネルの例**

`service: application`は、selection条件 `Channel: Application` をSigmaルールに追加するのと同じです。

**複数チャンネルの例**

`service: applocker`は、AppLockerが情報を4つの異なるログに保存するため、現在最も多くのチャンネルを検索対象とします。AppLockerのログのみを適切に検索するためには、Sigmaルールのロジックに次の条件を追加する必要があります。

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**現在のserviceマッピングのリスト**

| サービス                                    | チャンネル                                                                                                                          |
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

**serviceマッピングのソース**

私たちは、serviceとchannel名をマッピングするためのYAMLファイルを作成し、コンバータリポジトリで定期的にメンテナンスし、ホスティングしています。これらのファイルは、[SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml)のサービスマッピング情報に基づいています。このファイルは、公式の汎用設定ファイルとして提供されているわけではなさそうですが、最も最新の情報を含んでいるようです。

#### Categoryフィールド

ほとんどの`category`フィールドは、特定の`Channel`を検索することに加えて、`EventID`フィールドで特定のイベントIDを確認する条件を追加するだけです。カテゴリ名は主に[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)イベントに基づいており、ビルトインのPowerShellログやWindows Defender用の追加カテゴリも含まれています。

**categoryフィールドの例**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**現在のcategoryマッピングのリスト**

一部のcategoryは複数のservice/EventIDにマッピングされます（**太字**で示しています）。

| カテゴリ                  | サービス            | イベントID                                                             |
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

**categoryフィールドの課題**

上記のとおり、同じ`category`が複数のserviceやイベントIDを使用できます（**太字**で示しています）。これは、ルールで使用されているフィールドがビルトインのイベントログにも存在する場合、`sysmon`用に設計された一部のSigmaルールを、同様のビルトインWindowsの`security`イベントログで使用できる可能性があることを意味します。その場合、フィールド名、そして場合によっては値も、ビルトインの`security`イベントログのフィールド名や値に合わせて変換する必要があるかもしれません。特定のカテゴリにおいては、いくつかのフィールド名をリネームするだけで済むこともありますが、他のカテゴリではフィールド値のさまざまな変換も必要になるかもしれません。この変換方法や、`sysmon`ログと`security`ログの互換性については、[後述](#sysmon-builtin-comparison)で詳しく説明します。

**categoryマッピングのソース**

カテゴリのYAMLマッピングファイルもコンバータリポジトリでホスティングされており、これらも[SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml)の情報に基づいています。

## ログソースを抽象化するメリットと課題

ログソースを抽象化し、バックエンドで異なる`Channel`、`EventID`、およびフィールドのマッピングを作成することには、メリットと課題の両方があります。

### メリット

1. Sigmaルールを他のバックエンドクエリに変換する際、`Channel`や`EventID`のフィールド名を適切なバックエンドのフィールド名に変換する方が簡単かもしれません。
2. 2つのルールを1つに統合することが可能です。たとえば、プロセス作成イベントは`Sysmon 1`と`Security 4688`の両方に記録されることがあります。異なるチャンネル、イベントID、フィールドを参照するものの、それ以外は同じロジックを持つ2つのルールを作成する代わりに、フィールドをSysmonで使用されるものに統一し、その後バックエンドコンバータで`Channel`と`EventID`フィールドを追加し、必要に応じて他のフィールド情報を変換できます。これにより、メンテナンスすべきルールの数が減り、ルールのメンテナンスが容易になります。
3. 非常に稀ではありますが、ログソースが別の`Channel`や`EventID`にデータを記録し始めた場合、すべてのSigmaルールを更新する代わりにマッピングロジックだけを更新すればよいので、メンテナンスが簡単になります。

### 課題

1. 元のSysmonに基づいたSigmaルールが、誤検知を除外するためにビルトインのログには存在しないフィールドを使用している場合、どうすべきでしょうか？検出の可能性を優先してとにかくルールを作成するべきでしょうか、それとも誤検知を減らすことを優先して無視するべきでしょうか？理想的には、ユーザーがより適切に対応できるように、異なる`severity`、`status`、および誤検知情報を持つ2つのルールを作成する必要があります。
2. ルールのフィルタリングが難しくなります。派生ルールがまだ作成されていない場合、それは元のSysmonルールではなくビルトインログ向けの派生ルールであるため、`.yml`ファイル内やルールのファイルパスで`Channel`や`EventID`フィールドに基づいてフィルタリングすることができません。また、ルールIDが同じであるため、ルールIDでフィルタリングすることもできません。
3. Sysmonログから派生したビルトインログ向けのルールからアラートが発生した場合、アラートの確認が難しくなります。フィールド名や値が一致しないため、アナリストは多少複雑な変換プロセスを理解する必要があります。
4. バックエンドのロジックの作成がより複雑になります。

最初の問題については、その労力を正当化できる重要なユースケースがある場合に新しいルールを作成し維持する以外に対処方法はありませんが、問題2から4に対処するために、`logsource`フィールドの抽象化を解除し、複数のルールを生成できるルールについては2つのルールセットを作成することにしました。ビルトインログで攻撃を検出できるルールは`builtin`ディレクトリに出力され、Sysmon用のルールは`sysmon`ディレクトリに出力されます。

## 変換の例

以下は、変換プロセスをより理解するための簡単な例です。

**変換前** — 元のSigmaルール:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**変換後** — SysmonログのHayabusa互換ルール:

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

...そして、WindowsビルトインログのHayabusa互換ルール:

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

上記のとおり、`Sysmon 1`ログ用とビルトインの`Security 4688`ログ用の2つのルールが作成されています。ChannelとイベントIDの情報を持つ新しい`process_creation`条件が追加され、この条件が必須となるように`condition`フィールドに追加されています。また、元の`Image`フィールド名は`NewProcessName`に変更されています。

## 変換の共通点

特定のカテゴリをどのように変換するかを詳しく説明する前に、すべてのルールに適用される変換の共通部分について説明します。

1. `ignore-uuid-list.txt`にIDが含まれているルールは無視されます。現在、`mimikatz`などのキーワードを含んでいるため、Windows Defenderで誤検知を引き起こすルールのみを無視しています。
2. 「Placeholder（プレースホルダ）」ルールは、そのままでは使用できないため無視されます。これらはSigmaリポジトリの[`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/)フォルダに配置されているルールです。
3. 非互換なフィールド修飾子を使用するルールは除外されます。Hayabusaはフィールド修飾子の大部分をサポートしているため、パースエラーを避けるために、コンバータは以下以外の修飾子を使用するルールを出力しません（[フィールド修飾子](field-modifiers.md)を参照）。

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. 構文エラーを含むルールは変換されません。
5. `deprecated`および`unsupported`ルールのタグは、すべての一貫性を保ち、Hayabusaでの略語の扱いを容易にするために、`_`の代わりに`-`を使用するV1フォーマットからV2フォーマットに更新されます。例: `initial_access`は`initial-access`になります。
6. ルールに`Channel`と`EventID`の情報を追加するので、元のIDのMD5ハッシュを使用して新しいUUIDv4 IDを作成し、`related`フィールドに元のIDを指定して`type`を`derived`とマークします。複数のルール（`sysmon`と`builtin`）に変換できるルールについては、派生した`builtin`ルールにも新しいルールIDを作成する必要があります。これを行うには、`sysmon`ルールのIDのMD5ハッシュを計算し、それをUUIDv4 IDに使用します。以下は例です。

    元のSigmaルール:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    作成された`sysmon`ルール:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    作成された`builtin`ルール:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. ビルトインのWindowsイベントログを検出するルールは`builtin`ディレクトリに出力され、Sysmonログに依存するルールは、上流のSigmaリポジトリ内のディレクトリ構造に対応するサブディレクトリを持つ`sysmon`ディレクトリに出力されます。

## 変換の制限

現在のところ、唯一の[既知のバグ](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2)は、Sigmaルールのコメント行が、ソースコードに続くコメントでない限り、出力されたルールに含まれないことです。

## Sysmonとビルトインイベントの比較およびルール変換 { #sysmon-builtin-comparison }

### プロセス作成

* Category: `process_creation`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `1`
* Built-in log
    * Channel: `Security`
    * Event ID: `4688`

**比較**

![プロセス作成の比較](../assets/rules-doc/process_creation_comparison.png)

**変換の注意点**

1. `User`フィールドの情報は`SubjectUserName`と`SubjectDomainName`フィールドに分割する必要があります。
2. `LogonId`フィールド名は`SubjectLogonId`に変更され、16進数値の文字はすべて小文字にする必要があります。
3. `ProcessId`フィールド名は`NewProcessId`に変更され、値は16進数に変換する必要があります。
4. `Image`フィールド名は`NewProcessName`に変更されます。
5. `ParentProcessId`フィールド名は`ProcessId`に変更され、値は16進数に変換する必要があります。
6. `ParentImage`フィールド名は`ParentProcessName`に変更されます。
7. `IntegrityLevel`フィールド名は`MandatoryLabel`に変更され、以下の値変換が必要です。
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. ルールに`Security 4688`イベントにのみ存在する以下のフィールドが含まれている場合、`Sysmon 1`ルールは作成しません。
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. ルールに`Sysmon 1`イベントにのみ存在する以下のフィールドが含まれている場合、`Security 4688`ルールは作成しません。
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. #8および#9には例外があります。一方のログイベントにのみ存在するフィールドが使用されていても、そのフィールドが`OR`条件内にある場合は、そのルールを作成すべきです。たとえば、以下のルールは`OriginalFileName`フィールドが必須である（selection内が`AND`ロジックである）ため、`Security 4688`ルールを生成すべきでは**ありません**。

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    しかし、以下の条件を持つルールは、`OriginalFileName`がオプションである（selection内が`OR`ロジックである）ため、`Security 4688`ルールを作成す**べき**です。

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    難しいのは、パーサーがselectionの中だけでなく`condition`フィールド内のロジックも理解する必要がある点です。たとえば、以下のルールは`AND`ロジックを使用しているため、`Security 4688`ルールを作成すべきでは**ありません**。

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    しかし、以下のルールは`OR`ロジックを使用しているため、`Security 4688`ルールを作成す**べき**です。

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**そのほかの注意点**

* `Security 4688`の`SubjectUserSid`フィールドにはSIDが表示されますが、レンダリングされたイベントログの`Message`内では`DOMAIN\User`に変換されます。
* `Security 4688`イベントでは、設定によっては`CommandLine`にコマンドラインオプションの情報が含まれない場合があります。
* `TokenElevationType`は`Message`内でそのまま表示され、レンダリングされません。
* `MandatoryLabel`内の`S-1-16-4096`などは、レンダリングされた`Message`内で`Mandatory Label\Low Mandatory Level`などに変換されます。

**ビルトインのログ設定**

!!! warning "デフォルトでは有効になっていません"
    重要なビルトインの`Security 4688`プロセス作成イベントログは、デフォルトでは有効になっていません。Sigmaルールの大部分を使用するには、`4688`イベントとコマンドラインオプションのログ記録の両方を有効にする必要があります。

*グループポリシーで有効化:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*コマンドラインで有効化:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### ネットワークコネクション

* Category: `network_connection`
* Sysmon
    * Channel: `Microsoft-Windows-Sysmon/Operational`
    * Event ID: `3`
* Built-in log
    * Channel: `Security`
    * Event ID: `5156`

**比較**

![ネットワークコネクションの比較](../assets/rules-doc/network_connection_comparison.png)

**変換の注意点**

1. `ProcessId`フィールド名は`ProcessID`に変更されます。
2. `Image`フィールド名は`Application`に変更され、`C:\`は`\device\harddiskvolume?\`に変更されます。（注: ハードディスクのボリューム番号が分からないため、1文字のワイルドカード`?`に置き換えます。）
3. `Protocol`フィールドの値`tcp`は`6`に、`udp`は`17`に変更されます。
4. `Initiated`フィールド名は`Direction`に変更され、値`true`は`%%14593`に、`false`は`%%14592`に変更されます。
5. `SourceIp`フィールド名は`SourceAddress`に変更されます。
6. `DestinationIp`フィールド名は`DestAddress`に変更されます。
7. `DestinationPort`フィールド名は`DestPort`に変更されます。

**ビルトインのログ設定**

!!! warning "デフォルトでは有効になっていません"
    ビルトインの`Security 5156`ネットワーク接続ログは、デフォルトでは有効になっていません。これらは大量のログを生成し、`Security`イベントログ内の他の重要なログを上書きしてしまう可能性があり、ネットワーク接続数が多い場合はシステムの速度を低下させる可能性もあります。`Security`ログの最大ファイルサイズを大きく設定し、システムに悪影響がないことをテストで確認してください。

*グループポリシーで有効化:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*コマンドラインで有効化:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...英語以外のロケールを使用している場合は、以下のようになります。

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "関連情報"
    これらのルールが依拠する証跡を取得するために必要なビルトインWindowsイベントログの有効化について詳しくは、[Windowsのログ記録とSysmon](../resources/logging.md)と[EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings)プロジェクトを参照してください。

## Sigmaルール作成のアドバイス

!!! tip
    `sysmon`ログには存在するが`builtin`ログには存在しないフィールドを使用する場合は、`builtin`ログでもそのルールを使用できるように、そのフィールドを必ずオプションにしてください。

例:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

このselectionは、プロセス（`Image`）の名前が`addinutil.exe`である場合を検出します。問題は、攻撃者がこのルールを回避するために単にファイル名を変更できる点です。Sysmonのログにのみ存在する`OriginalFileName`フィールドは、コンパイル時にバイナリに埋め込まれるファイル名です。攻撃者がファイル名を変更しても、埋め込まれた名前は変更されません。そのため、このルールはSysmonを使用する際に攻撃者がファイル名を変更した攻撃を検出でき、標準のビルトインログを使用する際にはファイル名が変更されていない攻撃も検出できます。

## 変換済みのSigmaルール

このページで説明した方法で（`logsource`フィールドの抽象化を解除して）キュレーションされたSigmaルールは、[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)リポジトリの`sigma`フォルダにホスティングされています。

## 実行環境

SigmaルールをローカルでHayabusa互換形式に変換したい場合、まず[Poetry](https://python-poetry.org/)をインストールする必要があります。Poetryの公式[インストールドキュメント](https://python-poetry.org/docs/#installation)を参照してください。

## ツールの使い方

`sigma-to-hayabusa-converter.py`は、Sigmaルールの`logsource`フィールドをHayabusa互換形式に変換するための主要なツールです。これを実行するには、以下の作業を行ってください。

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

上記のコマンドを実行すると、Hayabusa互換形式に変換されたルールが`./converted_sigma_rules`ディレクトリに出力されます。
