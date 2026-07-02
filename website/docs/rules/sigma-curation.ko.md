# Windows 이벤트 로그를 위한 Sigma 룰 큐레이션

이 페이지에서는 Yamato Security가 Windows 이벤트 로그용 업스트림 [Sigma](https://github.com/SigmaHQ/sigma) 룰을 `logsource` 필드의 추상화를 해제하고 사용할 수 없거나 사용하기 어려운 룰을 걸러냄으로써 더 사용하기 쉬운 형태로 큐레이션하는 방법을 설명합니다. 이 작업은 [`sigma-to-hayabusa-converter`](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) 도구로 수행되며, 이 도구는 주로 [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)에서 호스팅되는 큐레이션된 Sigma 룰셋을 생성하는 데 사용됩니다. 이 룰셋은 [Hayabusa](https://github.com/Yamato-Security/hayabusa)와 [Velociraptor](https://github.com/Velocidex/velociraptor)에서 사용됩니다.

!!! info "출처"
    이 문서는 컨버터 도구 [Yamato-Security/sigma-to-hayabusa-converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter)와 함께 유지 관리됩니다. 이 정보가 Windows 이벤트 로그에서 공격을 탐지하기 위해 Sigma 룰을 사용하려는 다른 프로젝트에도 유용하기를 바랍니다. [룰 파일 생성](creating-rules.md)과 [필드 수정자](field-modifiers.md)도 참고하세요.

## 요약

* `logsource` 필드의 추상화를 해제하고 원래의 Sysmon 기반 룰뿐만 아니라 내장 룰을 위한 새로운 `.yml` 룰 파일을 생성하면 Sigma 룰의 완전한 내장 이벤트 지원이 더 쉬워지고, 분석가가 룰을 읽기 쉬워집니다.
* Windows 이벤트 로그용 Sigma 룰을 작성할 때는 원래의 Sysmon 기반 로그와 호환되는 내장 로그의 차이를 이해하는 것이 중요하며, 이상적으로는 두 로그 모두와 호환되도록 룰을 작성하는 것이 좋습니다.
* 많은 조직은 이를 처리할 전담 리소스가 없거나 Sysmon으로 인한 성능 저하나 충돌의 위험을 피하고 싶어서, 모든 Windows 엔드포인트에 Sysmon 에이전트를 설치하고 유지 관리할 수 없거나 원하지 않습니다. 이 때문에 가능한 한 많은 내장 이벤트 로그를 활성화하고, 그러한 내장 로그에서 공격을 탐지할 수 있는 도구를 사용하는 것이 중요합니다.

## Windows 이벤트 로그용 업스트림 Sigma 룰의 과제

저희의 경험상 Windows 이벤트 로그용 네이티브 Sigma 룰 파서를 만들 때 가장 큰 과제는 `logsource` 필드를 지원하는 것이었습니다. 현재 이는 매우 복잡하고 아직 진행 중인 작업이기 때문에 Hayabusa가 아직 네이티브로 지원하지 않는 몇 안 되는 기능 중 하나입니다. 당분간은 아래에서 자세히 설명하는 것처럼 업스트림 룰을 더 사용하기 쉬운 형식으로 변환하여 이 문제를 우회합니다.

### `logsource` 필드에 대하여

Windows 이벤트 로그용 Sigma 룰에서는 `product` 필드가 `windows`로 설정되고, 그 뒤에 `service` 필드 또는 `category` 필드가 이어집니다.

`service` 필드 예시:

```yaml
logsource:
    product: windows
    service: application
```

`category` 필드 예시:

```yaml
logsource:
    product: windows
    category: process_creation
```

#### Service 필드

`service` 필드는 처리하기가 비교적 간단하며, Sigma 룰을 사용하는 백엔드가 Windows XML 이벤트 로그의 `Channel` 필드를 기반으로 단일 채널 또는 여러 채널을 검색하도록 지시합니다.

**단일 채널 예시**

`service: application`은 Sigma 룰에 `Channel: Application` 선택 조건을 추가하는 것과 동일합니다.

**다중 채널 예시**

`service: applocker`는 AppLocker가 네 개의 서로 다른 로그에 정보를 저장하기 때문에 현재 검색해야 할 채널이 가장 많이 생성됩니다. AppLocker 로그만 제대로 검색하려면 Sigma 룰 로직에 다음 조건을 추가해야 합니다:

```yaml
Channel:
    - Microsoft-Windows-AppLocker/MSI and Script
    - Microsoft-Windows-AppLocker/EXE and DLL
    - Microsoft-Windows-AppLocker/Packaged app-Deployment
    - Microsoft-Windows-AppLocker/Packaged app-Execution
```

**현재 service 매핑 목록**

| 서비스                                     | 채널                                                                                                                                |
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

**service 매핑 출처**

저희는 서비스와 채널 이름을 매핑하는 YAML 매핑 파일을 만들었으며, 이를 주기적으로 유지 관리하고 컨버터 저장소에서 호스팅합니다. 이 파일들은 [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml)의 서비스 매핑 정보를 기반으로 합니다. 이것이 사람들이 사용할 수 있는 공식적인 범용 설정 파일로 보이지는 않지만, 가장 최신 정보인 것 같습니다.

#### Category 필드

대부분의 `category` 필드는 특정 `Channel`을 검색하는 것에 더해, `EventID` 필드에서 특정 이벤트 ID를 확인하는 조건을 단순히 추가합니다. 카테고리 이름은 대부분 [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) 이벤트를 기반으로 하며, 내장 PowerShell 로그와 Windows Defender를 위한 몇 가지 추가 카테고리가 있습니다.

**category 필드 예시**

```yaml
process_creation:
    EventID: 1
    Channel: Microsoft-Windows-Sysmon/Operational
```

**현재 category 매핑 목록**

일부 카테고리는 하나 이상의 service/EventID에 매핑됩니다(**굵게** 표시됨).

| 카테고리                  | 서비스             | 이벤트 ID                                                             |
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

**category 필드의 과제**

위에서 보듯이 동일한 `category`가 여러 service와 이벤트 ID를 사용할 수 있습니다(**굵게** 표시됨). 이는 룰이 사용하는 필드가 내장 이벤트 로그에도 존재한다면, `sysmon`용으로 설계된 일부 Sigma 룰을 유사한 내장 Windows `security` 이벤트 로그에 사용할 수 있음을 의미합니다. 이 경우 필드 이름 — 그리고 때로는 값도 — 을 내장 `security` 이벤트 로그의 필드 이름 및 값과 일치하도록 변환해야 할 수 있습니다. 특정 카테고리에서는 일부 필드 이름을 변경하는 것만큼 간단할 수 있지만, 다른 카테고리에서는 필드 값에 대한 다양한 변환도 필요할 수 있습니다. 이 변환을 수행하는 방법과 `sysmon` 로그와 `security` 로그 간의 호환성은 [아래](#sysmon-builtin-comparison)에서 자세히 설명합니다.

**category 매핑 출처**

카테고리를 위한 YAML 매핑 파일도 컨버터 저장소에서 호스팅되며, 마찬가지로 [SigmaHQ/sigma `tests/thor.yml`](https://github.com/SigmaHQ/sigma/blob/master/tests/thor.yml)의 정보를 기반으로 합니다.

## 로그 소스 추상화의 장점과 과제

로그 소스를 추상화하고 백엔드에서 서로 다른 `Channel`, `EventID` 및 필드에 대한 매핑을 만드는 것에는 장점과 과제가 모두 있습니다.

### 장점

1. Sigma 룰을 다른 백엔드 쿼리로 변환할 때 `Channel`과 `EventID` 필드 이름을 적절한 백엔드 필드 이름으로 변환하기가 더 쉬울 수 있습니다.
2. 두 개의 룰을 하나로 통합할 수 있습니다. 예를 들어, 프로세스 생성 이벤트는 `Sysmon 1`뿐만 아니라 `Security 4688`에도 기록될 수 있습니다. 서로 다른 채널, 이벤트 ID, 필드를 참조하지만 그 외에는 동일한 로직을 가진 두 개의 룰을 작성하는 대신, 필드를 Sysmon이 사용하는 것으로 표준화한 다음 백엔드 컨버터가 `Channel`과 `EventID` 필드를 추가하고 필요한 경우 다른 필드 정보를 변환하도록 할 수 있습니다. 이렇게 하면 유지 관리해야 할 룰이 적어지므로 룰 유지 관리가 더 쉬워집니다.
3. 매우 드물지만, 로그 소스가 데이터를 다른 `Channel`이나 `EventID`에 기록하기 시작하면, 모든 Sigma 룰을 업데이트하는 대신 매핑 로직만 업데이트하면 되므로 유지 관리가 더 쉬워집니다.

### 과제

1. Sysmon 기반의 원래 Sigma 룰이 오탐을 걸러내기 위해 내장 로그에 존재하지 않는 필드를 사용하는 경우 어떻게 될까요? 가능한 탐지를 우선시하여 어쨌든 룰을 만들어야 할까요, 아니면 오탐을 줄이는 것을 우선시하여 무시해야 할까요? 이상적으로는 사용자가 더 잘 처리할 수 있도록 서로 다른 `severity`, `status`, 오탐 정보를 가진 두 개의 룰을 만들어야 할 것입니다.
2. 룰 필터링이 더 어려워집니다. 파일이 아직 생성되지 않았다면 `.yml` 파일의 `Channel`이나 `EventID` 필드 또는 룰의 파일 경로를 기반으로 필터링할 수 없기 때문입니다 — 그것이 원래의 Sysmon 룰이 아니라 내장 로그를 위한 파생 룰이기 때문입니다. 또한 룰 ID가 동일하므로 룰 ID로 필터링할 수도 없습니다.
3. 알림이 Sysmon 로그에서 파생된 내장 로그용 룰에서 발생한 경우 알림을 확인하기가 더 어려워집니다. 필드 이름과 값이 일치하지 않으므로 분석가가 다소 복잡한 변환 과정을 이해해야 합니다.
4. 백엔드 로직을 만드는 것이 더 복잡해집니다.

첫 번째 문제에 대해서는 노력을 들일 만한 충분한 사용 사례가 있을 때 새로운 룰을 만들고 유지 관리하는 것 외에는 할 수 있는 것이 없지만, 2~4번 문제를 해결하기 위해 저희는 `logsource` 필드의 추상화를 해제하고 여러 룰을 생성할 수 있는 모든 룰에 대해 두 세트의 룰을 만들기로 결정했습니다. 내장 로그에서 공격을 탐지할 수 있는 룰은 `builtin` 디렉터리로 출력되고, Sysmon용 룰은 `sysmon` 디렉터리로 출력됩니다.

## 변환 예시

변환 과정을 더 잘 이해하기 위한 간단한 예시입니다.

**변환 전** — 원래 Sigma 룰:

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    condition: selection
```

**변환 후** — Sysmon 로그를 위한 Hayabusa 호환 룰:

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

...그리고 Windows 내장 로그를 위한 Hayabusa 호환 룰:

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

보시다시피 두 개의 룰이 생성되었습니다. 하나는 Sysmon 1 로그용이고, 다른 하나는 내장 Security 4688 로그용입니다. 채널과 이벤트 ID 정보를 담은 새로운 `process_creation` 조건이 추가되었으며, 이 조건을 요구하도록 `condition` 필드에 추가되었습니다. 또한 원래의 `Image` 필드 이름이 `NewProcessName`으로 변경되었습니다.

## 변환의 공통 사항

특정 카테고리를 어떻게 변환하는지 자세히 설명하기 전에, 모든 룰에 적용되는 변환 부분을 소개합니다.

1. `ignore-uuid-list.txt`에 ID가 있는 모든 룰은 무시됩니다. 현재는 `mimikatz`와 같은 키워드가 포함되어 있어 Windows Defender에서 오탐을 유발하는 룰만 무시합니다.
2. "플레이스홀더(placeholder)" 룰은 그대로 사용할 수 없기 때문에 무시됩니다. 이는 Sigma 저장소의 [`rules-placeholder`](https://github.com/SigmaHQ/sigma/tree/master/rules-placeholder/windows/) 폴더에 있는 룰입니다.
3. 호환되지 않는 필드 수정자를 사용하는 룰은 제외됩니다. Hayabusa는 대부분의 필드 수정자를 지원하므로, 컨버터는 파싱 오류를 피하기 위해 다음 이외의 수정자를 사용하는 룰을 출력하지 않습니다([필드 수정자](field-modifiers.md) 참고):

    `all`, `base64`, `base64offset`, `cased`, `cidr`, `contains`, `endswith`, `endswithfield`, `equalsfield`, `exists`, `fieldref`, `gt`, `gte`, `lt`, `lte`, `re`, `startswith`, `utf16`, `utf16be`, `utf16le`, `wide`, `windash`

4. 구문 오류가 있는 룰은 변환되지 않습니다.
5. `deprecated` 및 `unsupported` 룰의 태그는 모든 것을 일관되게 유지하고 Hayabusa에서 약어를 더 쉽게 처리하기 위해, `_` 대신 `-`를 사용하는 V2 형식으로 V1 형식에서 업데이트됩니다. 예: `initial_access`는 `initial-access`가 됩니다.
6. 룰에 `Channel`과 `EventID` 정보를 추가하기 때문에, 원래 ID의 MD5 해시를 사용하여 새로운 UUIDv4 ID를 생성하고, `related` 필드에 원래 ID를 지정하며, `type`을 `derived`로 표시합니다. 여러 룰(`sysmon` 및 `builtin`)로 변환될 수 있는 룰의 경우, 파생된 `builtin` 룰을 위한 새로운 룰 ID도 생성해야 합니다. 이를 위해 `sysmon` 룰 ID의 MD5 해시를 계산하고 이를 UUIDv4 ID로 사용합니다. 예를 들면:

    원래 Sigma 룰:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
    ```

    새로운 `sysmon` 룰:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
    ```

    새로운 `builtin` 룰:

    ```yaml
    title: 7Zip Compressing Dump Files
    id: 93586827-5f54-fc91-0b2f-338fd5365694
    related:
        - id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
        type: derived
        - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
        type: derived
    ```

7. 내장 Windows 이벤트 로그에서 탐지하는 룰은 `builtin` 디렉터리로 출력되고, Sysmon 로그에 의존하는 룰은 `sysmon` 디렉터리로 출력되며, 업스트림 Sigma 저장소의 디렉터리와 일치하는 하위 디렉터리를 갖습니다.

## 변환의 제약 사항

현재 알려진 [버그](https://github.com/Yamato-Security/sigma-to-hayabusa-converter/issues/2)는 하나뿐입니다: Sigma 룰의 주석 줄은 주석이 일부 소스 코드 뒤에 오지 않는 한 출력 룰에 포함되지 않습니다.

## Sysmon과 내장 이벤트 비교 및 룰 변환 { #sysmon-builtin-comparison }

### 프로세스 생성

* 카테고리: `process_creation`
* Sysmon
    * 채널: `Microsoft-Windows-Sysmon/Operational`
    * 이벤트 ID: `1`
* 내장 로그
    * 채널: `Security`
    * 이벤트 ID: `4688`

**비교**

![프로세스 생성 비교](../assets/rules-doc/process_creation_comparison.png)

**변환 참고 사항**

1. `User` 필드 정보는 `SubjectUserName`과 `SubjectDomainName` 필드로 분리해야 합니다.
2. `LogonId` 필드 이름은 `SubjectLogonId`로 변경되며, 16진수 값의 문자는 모두 소문자로 변환해야 합니다.
3. `ProcessId` 필드 이름은 `NewProcessId`로 변경되며, 값은 16진수로 변환해야 합니다.
4. `Image` 필드 이름은 `NewProcessName`으로 변경됩니다.
5. `ParentProcessId` 필드 이름은 `ProcessId`로 변경되며, 값은 16진수로 변환해야 합니다.
6. `ParentImage` 필드 이름은 `ParentProcessName`으로 변경됩니다.
7. `IntegrityLevel` 필드 이름은 `MandatoryLabel`로 변경되며, 다음과 같은 값 변환이 필요합니다:
    * `Low`: `S-1-16-4096`
    * `Medium`: `S-1-16-8192`
    * `High`: `S-1-16-12288`
    * `System`: `S-1-16-16384`
8. 룰에 `Security 4688` 이벤트에만 존재하는 다음 필드가 포함되어 있으면, `Sysmon 1` 룰을 생성하지 않습니다:
    * `SubjectUserSid`, `TokenElevationType`, `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId`
9. 룰에 `Sysmon 1` 이벤트에만 존재하는 다음 필드가 포함되어 있으면, `Security 4688` 룰을 생성하지 않습니다:
    * `RuleName`, `UtcTime`, `ProcessGuid`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `CurrentDirectory`, `LogonGuid`, `TerminalSessionId`, `Hashes`, `ParentProcessGuid`, `ParentCommandLine`, `ParentUser`
10. #8과 #9에는 예외가 있습니다: 한 로그 이벤트에만 존재하는 필드가 사용되더라도, 그 필드가 `OR` 조건에 있다면 여전히 해당 룰을 생성해야 합니다. 예를 들어, 다음 룰은 `OriginalFileName` 필드가 필수이기 때문에(선택 항목 내 `AND` 로직) `Security 4688` 룰을 생성해서는 **안 됩니다**:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
        OriginalFileName: AddInUtil.exe
    ```

    그러나 다음과 같은 조건을 가진 룰은 `OriginalFileName`이 선택적이기 때문에(선택 항목 내 `OR` 로직) `Security 4688` 룰을 생성해야 **합니다**:

    ```yaml
    selection_img:
        - Image|endswith: \addinutil.exe
        - OriginalFileName: AddInUtil.exe
    ```

    여기서 어려운 점은 파서가 선택 항목 내부의 로직뿐만 아니라 `condition` 필드 내부의 로직도 이해해야 한다는 것입니다. 예를 들어, 다음 룰은 `AND` 로직을 사용하기 때문에 `Security 4688` 룰을 생성해서는 **안 됩니다**:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img and selection_orig
    ```

    그러나 다음 룰은 `OR` 로직을 사용하기 때문에 `Security 4688` 룰을 생성해야 **합니다**:

    ```yaml
    selection_img:
        Image|endswith: \addinutil.exe
    selection_orig:
        OriginalFileName: AddInUtil.exe
    condition: selection_img or selection_orig
    ```

**기타 참고 사항**

* `Security 4688`의 `SubjectUserSid` 필드는 SID를 표시하지만, 렌더링된 이벤트 로그 `Message`에서는 `DOMAIN\User`로 변환됩니다.
* `Security 4688` 이벤트는 설정에 따라 `CommandLine`에 명령줄 옵션 정보를 포함하지 않을 수 있습니다.
* `TokenElevationType`은 `Message`에 그대로 표시되며 렌더링되지 않습니다.
* `MandatoryLabel` 내부의 `S-1-16-4096` 등은 렌더링된 `Message`에서 `Mandatory Label\Low Mandatory Level` 등으로 변환됩니다.

**내장 로그 설정**

!!! warning "기본적으로 활성화되어 있지 않음"
    중요한 내장 `Security 4688` 프로세스 생성 이벤트 로그는 기본적으로 활성화되어 있지 않습니다. 대부분의 Sigma 룰을 사용하려면 `4688` 이벤트와 명령줄 옵션 로깅을 모두 활성화해야 합니다.

*그룹 정책으로 활성화:*

* `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation`: `Enabled`
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`: `Enabled`

*명령줄로 활성화:*

```bat
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### 네트워크 연결

* 카테고리: `network_connection`
* Sysmon
    * 채널: `Microsoft-Windows-Sysmon/Operational`
    * 이벤트 ID: `3`
* 내장 로그
    * 채널: `Security`
    * 이벤트 ID: `5156`

**비교**

![네트워크 연결 비교](../assets/rules-doc/network_connection_comparison.png)

**변환 참고 사항**

1. `ProcessId` 필드 이름은 `ProcessID`로 변경됩니다.
2. `Image` 필드 이름은 `Application`으로 변경되며, `C:\`는 `\device\harddiskvolume?\`로 변경됩니다. (참고: 하드 디스크 볼륨 번호를 알 수 없기 때문에 단일 문자 와일드카드 `?`로 대체합니다.)
3. `Protocol` 필드 값 `tcp`는 `6`으로, `udp`는 `17`로 변경됩니다.
4. `Initiated` 필드 이름은 `Direction`으로 변경되며, 값 `true`는 `%%14593`으로, `false`는 `%%14592`로 변경됩니다.
5. `SourceIp` 필드 이름은 `SourceAddress`로 변경됩니다.
6. `DestinationIp` 필드 이름은 `DestAddress`로 변경됩니다.
7. `DestinationPort` 필드 이름은 `DestPort`로 변경됩니다.

**내장 로그 설정**

!!! warning "기본적으로 활성화되어 있지 않음"
    내장 `Security 5156` 네트워크 연결 로그는 기본적으로 활성화되어 있지 않습니다. 이 로그는 많은 양의 로그를 생성하여 `Security` 이벤트 로그의 다른 중요한 로그를 덮어쓸 수 있으며, 네트워크 연결 수가 많은 경우 시스템 속도를 저하시킬 수 있습니다. `Security` 로그의 최대 파일 크기를 크게 설정하고, 시스템에 부작용이 없는지 테스트하세요.

*그룹 정책으로 활성화:*

* `Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access -> Filtering Platform Connection`: `Success and Failure`

*명령줄로 활성화:*

```bat
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

...또는 영어가 아닌 로케일을 사용하는 경우 다음을 사용하세요:

```bat
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

!!! tip "함께 보기"
    이 룰들이 의존하는 증거를 수집하는 데 필요한 내장 Windows 이벤트 로그 활성화에 대한 자세한 내용은 [Windows 로깅 및 Sysmon](../resources/logging.md)과 [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) 프로젝트를 참고하세요.

## Sigma 룰 작성 조언

!!! tip
    `sysmon` 로그에는 존재하지만 `builtin` 로그에는 존재하지 않는 필드를 사용하는 경우, 해당 룰을 `builtin` 로그에도 사용할 수 있도록 그 필드를 선택적으로 만드세요.

예를 들면:

```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe
```

이 선택 항목은 프로세스(`Image`)의 이름이 `addinutil.exe`인 경우를 찾습니다. 문제는 공격자가 룰을 우회하기 위해 파일 이름을 바꾸기만 하면 된다는 것입니다. Sysmon 로그에만 존재하는 `OriginalFileName` 필드는 컴파일 시점에 바이너리에 삽입되는 파일 이름입니다. 공격자가 파일 이름을 바꾸더라도 삽입된 이름은 변경되지 않으므로, 이 룰은 Sysmon을 사용할 때 공격자가 파일 이름을 바꾼 공격을 탐지할 수 있고, 표준 내장 로그를 사용할 때 파일 이름이 변경되지 않은 공격도 탐지할 수 있습니다.

## 사전 변환된 Sigma 룰

이 페이지에서 설명한 방식으로 — `logsource` 필드의 추상화를 해제하여 — 큐레이션된 Sigma 룰은 [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) 저장소의 `sigma` 폴더 아래에서 호스팅됩니다.

## 도구 실행 환경

Sigma 룰을 로컬에서 Hayabusa 호환 형식으로 변환하려면 먼저 [Poetry](https://python-poetry.org/)를 설치해야 합니다. Poetry 공식 [설치 문서](https://python-poetry.org/docs/#installation)를 참고하세요.

## 도구 사용법

`sigma-to-hayabusa-converter.py`는 Sigma 룰의 `logsource` 필드를 Hayabusa 호환 형식으로 변환하는 저희의 주요 도구입니다. 이를 실행하려면 다음 작업을 수행하세요:

```bash
git clone https://github.com/SigmaHQ/sigma.git
git clone https://github.com/Yamato-Security/sigma-to-hayabusa-converter.git
cd sigma-to-hayabusa-converter
poetry install --no-root
poetry run python sigma-to-hayabusa-converter.py -r ../sigma -o ./converted_sigma_rules
```

위 명령을 실행하면 Hayabusa 호환 형식으로 변환된 룰이 `./converted_sigma_rules` 디렉터리로 출력됩니다.
