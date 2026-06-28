# Hayabusa 실행하기

## 주의: 안티바이러스/EDR 경고 및 느린 실행 속도

탐지 시그니처에 `mimikatz` 같은 키워드나 의심스러운 PowerShell 명령어가 포함되어 있기 때문에, hayabusa를 실행하려고 하거나 단순히 `.yml` 규칙을 다운로드할 때 안티바이러스 또는 EDR 제품으로부터 경고를 받을 수 있습니다.
이는 오탐(false positive)이므로 hayabusa가 실행될 수 있도록 보안 제품에서 예외를 설정해야 합니다.
악성코드나 공급망 공격이 걱정된다면, hayabusa 소스 코드를 확인하고 직접 바이너리를 컴파일하시기 바랍니다.

특히 재부팅 후 첫 실행 시에는 Windows Defender의 실시간 보호 기능 때문에 실행 속도가 느려질 수 있습니다.
실시간 보호를 일시적으로 끄거나 hayabusa 실행 디렉터리를 예외로 추가하면 이를 피할 수 있습니다.
(이렇게 하기 전에 보안 위험을 고려해 주시기 바랍니다.)

## Windows

Command/PowerShell 프롬프트 또는 Windows Terminal에서, 적절한 32비트 또는 64비트 Windows 바이너리를 실행하기만 하면 됩니다.

### 경로에 공백이 있는 파일이나 디렉터리를 스캔하려고 할 때 발생하는 오류

Windows의 기본 제공 Command 또는 PowerShell 프롬프트를 사용할 때, 파일 또는 디렉터리 경로에 공백이 있으면 Hayabusa가 .evtx 파일을 로드하지 못했다는 오류를 받을 수 있습니다.
.evtx 파일을 제대로 로드하려면 다음 사항을 반드시 지켜 주세요:

1. 파일 또는 디렉터리 경로를 큰따옴표로 감쌉니다.
2. 디렉터리 경로인 경우, 마지막 문자에 백슬래시를 포함하지 않도록 주의합니다.

### 문자가 올바르게 표시되지 않음

Windows의 기본 글꼴인 `Lucida Console`에서는 로고와 표에 사용되는 다양한 문자가 제대로 표시되지 않습니다.
이를 해결하려면 글꼴을 `Consalas`로 변경해야 합니다.

이렇게 하면 종료 메시지에 표시되는 일본어 문자를 제외한 대부분의 텍스트 렌더링이 해결됩니다:

![Mojibake](../assets/screenshots/Mojibake.png)

이를 해결하기 위한 네 가지 옵션이 있습니다:

1. Command 또는 PowerShell 프롬프트 대신 [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/)을 사용합니다. (권장)
2. `MS Gothic` 글꼴을 사용합니다. 단, 백슬래시가 엔(Yen) 기호로 바뀝니다.
   ![MojibakeFix](../assets/screenshots/MojibakeFix.png)
3. [HackGen](https://github.com/yuru7/HackGen/releases) 글꼴을 설치하고 `HackGen Console NF`를 사용합니다.
4. `-q, --quiet`를 사용하여 일본어가 포함된 종료 메시지를 표시하지 않습니다.

## Linux

먼저 바이너리를 실행 가능하게 만들어야 합니다.

```bash
chmod +x ./hayabusa
```

그런 다음 Hayabusa 루트 디렉터리에서 실행합니다:

```bash
./hayabusa
```

## macOS

Terminal 또는 iTerm2에서, 먼저 바이너리를 실행 가능하게 만들어야 합니다.

```bash
chmod +x ./hayabusa
```

그런 다음 Hayabusa 루트 디렉터리에서 실행해 봅니다:

```bash
./hayabusa
```

최신 버전의 macOS에서는 실행하려고 할 때 다음과 같은 보안 오류를 받을 수 있습니다:

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

"Cancel"을 클릭한 다음 System Preferences에서 "Security & Privacy"를 열고 General 탭에서 "Allow Anyway"를 클릭합니다.

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

그 후 다시 실행해 봅니다.

```bash
./hayabusa
```

다음과 같은 경고가 나타나면 "Open"을 클릭해 주세요.

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

이제 hayabusa를 실행할 수 있을 것입니다.
