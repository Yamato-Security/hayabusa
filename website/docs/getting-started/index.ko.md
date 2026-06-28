# 다운로드

[Releases](https://github.com/Yamato-Security/hayabusa/releases) 페이지에서 컴파일된 바이너리가 포함된 Hayabusa 최신 안정 버전을 다운로드하거나 소스 코드를 컴파일하십시오.

다음 아키텍처용 바이너리를 제공합니다:

- Linux ARM 64비트 GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64비트 GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64비트 MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64비트 (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64비트 (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64비트 (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64비트 (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32비트 (`hayabusa-x.x.x-win-x86.exe`)

> [어떤 이유에서인지 Linux ARM MUSL 바이너리가 제대로 실행되지 않기](https://github.com/Yamato-Security/hayabusa/issues/1332) 때문에 해당 바이너리는 제공하지 않습니다. 이는 저희가 제어할 수 없는 부분이므로, 향후 문제가 해결되면 제공할 계획입니다.

## Windows 라이브 리스폰스 패키지

v2.18.0부터, 단일 파일로 제공되는 XOR 인코딩된 규칙과 단일 파일로 결합된 모든 설정 파일([hayabusa-encoded-rules 저장소](https://github.com/Yamato-Security/hayabusa-encoded-rules)에 호스팅됨)을 사용하는 특수 Windows 패키지를 제공합니다.
이름에 `live-response`가 포함된 zip 패키지를 다운로드하기만 하면 됩니다.
zip 파일에는 세 개의 파일, 즉 Hayabusa 바이너리, XOR 인코딩된 규칙 파일, 그리고 설정 파일만 포함되어 있습니다.
이러한 라이브 리스폰스 패키지의 목적은 클라이언트 엔드포인트에서 Hayabusa를 실행할 때 Windows Defender와 같은 안티바이러스 스캐너가 `.yml` 규칙 파일에 대해 오탐을 발생시키지 않도록 하기 위함입니다.
또한, USN Journal과 같은 포렌식 아티팩트가 덮어쓰이지 않도록 시스템에 기록되는 파일의 양을 최소화하고자 합니다.
