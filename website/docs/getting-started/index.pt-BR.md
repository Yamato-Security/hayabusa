# Downloads

Faça o download da versão estável mais recente do Hayabusa com binários compilados ou compile o código-fonte a partir da página de [Releases](https://github.com/Yamato-Security/hayabusa/releases).

Fornecemos binários para as seguintes arquiteturas:

- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [Por algum motivo, o binário Linux ARM MUSL não é executado corretamente](https://github.com/Yamato-Security/hayabusa/issues/1332), por isso não fornecemos esse binário. Isso está fora do nosso controle, então planejamos fornecê-lo no futuro quando o problema for corrigido.

## Pacotes de resposta ao vivo para Windows

A partir da v2.18.0, fornecemos pacotes especiais para Windows que utilizam regras codificadas em XOR fornecidas em um único arquivo, bem como todos os arquivos de configuração combinados em um único arquivo (hospedados no [repositório hayabusa-encoded-rules](https://github.com/Yamato-Security/hayabusa-encoded-rules)).
Basta fazer o download dos pacotes zip com `live-response` no nome.
Os arquivos zip incluem apenas três arquivos: o binário do Hayabusa, o arquivo de regras codificadas em XOR e o arquivo de configuração.
O objetivo desses pacotes de resposta ao vivo é, ao executar o Hayabusa em endpoints de clientes, garantir que scanners de antivírus como o Windows Defender não gerem falsos positivos em arquivos de regras `.yml`.
Além disso, queremos minimizar a quantidade de arquivos gravados no sistema para que artefatos forenses como o USN Journal não sejam sobrescritos.
