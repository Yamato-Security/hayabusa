# Downloads

Please download the latest stable version of Hayabusa with compiled binaries or compile the source code from the [Releases](https://github.com/Yamato-Security/hayabusa/releases) page.

We provide binaries for the following architectures:

- Linux ARM 64-bit GNU (`hayabusa-x.x.x-lin-aarch64-gnu`)
- Linux Intel 64-bit GNU (`hayabusa-x.x.x-lin-x64-gnu`)
- Linux Intel 64-bit MUSL (`hayabusa-x.x.x-lin-x64-musl`)
- macOS ARM 64-bit (`hayabusa-x.x.x-mac-aarch64`)
- macOS Intel 64-bit (`hayabusa-x.x.x-mac-x64`)
- Windows ARM 64-bit (`hayabusa-x.x.x-win-aarch64.exe`)
- Windows Intel 64-bit (`hayabusa-x.x.x-win-x64.exe`)
- Windows Intel 32-bit (`hayabusa-x.x.x-win-x86.exe`)

> [For some reason the Linux ARM MUSL binary does not run properly](https://github.com/Yamato-Security/hayabusa/issues/1332) so we do not provide that binary. It is out of our control, so we plan on providing it in the future when it gets fixed.

## Windows live response packages

As of v2.18.0, we are provide special Windows packages that use XOR-encoded rules provided in a single file as well as all of the config files combined into a single file (hosted at the [hayabusa-encoded-rules repository](https://github.com/Yamato-Security/hayabusa-encoded-rules)).
Just download the zip packages with `live-response` in the name.
The zip files just include three files: the Hayabusa binary, XOR-encoded rules file and the config file.
The purpose of these live response packages are for when running Hayabusa on client endpoints, we want to make sure that anti-virus scanners like Windows Defender do not give false positives on `.yml` rule files.
Also, we want to minimize the amount of files being written to the system so that forensics artifacts like the USN Journal do not get overwritten.
