# Running Hayabusa

## Caution: Anti-Virus/EDR Warnings and Slow Runtimes

You may receive an alert from anti-virus or EDR products when trying to run hayabusa or even just when downloading the `.yml` rules as there will be keywords like `mimikatz` and suspicious PowerShell commands in the detection signature.
These are false positives so will need to configure exclusions in your security products to allow hayabusa to run.
If you are worried about malware or supply chain attacks, please check the hayabusa source code and compile the binaries yourself.

You may experience slow runtime especially on the first run after a reboot due to the real-time protection of Windows Defender.
You can avoid this by temporarily turning real-time protection off or adding an exclusion to the hayabusa runtime directory.
(Please take into consideration the security risks before doing these.)

## Windows

In a Command/PowerShell Prompt or Windows Terminal, just run the appropriate 32-bit or 64-bit Windows binary.

### Error when trying to scan a file or directory with a space in the path

When using the built-in Command or PowerShell prompt in Windows, you may receive an error that Hayabusa was not able to load any .evtx files if there is a space in your file or directory path.
In order to load the .evtx files properly, be sure to do the following:

1. Enclose the file or directory path with double quotes.
2. If it is a directory path, make sure that you do not include a backslash for the last character.

### Characters not being displayed correctly

With the default font `Lucida Console` on Windows, various characters used in the logo and tables will not be displayed properly.
You should change the font to `Consalas` to fix this.

This will fix most of the text rendering except for the display of Japanese characters in the closing messages:

![Mojibake](../assets/screenshots/Mojibake.png)

You have four options to fix this:

1. Use [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) instead of the Command or PowerShell prompt. (Recommended)
2. Use the `MS Gothic` font. Note that backslashes will turn into Yen symbols.
   ![MojibakeFix](../assets/screenshots/MojibakeFix.png)
3. Install the [HackGen](https://github.com/yuru7/HackGen/releases) fonts and use `HackGen Console NF`.
4. Use the `-q, --quiet` to not display the closing messages that contain Japanese.

## Linux

You first need to make the binary executable.

```bash
chmod +x ./hayabusa
```

Then run it from the Hayabusa root directory:

```bash
./hayabusa
```

## macOS

From Terminal or iTerm2, you first need to make the binary executable.

```bash
chmod +x ./hayabusa
```

Then, try to run it from the Hayabusa root directory:

```bash
./hayabusa
```

On the latest version of macOS, you may receive the following security error when you try to run it:

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

Click "Cancel" and then from System Preferences, open "Security & Privacy" and from the General tab, click "Allow Anyway".

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

After that, try to run it again.

```bash
./hayabusa
```

The following warning will pop up, so please click "Open".

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

You should now be able to run hayabusa.

## VHDX inputs

All event-log scanning commands accept `--vhdx` with `-f <IMAGE.vhdx>` or `-d <IMAGE_DIRECTORY>`. Directory discovery checks the supplied root and up to three subdirectory levels; the log search inside each image has no three-level limit. All readable NTFS volumes are searched.

```bash
# One image
./hayabusa dfir-timeline --vhdx -f host.vhdx -w -U -p verbose -o timeline.csv

# A directory of images
./hayabusa dfir-timeline --vhdx -d images/ -w -U -p verbose -o timeline.csv

# Inspect the logs inside the images
./hayabusa log-metrics --vhdx -d images/ -U -o logs.csv
```

Hayabusa reads NTFS files directly inside the images using the portable `ys-vhdx-mount` image API shared with Juntei. Native scanning works on **Linux, macOS, and Windows**, with no FUSE, mounting driver, mount helper, administrator privileges, or temporary log extraction. Each event log is opened as a seekable read-only stream, and the source images remain unchanged.

This input mode works with `dfir-timeline`, `search`, `eid-metrics`, `log-metrics`, `logon-summary`, `computer-metrics`, `extract-base64`, `pivot-keywords-list`, and `config-critical-systems`. Other options still apply, including `-J` for JSON event files on commands supporting JSON input. Use `--vhdx` explicitly: ordinary `-d` scans continue to look for event logs.

Evidence filenames use `host.vhdx!/Windows/.../Security.evtx`; multi-volume images include `Volume1`, `Volume2`, and so on. This identifies the image and internal path without relying on a mount path. Inputs cannot be reused as output files, including through symbolic or hard links.

Unreadable images, unreadable partitions, or images without matching logs cause a nonzero exit status. If some images or directories fail but usable logs remain, the scan still saves the readable results, including HTML reports and pivot files. The HTML report is marked incomplete and the command exits nonzero. Check the warnings to identify missing input. The backend reads NTFS volumes only. BitLocker-encrypted volumes and images requiring an external differencing parent are not supported by this input mode.

## E01/Ex01 inputs { #e01-inputs }

Use `--e01` to scan physical EWF1 (`.E01`) or EWF2 (`.Ex01`) images directly. This works with all the event-log scanning commands listed above, on Linux, macOS and Windows. No FUSE, mounting driver, helper program, administrator privileges, full-disk export or temporary log extraction is required.

```bash
# Start with the first segment; keep companion segments beside it.
./hayabusa dfir-timeline --e01 -f disk.E01 -w -U -p verbose -o timeline.csv

# Discover first segments through three subdirectory levels.
./hayabusa log-metrics --e01 -d images/ -U -o logs.csv

# Scan a directory containing both container formats.
./hayabusa dfir-timeline --vhdx --e01 -d images/ -w -U -o timeline.csv
```

The EWF reader decompresses accessed chunks into bounded memory caches. The portable NTFS reader then supplies seekable file streams directly to the EVTX or JSON parser (`-J` on commands supporting JSON input). It does not create extracted EVTX files or an OS-visible mount.

Only first-segment filenames (`.E01` and `.Ex01`, case-insensitive) are discovered. Other segments are opened automatically from the same directory; preserve their original names. Continuation files such as `.E02` are not separate inputs. Whole disks with NTFS partitions and bare NTFS volumes are supported. Evidence filenames retain the original image and internal path, such as `disk.E01!/Windows/System32/winevt/Logs/Security.evtx`; multi-volume images include `Volume1`, `Volume2`, and so on.

Every matching companion segment is protected against output replacement, including malformed companions and symbolic/hard-link aliases. If an image or accessed data is incomplete, Hayabusa retains readable results, reports the damage, marks HTML reports incomplete and exits nonzero. Acquisition-error sectors already recorded as zeros are explicitly reported. A successful scan is **not a full-media integrity verification**: it does not read every sector or compare the complete media against stored acquisition hashes.

The filesystem reader supports NTFS only. Logical `.L01`/`.Lx01` evidence, encrypted EWF images requiring a password, and BitLocker volumes are not supported by this input mode. Large images still need enough RAM for parser state, filesystem metadata and container caches, plus disk space for results. Image data is opened read-only.
