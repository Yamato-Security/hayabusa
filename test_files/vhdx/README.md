# VHDX scan fixtures

These small images contain public laboratory data and synthetic NTFS metadata; they contain no private investigation evidence.

- `logs.vhdx.gz`: a dynamically allocated VHDX containing one bare NTFS volume. Its root contains `Security.evtx` and `events.json`.
- `two-volumes.vhdx.gz`: an MBR disk with two NTFS partitions containing the same files, testing the SDK's `Volume1` and `Volume2` paths.
- `Security.evtx`: the unchanged [scheduled-task creation sample](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) from mdecrevoisier's EVTX-to-MITRE-Attack collection, under CC0 1.0. Its licence is in `LICENSE-CC0.txt`. It contains four Security events, including task-creation evidence.
- `events.json` inside each volume is Hayabusa's existing `test_files/evtx/test.json`.
- `events.yml` is a regression-test rule; it is not part of the production ruleset.

The images were built by formatting a 32 MiB regular file with `mkntfs`, adding the two files with `ntfscp`, and wrapping the resulting bytes in a VHDX container. The two-volume disk uses an MBR with type 0x07 partitions starting at LBA 2048 and immediately after the first volume. Only newly generated files were written. Container encoding used Juntei's existing public test-fixture generator; the generator is not included or required at runtime. Equivalent containers can be produced with `qemu-img convert -f raw -O vhdx -o subformat=dynamic` and compressed with gzip.

Compressed fixture SHA-256:

```text
61a2a79ec230696b0d93339d0659d61dd8518c1ade6a8659bbd9c8d4c25fcb13  logs.vhdx.gz
1d7dbb3db6b1b13f9a9abee8b5b63a242ad8c45a87af16c3bd7c094204254f07  two-volumes.vhdx.gz
```

The integration tests require Linux, `/dev/fuse`, and `fusermount3`. Set `HAYABUSA_REQUIRE_FUSE=1` to fail instead of skipping when FUSE is unavailable. Ordinary scanning and all portable discovery/CLI tests run without FUSE.
