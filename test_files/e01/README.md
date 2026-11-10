# Native E01/Ex01 scan fixtures

These images contain only the existing public data from `../vhdx/`: its CC0 Security.evtx sample and Hayabusa JSON test events. They contain no private evidence. The CC0 license is retained beside the fixtures.

- `logs.E01` / `logs.E02`: EWF1, two segments, containing the bare NTFS volume of `logs.vhdx.gz` followed by 1,310,720 deterministic random bytes (`random.Random(1955).randbytes`). The padding forces a split while leaving the NTFS evidence unchanged.
- `logs.Ex01`: the same decoded media in EWF2 format.
- `two-volumes.Ex01`: the MBR disk from `two-volumes.vhdx.gz`, including two NTFS partitions with identical test logs.

Written independently with libewf `ewfacquire` 20260924 and checked byte-for-byte using pyewf against the original decoded VHDX media. Only newly generated fixture files were written. Runtime code does not use libewf, Python, FUSE, or extraction helpers.

```bash
ewfacquire -u -t logs -f encase6 -c deflate:best -S 1MiB -C HAYABUSA-TEST \
  -D "Public native event log scan fixture" -E Hayabusa -e "Yamato Security" \
  -N "Existing public CC0 Hayabusa VHDX test data" -m fixed -M physical -b 64 -q logs-padded.raw
```

For EWF2 use `-f encase7-v2 -S 2GiB`, with either decoded source media.

SHA-256 of the encoded files:

```text
b2386841b142151bb686e2317e15f45ed643fb2e2bb3534475e561da82650ab9  logs.E01
8b585c8e14239c6b388b1c1608005a810567c1ce6360a8a8f2317c372e416818  logs.E02
57dda5fa61858d172ce33872dc4c0e53925c20d698ebbe75e35e6436fd5bd542  logs.Ex01
bad293795636e5b78f0e2dda285a098fb9b587bcecef57a08e8d642be92b9afc  two-volumes.Ex01
```

Decoded media:

- `logs.E01`: 34865152 bytes; SHA-256 `dd1549376513ee9c1b38fd8e9865acb3dea544d5416c01e8bce443ca3e7e8727`.
- `logs.Ex01`: 34865152 bytes; SHA-256 `dd1549376513ee9c1b38fd8e9865acb3dea544d5416c01e8bce443ca3e7e8727`.
- `two-volumes.Ex01`: 69206016 bytes; SHA-256 `bf07c42d0311bd0c1cb8a9d2b26f18e43159e8868cb463e54679b2e0d122d7dd`.
