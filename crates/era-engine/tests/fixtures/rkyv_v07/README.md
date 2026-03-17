# rkyv 0.7 compatibility fixture

This directory contains a pre-upgrade archive fixture generated before the
workspace `rkyv` migration.

- File: `sample_archive.era`
- Password: `fixture-pass`
- Original payload: `input.txt` containing `rkyv07 fixture payload\n`
- Generation profile:

```bash
ArchiveWriter::builder(...)
  .password("fixture-pass")
  .config(no_compression + no_erasure)
  .max_volume_size(8 GiB)
  .enable_small_file_packing(false)
  .add_bytes("input.txt", b"rkyv07 fixture payload\n")
  .finalize()
```

The fixture exists to prove that archives written before the `rkyv 0.8`
migration remain readable and appendable.
