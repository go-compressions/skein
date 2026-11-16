# skein

Pure-Go Skein-512 (Skein 1.3), with key (MAC) pre-processing and any output
length. It is a port of the OpenZFS implementation, zfs-2.3.0
`module/icp/algs/skein/skein.c` and `skein_block.c` (Doug Whiting, public
domain), and exists so that ZFS pool checksums (`checksum=skein`, which is
Skein-512-256 keyed with the pool checksum salt) can be verified in Go.

```go
d := skein.New(256, salt) // salt: the 32-byte org.illumos:checksum_salt
d.Write(block)
sum := d.Sum(nil)
```

`New(256, nil)` is plain Skein-512-256 (empty message:
`39ccc455...2621`). `Clone` copies a keyed state, the analogue of the ZFS
context template.

## Verification

`testdata/openzfs-2.3.0-vectors.txt` holds 1092 vectors (message lengths
0..260 plus 383..65536; unkeyed 256, salted 256, 17-byte key 512, 1000-bit
output) produced by compiling the OpenZFS C sources verbatim behind a small
shim and running them; every line is checked by `go test`.

## Performance

Single core, Apple M4 Max, Skein-512-256 keyed, from a cloned template,
OpenZFS C compiled with `clang -O2` (`SKEIN_LOOP` default, unrolled):

| size  | OpenZFS C | this package |
|-------|-----------|--------------|
| 4 KiB | 591 MB/s  | 660 MB/s     |
| 128 KiB | 599 MB/s | 662 MB/s    |
