# OFED sources shipped by this repository

What ships here is **six whole source files** plus one `BASELINE` manifest —
not patches:

- `ib_core/modified/umem.c` -> `drivers/infiniband/core/umem.c`
- `ib_core/modified/ib_umem.h` -> `include/rdma/ib_umem.h`
- `mlx5_ib/modified/{mr.c,mem.c,main_ext.c,mlx5_ib.h}` ->
  `drivers/infiniband/hw/mlx5/<same name>`

The baseline is **the official MLNX_OFED 5.8-3.0.7.0 kernel source drop**
(the `MLNX_OFED_SRC` tarball, `mlnx-ofed-kernel_5.8.orig.tar.gz`), and the six
shipped files are that drop **after its own `configure`** — the official
backport pass that adapts the sources to the baseline kernel 5.11 — **plus
exactly two SymRDMA features**:

1. **no-pin umem** (`IB_UMEM_NOPIN`, `is_nopin`, `ib_umem_get_nopin`):
   registration neither pins pages (no GUP) nor charges `pinned_vm` nor
   dma-maps; release early-outs for a no-pin umem; `ib_umem_find_best_pgsz`
   guards the empty sg list.
2. **identity MTT** (`identity_mtt`, `identity_mtt_write_offset`,
   `identity_mtt_log_pgsize` module parameters, `mlx5_ib_populate_pas_identity`,
   the `MLX5_IB_ACCESS_SYMRDMA`/`_WREG` access bits and the identity branch in
   the mr.c paths): MTT entries are the user VA, translation is delegated to
   the system IOMMU where the SymRDMA kernel module has already mapped
   VA -> real PA / sentinel / blackhole.

Everything else in the shipped files is the official drop's own code,
byte-for-byte as its `configure` produces it. See the repository README for
the mechanism and `BASELINE` for the digests.

## How sym uses them

`sym build ofed=<tree>` expects `<tree>` to be **the kernel source tree of the
validated deployment** — the official 5.8-3.0.7.0 drop, unpacked and run
through its own `configure` (the same two steps the repository README
prescribes). Before copying anything, the build checks the lineage anchors:
three files this project never modifies (`uverbs_cmd.c`, `qp.c`,
`umem_odp.c`, listed in `BASELINE`) must byte-match the digests recorded
there. The anchors are the post-`configure` digests of those files — `sym
build` runs on the tree after the README's configure step, so this is the
state it actually sees; `BASELINE` also records the pristine pre-configure
digests for traceability. A tree that fails the anchors is not this OFED
build, and nothing is touched — distribution source trees such as
`/usr/src/mlnx-ofed-kernel-5.8` are rejected here by design. Once the anchors
pass, the six shipped files are copied over the tree (the pre-copy digests of
those files land in the install record for audit) and the tree is compiled
with its own `make`. The privileged `sym install` then installs the built
modules, writes the identity-MTT parameters under `/etc/modprobe.d/`, and
loads symrdma.

## Why whole files and not patches

The authoritative baseline exists and is reproducible: the official
`MLNX_OFED_SRC` tarball, unpacked and configured. A patch against it would
still be a diff against one specific kernel configuration — the drop's
`configure` rewrites the same six files differently per target kernel, so a
"patch" would silently claim to apply where it cannot. Shipping the six
post-`configure` files plus the two features, anchored by the digests of the
files around them, states exactly what is deployed and proves which tree it
belongs to. If the baseline release ever changes, `BASELINE` is the single
place to re-point the lineage gate at it.
