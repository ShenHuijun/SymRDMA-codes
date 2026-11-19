# SymRDMA

SymRDMA lets one-sided RDMA access **unpinned** remote virtual memory. NIC address
translation is delegated to the IOMMU: resident pages map to real memory, a
swapped-out page maps to a sentinel page (reads) or a black-hole page (writes), and
when the user-space library sees a sentinel it asks the page owner to repair the
mapping before retrying the access.

This release ships the mechanism only:

- `kernel/` — the `symrdma` kernel module (IOMMU domain, sentinel/black-hole pages,
  notifier, MR registration, repair),
- `ofed/` — the six MLNX_OFED driver source files the mechanism needs (whole files,
  not patches) plus `BASELINE`, the lineage manifest `sym build` checks against,
- `common/` — the shared `/dev/symrdma` ioctl ABI header,
- `nprdma/` — `libnprdma.so`, transparent interception (`LD_PRELOAD`,
  `NPRDMA_INTERCEPT`),
- `sir/` — the SIR (server-initiated repair) service,
- `base/` — `sym`, the machine-local installer:
  `sym build` (unprivileged) → `sym install` (privileged) → `sym env` → `sym uninstall`.

Development software and two-host functional tests are not shipped in this
production package. For an installation check, use plain RDMA connectivity
(step 5) plus the `/proc/symrdma` state (step 5). `sym build kind=test` therefore
refuses: that kind adds a fault-injection module which the release does not
distribute, and the default `kind=prod` is the shipped package.

## Implementation

The transparent library intercepts RDMA operations and maps native completions
back to application requests. Sentinel checks and version snapshots validate
one-sided transfers; SIR repairs missing pages using temporary pins and reverse
RDMA operations. Small writes use source snapshots and auxiliary readback, while
batched writes share a verification step. The transfer engine supports multiple
SGEs and extended QP posting. Completion channels preserve application CQ pointers,
contexts, notifications and acknowledgements.

## Requirements

Two RDMA test hosts, `host-a` (client side) and `host-b` (server side). Each host:

- a Mellanox/NVIDIA `mlx5` RDMA NIC; connect the two hosts directly or through a switch,
- an Intel CPU and platform with VT-d (the IOMMU does the translation),
- swap space (the mechanism is about swapped-out pages),
- Ubuntu 20.04.6 with Linux `5.11.0-46-generic`,
- MLNX_OFED `5.8-3.0.7.0` user space (step 3), with perftest **6.09** for functional verification,
- `gcc`, `make`, `pkg-config`, kernel headers for the running kernel, and `sudo`.

Install the build dependencies:

```bash
# host-a and host-b
sudo apt update
sudo apt install -y build-essential pkg-config linux-headers-$(uname -r)
```

`base/sym` is machine-local: it never talks to the network. Copy this tree to each
host (or clone it there) and run everything on that host.

## 1. Enable the IOMMU

```bash
# host-a and host-b
sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 intel_iommu=on iommu.strict=1"/' \
  /etc/default/grub
sudo update-grub
sudo reboot
```

After the reboot `cat /proc/cmdline` must contain `intel_iommu=on iommu.strict=1`.

## 2. Install MLNX_OFED and prepare the driver source tree

```bash
# host-a and host-b
wget https://content.mellanox.com/ofed/MLNX_OFED-5.8-3.0.7.0/MLNX_OFED_LINUX-5.8-3.0.7.0-ubuntu20.04-x86_64.tgz
tar xzf MLNX_OFED_LINUX-5.8-3.0.7.0-ubuntu20.04-x86_64.tgz
cd MLNX_OFED_LINUX-5.8-3.0.7.0-ubuntu20.04-x86_64 && sudo ./mlnxofedinstall --force && cd ..
ofed_info -s                     # MLNX_OFED_LINUX-5.8-3.0.7.0
```

`sym build` replaces six driver files with the versions this release ships, so it
needs an **unpacked and configured OFED kernel source tree**. Download the source
package and unpack it:

```bash
# host-a and host-b
wget https://content.mellanox.com/ofed/MLNX_OFED-5.8-3.0.7.0/MLNX_OFED_SRC-debian-5.8-3.0.7.0.tgz
tar xzf MLNX_OFED_SRC-debian-5.8-3.0.7.0.tgz
mkdir -p ~/sym-ofed
tar xzf MLNX_OFED_SRC-5.8-3.0.7.0/SOURCES/mlnx-ofed-kernel_5.8.orig.tar.gz -C ~/sym-ofed
cd ~/sym-ofed/mlnx-ofed-kernel-5.8
./configure --kernel-version=$(uname -r) --kernel-sources=/lib/modules/$(uname -r)/build \
  $(ofed_scripts/dkms_ofed $(uname -r) /lib/modules/$(uname -r)/build get-config) \
  --with-njobs=$(nproc)
```

`configure` prints `Created configure.mk.kernel` and `Type 'make' to build kernel
modules.` — do not run `make`; `sym build` drives the build itself.

**Source-drop requirement.** `ofed/BASELINE` records the digests of three files this
project never modifies, and `sym build` refuses any tree whose anchors differ (it
then touches nothing). The anchors identify the **MLNX_OFED 5.8-3.0.7.0** kernel
source drop this release ships drivers for — the same drop the untar command above
produces, **after** its own `configure` run for the release's kernel (the anchors are
the post-`configure` state, so configure for the same kernel before running `sym
build`). A tree from another MLNX_OFED drop, or configured for another kernel, is
rejected on purpose instead of being patched blindly. If your stack already carries the changes (`ib_umem_get_nopin` in
`/proc/kallsyms` and the `identity_mtt*` parameters on `mlx5_ib`), pass `--skip-ofed`
and skip this step entirely — `sym build` verifies that claim on the running kernel
rather than trusting it.

## 3. Build and install

```bash
# host-a and host-b, from the top of this tree
./base/sym build ofed=~/sym-ofed/mlnx-ofed-kernel-5.8
```

`sym build` needs no privileges. It checks the OFED lineage, copies the six driver
files over the tree, rebuilds the affected OFED modules (incremental — the first
build of an unconfigured tree takes minutes), then builds `kernel/` and
`nprdma/`. Then install, with the host's own NIC address:

```bash
# host-a and host-b
lspci -D | grep -i mellanox                                 # pick the port that faces the peer
sudo SYM_HOME=$HOME/sym ./base/sym install mode=1 pci_bdf=<domain:bus:dev.fn>
```

`install` runs `make install` for the rebuilt OFED modules, writes the identity-MTT
module parameters to `/etc/modprobe.d/mlx5_ib.conf`, reloads the IB stack (this
interrupts RDMA processes already running on the host) and loads `symrdma`. Both
`build` and `install` skip stages whose inputs are unchanged; `force=load` reloads
only the module.

## 4. Configure the runtime environment

```bash
# host-a and host-b
./base/sym env                     # writes $SYM_HOME/sym.env
source ~/sym/sym.env               # NP_RDMA_DEV, SYM_RDMA_IP, SYM_RDMA_GID, ...
```

`sym env` probes this host's RDMA port (device, netdev, RoCE GID index, MTU), merges
the install record and refuses to guess: on a host with more than one usable link it
lists the candidates and asks you to pin the choice in `$SYM_HOME/sym.conf`
(`SYM_IP=<address>` and/or `SYM_NETDEV=<name>`). It also verifies that the GID's IPv4
is the address the netdev actually carries.

## 5. Verify

```bash
# host-a and host-b
cat /proc/cmdline                                            # intel_iommu=on iommu.strict=1
grep -c ib_umem_get_nopin /proc/kallsyms                     # > 0
cat /sys/module/mlx5_ib/parameters/identity_mtt_write_offset # 34359738368
cat /sys/module/symrdma/parameters/mode                      # 1
head -8 /proc/symrdma
```

The PCI device must be the NIC you installed against and the domain mode must be
`NIC`. Then check plain RDMA connectivity — server first:

```bash
# host-b
ib_read_bw -d $NP_RDMA_DEV -x $SYM_RDMA_GID -s 4096 -n 1000 --report_gbits
# host-a
ib_read_bw -d $NP_RDMA_DEV -x $SYM_RDMA_GID -s 4096 -n 1000 --report_gbits <host-b RDMA IP>
```

`-x` is the **GID index on the local host** (perftest 6.09): take it from this host's
`sym.env`, it changes when addresses on the port change. Do not use `-D <seconds>` for
latency runs: it stretches a fixed iteration count over a time window and reports an
artifact. To run the same benchmark with transparent interception, preload the library
on **both** hosts. Use the perftest 6.09 binaries explicitly, with the server
started first. The SIR TCP endpoint is separate from the perftest port:

```bash
# host-b (server); use this host's sym.env values
export SYMRDMA_SIR_TCP=listen:18915
export SYMRDMA_SIR_GID=$SYM_RDMA_GID
export NPRDMA_INTERCEPT=all
LD_PRELOAD=$PWD/nprdma/libnprdma.so ~/perftest-6.09/ib_write_lat \
  -d "$NP_RDMA_DEV" -x "$SYM_RDMA_GID" -s 2 -n 1000

# host-a (client); use this host's sym.env values
export SYMRDMA_SIR_TCP="<host-b-address>:18915"
export SYMRDMA_SIR_GID=$SYM_RDMA_GID
export NPRDMA_INTERCEPT=all
LD_PRELOAD=$PWD/nprdma/libnprdma.so ~/perftest-6.09/ib_write_lat \
  -d "$NP_RDMA_DEV" -x "$SYM_RDMA_GID" -s 2 -n 1000 <host-b-RDMA-IP>
```

`NPRDMA_INTERCEPT=all` adopts every MR; it runs a preflight (`/dev/symrdma`, a
`REG_MR` round trip, `mode=1`, the identity-MTT parameters) and fails closed instead of
silently falling back.

## 6. Uninstall

```bash
# host-a and host-b
sudo SYM_HOME=$HOME/sym ./base/sym uninstall --purge
```

This unloads `symrdma`, removes the module parameters and the files under
`$SYM_HOME`. The rebuilt OFED modules stay installed; reinstall MLNX_OFED to return
the host to stock drivers.

## Layout and state

| Path | Contents |
| --- | --- |
| `base/` | `sym` and its stage library; the only entry point |
| `ofed/` | the six shipped driver files, `BASELINE`, and their provenance note |
| `kernel/`, `nprdma/`, `sir/`, `common/` | the mechanism |
| `$SYM_HOME` (`~/sym`) | `install.state` (install record), `sym.env`, `sym.conf` |

`sym --help` documents every command, argument and stage.

## License

GPL-2.0, see `LICENSE`. The kernel module links GPL-only kernel interfaces, which is
why the module and the code it builds with are GPL-2.0.
