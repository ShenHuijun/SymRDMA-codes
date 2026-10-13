# OFED 5.8 补丁

## identity_mtt.patch

**MTT identity mapping 补丁 (论文 §4.2)** — 让用户 MR 的 MTT 条目直接填用户 VA (IOVA == VA)，地址翻译完全交给系统 IOMMU —— SymRDMA 内核模块已在 NIC 的 IOMMU 域中映射 VA → 真实PA / 哨兵页 / 黑洞页。

> **命名辨析**: 这里的 "identity" 指 **MTT 条目 = 用户 VA**（IOVA==VA），硬件仍经 IOMMU 翻译（系统须保持 `intel_iommu=on` 翻译模式）。**不是** IOMMU passthrough 的 identity（IOVA==PA 不翻译，即 `iommu=pt`）——后者与 SymRDMA 互斥。
>
> **激活方式 (v0.11.0)**: `identity_mtt=0`（默认）按 MR 选择性激活 — 带 `SYMRDMA_ACCESS_IDENTITY` 标记位（uverbs optional 位 1<<21）的 MR 走 identity，普通应用完全原版路径（论文 "unaffected"）；`identity_mtt=1` 全局强制（所有用户 MR，未 hook 应用会 DMA fault）。
>
> **影响**: identity MR 的 DMA 缓冲区须有 SymRDMA IOMMU 映射（未映射 → DMA fault）；IOMMU 页表粒度 4KB（IOTLB 压力）。参数加载时固定（只读）。

修改点:

1. `main_ext.c`: 模块参数 `identity_mtt` (bool, 默认 0)
2. `mlx5_ib.h`: extern 声明 + `populate_pas_identity` 原型 + `mlx5_ib_mr.identity_womr` 字段
3. `mem.c`: `mlx5_ib_populate_pas_identity()` — identity 版本填表函数 (含写区域偏移)
4. `mr.c`: `reg_create`/`set_mr_fields` 标记写区域 + `reg_create` 直接路径 + `update_mr_pas` UMR 路径按参数切换
5. `mr.c`: ODP/dmabuf 注册在 identity_mtt 时返回 `-EOPNOTSUPP`

### 模块参数

| 参数 | 默认 | 说明 |
|------|------|------|
| `identity_mtt=1` | 0 | **0=按 MR 选择性** (带标记位 MR 走 identity, 普通应用原版); **1=全局强制** (所有用户 MR; QP/CQ/SRQ 仍走 dma IOVA) |
| `identity_mtt_log_pgsize=31` | 31 | **identity MTT 条目页大小 log2 (v0.17.0, 论文 §4.2)**: 31=2GB (mkc 5 位字段上限, NIC 原生大页) — 128GB MR 仅 64 条目, MTT cache 结构性不 miss; MKEY start_addr 自动下取整对齐 (rounded-start), 条目无需 VA 对齐; 置 12 回退 4KB 逐页 |
| `identity_mtt_write_offset=34359738368` | 0 | **写区域偏移 (32GB)**: 无 REMOTE_READ 的 MR (RDMA Write 目标 + LOCAL-only 接收 buffer) 的 MTT = VA + 偏移 → 命中 write_iova 黑洞区, 哨兵不被写入污染。取值须与内核模块 `SYMRDMA_MR_WRITE_OFFSET` 一致 |

```bash
# /etc/modprobe.d/mlx5_ib.conf  (双机部署: 按 MR 选择性激活, v0.11.0)
options mlx5_ib identity_mtt=0 identity_mtt_write_offset=34359738368
# identity_mtt=1 为全局强制 (所有用户 MR), 普通应用需挂 LD_PRELOAD
```

### 源码位置与补丁生成 (仓库自持, 无远端依赖)

```
ofed/mlx5_ib/
├── original/    # 原版基准 (OFED 5.8 未修改, 只读参考)
└── modified/    # 修改后文件 (git 跟踪, 直接在这里编辑)
ofed/ib_core/    # ib_umem no-pin 补丁 (ib_umem_nopin.patch)
```

- **生成补丁**: `bash scripts/regen_patch.sh` (本地 diff original → modified)
- **推送编译**: `bash scripts/ofed_push.sh` → 远端工作树编译 → `bash ~/pro/symrdma/scripts/update_mlx5.sh` (sudo 安装 + 重载 mlx5_ib)
- **应用补丁** (重建环境时): `cd <ofed树> && patch -p1 < <仓库>/ofed/patches/identity_mtt.patch`

## ib_umem_nopin.patch

**no-pin umem 补丁 (v0.9.0, 论文 §4.1 "remove pinning")** — `ib_umem_get_nopin()`:
identity MTT 模式下注册用户 MR 不 GUP (不 pin、不占 locked_vm 额度)、不 dma_map
(sg 留空)。翻译完全由 SymRDMA 的 IOMMU 映射承担; 换出页由 MMU notifier 重定向
哨兵/黑洞, REPAIR ioctl 按需换入。

修改点:

1. `ib_umem.h`: `IB_UMEM_NOPIN` flag + `ib_umem_get_nopin()` 声明 +
   `struct ib_umem.is_nopin` 位 (v0.15.0 下溢修复)
2. `umem.c`: `__ib_umem_get` 的 NOPIN 分支 (跳过 pin/dma_map,
   **置位 `is_nopin`**) + 新导出函数 +
   `ib_umem_find_best_pgsz` 空 sg 防护 (返回系统页大小) +
   `ib_umem_release` 跳过 pinned_vm 减法 (**v0.15.0: 修复下溢** —
   注册时不加 pinned_vm, release 无条件减会下溢成负数, 破坏后续
   create_cq/正常 MR 的 mlock 限额检查)
3. `mlx5 mr.c` (identity_mtt.patch 覆盖): identity 时注册走 nopin、
   `create_real_mr` 强制直接 CREATE_MKEY (UMR 路径按 sg 迭代, 空 sg 不可用)、
   rereg 拒绝 (-EOPNOTSUPP)

**限制**: identity 下大 MR 的直接填充受 kvzalloc 限制 (论文 2GB MTT 大页优化未实现);
rereg/FRMR 不支持。

**v0.15.0 pinned_vm 下溢修复**: 此补丁最初的 NOPIN 分支未标记 umem，导致
`ib_umem_release` 无条件减 `pinned_vm` 而注册时未加 → 下溢。已由
`is_nopin` 位修复（本补丁 v0.15.0 版本），由 L11 错误处理工具暴露。

**v0.21.0 适配 sgt_append 内核 + 双重释放修复** (host-a/host-b; 5.15 编译验证,
实际部署 5.11.0-46, 5.4 编译验证):
1. `ib_umem_find_best_pgsz` 空表判据条件化: `HAVE_SG_APPEND_TABLE`
   (sg_append_table 实际 5.12+ 才进内核; 5.15 探测=1, **5.11/5.4 实测=0**
   → 两世界走 nmap 分支) 下 struct ib_umem 无 `nmap` 成员, 判据等价换为
   `!umem->sgt_append.sgt.nents`; 否则保持 `!umem->nmap` (回归基线)。
   注意 `HAVE_*` 真源是 `compat/config.h` (autoconf, 经 EXTRA_KCFLAGS
   强制 -include), 不是 compat_autoconf.h —— make 会自动重探测内核。
   条件化设计在 5.15 (sgt_append) 与 5.11/5.4 (nmap) 两个世界各验证一次。
2. NOPIN 分支去掉多余 `free_page(page_list/vma_list)`: `out:` 出口本来就
   单次释放, 分支内先放是双重 free (第二次 put_page_testzero 对
   refcount-0 页静默 no-op, DEBUG_VM=y 下 VM_BUG_ON)。
3. `ib_umem_release` 对 `is_nopin` umem 整体跳过 `__ib_umem_release`:
   sgt_append 分支对零化表的 `ib_dma_unmap_sgtable_attrs` /
   `sg_free_append_table` 无守卫 (原版从不出现空表); nmap 分支跳过亦等价。

**v0.27.0 单一路径化: 5.15 支持移除** (2026-09-17, 双机 OFED 编译通过;
部署待 update_mlx5.sh 重载后回归):

- `ib_core/{umem.c,ib_umem.h}` 的全部多内核兼容分支按 **5.11.0-46
  configure 实测取值** (host-a `compat/config.h`) 解析为单一路径 —
  `HAVE_SG_APPEND_TABLE=0` (nmap/sg_head 布局) / `HAVE_ATOMIC_PINNED_VM=1`
  (5.11 的 `mm->pinned_vm` 已是 atomic64_t — 注意不是 5.12+ 才引入) /
  `HAVE_UNPIN_USER_PAGE_RANGE_DIRTY_LOCK_EXPORTED=0` /
  `HAVE_SG_ALLOC_TABLE_FROM_PAGES_GET_9_PARAMS=1` / `HAVE_LINUX_COUNT_
  ZEROS_H=1` / `HAVE_DMA_BUF_DYNAMIC_ATTACH_GET_4_PARAMS=1` /
  `HAVE_FOLL_LONGTERM=1` / `DMA_ATTR_WRITE_BARRIER` 无。上一节 v0.21.0
  的 sgt_append 条件化设计即由此终结 (历史决策记录保留)。
- 解析后 umem.c 净 -500 行条件编译; `ib_umem_nopin.patch` 932 行
  (含上游兼容分支删除 — **本补丁自此与 5.11 强绑定**, 5.12+ 因
  `struct ib_umem` 无 `nmap` 编译失败); `identity_mtt.patch` 不含版本
  分支, 保持版本无关 (mlx5_ib 侧上游 `HAVE_MMU_INTERVAL_NOTIFIER` 等
  未动)。
- 判定依据: 31 (docs/decisions.md; 沿革见 docs/HISTORY.md 附录 A)。
