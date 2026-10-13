/* mlockall_shim.c — no-PF 带宽矩阵的驻留保证 (scripts/run_nopf_bw.sh 专用)
 *
 * 背景 (双机实测): no-pin MR 不走 GUP, 当 OS 回收/迁移测试 buffer
 * 页 (kswapd 换出 / khugepaged 合并 / NUMA balancing 迁移) 时, MMU notifier
 * 的 IOMMU unmap→remap 存在窗口, 在飞的 DMA 读在窗口内被断 → NIC 上报
 * LOC_PROT_ERR (syndrom 0x51) → QP flush (400K 迭代持续写 3 跑 2 挂)。
 * bare 路径页被 GUP pin 死, 天然免疫 — 这是 bare 过 / sym 挂的根因。
 *
 * 本 shim 在构造期 mlockall(MCL_CURRENT|MCL_FUTURE) 锁定全部内存: 页不再被
 * 换出/迁移/合并 → IOMMU 映射全程稳定 → 论文 no-PF 前提 ("working set is
 * naturally resident") 严格成立。不拦截任何符号、不含 SymRDMA 逻辑,
 * bare/sym 两侧同挂保证条件对齐。memlock rlimit 需 unlimited (host-a/8
 * 实测 unlimited; 不足时构造期打印告警, 此时 no-PF 前提不成立, 数据无效)。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

__attribute__((constructor))
static void npfbw_mlockall(void)
{
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		fprintf(stderr, "[mlockall_shim] mlockall 失败: %s — no-PF 前提不成立!\n",
			strerror(errno));
}
