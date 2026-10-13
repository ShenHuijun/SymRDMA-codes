/* libnprdma.h — LD_PRELOAD 透明引擎的用户接口 
 *
 * 拦截模式 (环境变量 NPRDMA_INTERCEPT, 见 nprdma.c 注释):
 *
 *   flag (默认 翻转; 不设即 flag):
 *     仅显式带 NPRDMA_MR_SYMRDMA 标记位的 MR 转 SymRDMA, 其余纯透传
 *     (vanilla pinned)。语义分层: 不挂 preload 的进程 / 挂了但未标记的
 *     MR / 挂了但模块未加载的进程 — 行为全部与原生 RDMA 一致, preload
 *     可常驻部署 (profile/容器镜像)。适用于: 同进程混合部署 (热路径数据
 *     pinned + 弹性内存 SymRDMA)、灰度切换、精确 A/B 对照。
 *       env LD_PRELOAD=~/pro/symrdma/nprdma/libnprdma.so ./your_app
 *
 *       mr = ibv_reg_mr(pd, buf, len, access | NPRDMA_MR_SYMRDMA);
 *
 *   all (显式开启):
 *     进程内所有 ibv_reg_mr 透明转为 SymRDMA — 未修改应用 (perftest
 *     等) 即获得 unpinned MR + IOMMU 双映射 + 哨兵/修复语义 (论文 §4.1)。
 *       env NPRDMA_INTERCEPT=all LD_PRELOAD=~/pro/symrdma/nprdma/libnprdma.so \
 *           ./your_app
 *
 * 降级闭环: /dev/symrdma 不可用 (模块未加载) → 本次进程所有
 * MR 剥位纯透传 + 一次性 stderr 告警 — 挂 preload 永不使行为劣于原生。
 *
 * 注意: NPRDMA_MR_SYMRDMA = uverbs optional 位 1<<21 (与 OFED 补丁
 * MLX5_IB_ACCESS_SYMRDMA 同值), 需 OFED 5.8 补丁版 (identity_mtt +
 * nopin) 内核配合; 未挂引擎时该位被 OFED 忽略 (MR 退 vanilla), 无害。
 * 挂引擎 + flag 模式时, 引擎识别该位做完整转换 (ioctl REG_MR +
 * auto-export + WREG 写区标记按 access 推导)。
 */
#ifndef _LIBNPRDMA_H
#define _LIBNPRDMA_H

#define NPRDMA_MR_SYMRDMA (1u << 21)   /* MR 级 SymRDMA 启用标记 */

/* 拦截模式取值 (供阅读; 运行时经环境变量 NPRDMA_INTERCEPT 设置, 非编译期) */
#define NPRDMA_INTERCEPT_FLAG "flag"  /* 默认: 仅带 NPRDMA_MR_SYMRDMA 的 MR */
#define NPRDMA_INTERCEPT_ALL  "all"   /* 显式开启: 全拦截 */

#endif /* _LIBNPRDMA_H */
