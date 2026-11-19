/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RDV_MEMORY_H
#define RDV_MEMORY_H
#include <stdint.h>
/* Process-local value capability, never serialized on peer wire. Core owns
 * original-registration captures and each F_DUPFD_CLOEXEC duplicate until the
 * matching SOURCE/SINK_RELEASED receipt proves all bridge MRs deregistered and
 * every real SYM PIN released. Actor/executor borrow dupfd; neither closes it.
 * No app MR/entry/PD/QP/CQ/order pointers may cross this boundary. */
enum sir_rdv_memory_kind {
 SIR_RDV_PROVIDER_GUP_ONLY=0, /* ordinary native/inline; provider MR owns GUP */
 SIR_RDV_SYM_PIN=1
};
struct sir_rdv_backend {
 uint32_t kind;
 int dupfd,mr_id;
 uint64_t registration_gen;
};
/* Actual authorized used bytes. A backend does not authorize any larger range.
 * cpu_address==0 is not a generic syntax error; original authority decides it.
 * A zero-length/unused segment needs no ioctl/provider MR. */
struct sir_rdv_span {
 uint64_t cpu_address,length,message_offset;
 struct sir_rdv_backend backend;
};
static inline int sir_rdv_backend_valid(const struct sir_rdv_backend *b)
{
 return b&&(b->kind==SIR_RDV_PROVIDER_GUP_ONLY||
  (b->kind==SIR_RDV_SYM_PIN&&b->dupfd>=0&&b->mr_id>=0&&b->registration_gen));
}
static inline int sir_rdv_backend_equal(const struct sir_rdv_backend *a,const struct sir_rdv_backend *b)
{
 if(!a||!b||a->kind!=b->kind)return 0;
 if(a->kind==SIR_RDV_PROVIDER_GUP_ONLY)return 1;
 return a->kind==SIR_RDV_SYM_PIN&&a->dupfd==b->dupfd&&a->mr_id==b->mr_id&&a->registration_gen==b->registration_gen;
}
#endif
