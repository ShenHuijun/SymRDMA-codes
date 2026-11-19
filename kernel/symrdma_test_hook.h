/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _SYMRDMA_TEST_HOOK_H
#define _SYMRDMA_TEST_HOOK_H

#include <linux/types.h>

/*
 * What a forced state change asks for.  This is the shape the forcing verb
 * speaks; the test face's own user ABI numbers the same three targets and the
 * test module is the one place that translates between them.
 */
enum symrdma_state_target {
	SYMRDMA_TGT_REAL      = 0,
	SYMRDMA_TGT_SENTINEL  = 1,
	SYMRDMA_TGT_BLACKHOLE = 2,
};

/*
 * The one collaboration point between this module and a test module.
 *
 * The test face lives in its own module, built only for test packages, with
 * its own device, its own ioctl numbers and its own parameters.  A separately
 * compiled module cannot call the static primitives here, and handing out the
 * iommu domain, the mm_state lock or the raw page array would trade an ioctl
 * backdoor for an exported one.  So exactly two things cross the boundary:
 *
 *   force_page_state  the provider side (this module) hands out one verb that
 *                     forces one page's state, so the test face can build the
 *                     states a test needs without touching the authority;
 *   demote_should_fail
 *                     the test side hands out one predicate, so a fault can be
 *                     injected into a demotion without this module learning
 *                     how to inject faults.
 *
 * Nothing here is reachable from user space: registering requires loading a
 * kernel module, and when no test module is loaded both reads are a NULL
 * check (fail-closed: no injection).
 */

struct symrdma_test_ops {
	/*
	 * Filled in by this module at register time.  Resolves the MR by id,
	 * checks that the caller owns its mm, and runs the state authority's
	 * verbs for `target` (enum symrdma_state_target).
	 */
	int  (*force_page_state)(int mr_id, unsigned long page_idx, int target);
	/*
	 * Filled in by the test module before registering.  Read on the
	 * demotion path; it must have no side effects and must not sleep.
	 */
	bool (*demote_should_fail)(unsigned int grp);
};

extern struct symrdma_test_ops __rcu *symrdma_test_ops_active;

/* Called by the test module: fills the provider half, publishes under RCU. */
int  symrdma_test_register(struct symrdma_test_ops *ops);
void symrdma_test_unregister(void);

/*
 * The demotion path's whole injection cost: one RCU read and a NULL check.
 * With no test module loaded this returns false and nothing else happens.
 */
static inline bool symrdma_test_demote_should_fail(unsigned int grp)
{
	struct symrdma_test_ops *ops;
	bool fail = false;

	rcu_read_lock();
	ops = rcu_dereference(symrdma_test_ops_active);
	if (ops && ops->demote_should_fail)
		fail = ops->demote_should_fail(grp);
	rcu_read_unlock();

	return fail;
}

#endif /* _SYMRDMA_TEST_HOOK_H */
