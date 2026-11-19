
CC       ?= gcc
CFLAGS   ?= -O2 -g -Wall -Wextra -fPIC

HAVE_IBVERBS := $(shell pkg-config --exists libibverbs 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAVE_IBVERBS),1)
    IBV_CFLAGS  = $(shell pkg-config --cflags libibverbs)
    IBV_LDFLAGS = $(shell pkg-config --libs libibverbs)
else
    IBV_CFLAGS  = -I/usr/local/include
    IBV_LDFLAGS = -L/usr/local/lib -libverbs
endif

all: libnprdma.so

#
# Two build kinds, one tree.
#
#   BUILD_KIND=prod  (default)  the library with no injection entries
#   BUILD_KIND=test             plus npr_inject.c: the two entries a test
#                               carrier uses to fail one step on purpose
#
# The artifacts carry the same names: the kind is a property of the package,
# not a second library to choose from at load time. A production package has no
# injection symbols and no injection variable names in it at all.
#
BUILD_KIND ?= prod

override CFLAGS += -DNPR_PROGRESS_INTEGRATED=1

NPR_SRCS = npr_native_notify.c npr_mr_authority.c npr_rdv_rq.c npr_rendezvous.c npr_qp_connection.c npr_identity.c npr_sendrecv.c npr_progress.c nprdma.c npr_order.c nprdma_engine.c npr_emit.c npr_ex.c

ifeq ($(BUILD_KIND),test)
override CFLAGS += -DNPRDMA_TEST_INJECT=1
NPR_SRCS += npr_inject.c
endif

SIR_SRCS = ../sir/sir.c ../sir/app_qp_binding.c ../sir/app_rdv_mailbox.c \
	../sir/rdv_protocol.c ../sir/rdv_bridge.c ../sir/control_app_rdv.c \
	../sir/control_log.c ../sir/control_protocol.c ../sir/control_rpc.c \
	../sir/control_transport.c ../sir/control_executor.c \
	../sir/control_session.c ../sir/control_owner.c \
	../sir/control_runtime.c ../sir/endpoint_registry.c \
	../sir/control_reactor.c ../sir/control_rendezvous.c \
	../sir/control_trace.c ../sir/peer_registry.c

# Per-object, dependency-aware build: a one-file change recompiles one file, and
# a header change recompiles exactly the objects that include it (-MMD -MP). The
# old single-command shape had to be forced with -B, i.e. everything always.
OBJS := $(NPR_SRCS:.c=.o)
SIR_OBJS := $(notdir $(SIR_SRCS:.c=.o))
ALL_OBJS := $(OBJS) $(SIR_OBJS)

libnprdma.so: $(ALL_OBJS)
	$(CC) $(CFLAGS) -shared -Wl,-z,defs -o $@ $(ALL_OBJS) $(IBV_LDFLAGS) -ldl -lpthread

%.o: %.c
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -I../sir -I../common -MMD -MP -c -o $@ $<

$(SIR_OBJS): %.o: ../sir/%.c
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -I../sir -I../common -MMD -MP -fPIC -c -o $@ $<

-include $(ALL_OBJS:.o=.d)

clean:
	rm -f libnprdma.so *.o *.d

.PHONY: all clean
