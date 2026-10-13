# nprdma/Makefile — libnprdma.so (LD_PRELOAD 拦截库 + M2 透明引擎)
# 含 ../sir/sir.c (SIR 自动双向修复通道, v0.18.0; v0.24.3 起源码在 sir/); 被 build.sh 在远端调用

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

NPR_SRCS = nprdma.c nprdma_engine.c

SIR_SRCS = ../sir/sir.c ../sir/sir_channel.c ../sir/sir_service.c

libnprdma.so: $(NPR_SRCS) nprdma_internal.h $(SIR_SRCS) ../sir/sir.h \
		../sir/sir_internal.h ../sir/pinbm.h ../sir/sentinel.h ../sir/vtpages.h
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -I../sir -shared -o $@ \
		$(NPR_SRCS) $(SIR_SRCS) $(IBV_LDFLAGS) -ldl -lpthread

clean:
	rm -f libnprdma.so

.PHONY: all clean
