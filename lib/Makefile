# lib/Makefile — libsymrdma 静态库
# 被 tests/programs/Makefile 与远端 build.sh 调用
# v0.24.3: SIR 控制通道源码独立到 ../sir/ (libsymrdma.a 与 libnprdma.so
# 共享同一编译单元, 本 Makefile 仍负责把它编入 libsymrdma.a)

CC       ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
CFLAGS  += -I../sir

# libibverbs 检测 (与 test/Makefile 一致, OFED 5.8 在 /usr/local)
HAVE_IBVERBS := $(shell pkg-config --exists libibverbs 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAVE_IBVERBS),1)
    IBV_CFLAGS  = $(shell pkg-config --cflags libibverbs)
else
    IBV_CFLAGS  = -I/usr/local/include
endif

all: libsymrdma.a

libsymrdma.o: libsymrdma.c libsymrdma.h libsymrdma_internal.h \
	../sir/pinbm.h ../sir/sentinel.h ../sir/vtpages.h
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -c -o $@ $<

SIR_SRCS = ../sir/sir.c ../sir/sir_channel.c ../sir/sir_service.c
SIR_HDRS  = ../sir/sir.h ../sir/sir_internal.h

sir.o: $(SIR_SRCS) $(SIR_HDRS)
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -c -o $@ ../sir/sir.c
sir_channel.o: $(SIR_SRCS) $(SIR_HDRS)
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -c -o $@ ../sir/sir_channel.c
sir_service.o: $(SIR_SRCS) $(SIR_HDRS)
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -c -o $@ ../sir/sir_service.c

libsymrdma_remote.o: libsymrdma_remote.c libsymrdma.h libsymrdma_internal.h \
	../sir/sir.h ../sir/sentinel.h
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -c -o $@ $<

libsymrdma.a: libsymrdma.o libsymrdma_remote.o sir.o sir_channel.o sir_service.o
	ar rcs $@ $^

clean:
	rm -f *.o *.a

.PHONY: all clean
