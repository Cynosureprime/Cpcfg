# Cpcfg Makefile — portable across macOS, Linux, FreeBSD

CC = cc
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Architecture
ifeq ($(UNAME_M),x86_64)
  ARCHOPT = -DINTEL -mssse3
else ifeq ($(UNAME_M),i386)
  ARCHOPT = -DINTEL -msse
else ifeq ($(UNAME_M),i686)
  ARCHOPT = -DINTEL -msse
else ifeq ($(UNAME_M),aarch64)
  ARCHOPT = -DARM=8
else ifeq ($(UNAME_M),armv7l)
  ARCHOPT = -DARM=7
else
  ARCHOPT =
endif

# OS
ifeq ($(UNAME_S),Darwin)
  OSOPT = -DMACOSX
  INCEXTRA = -I/opt/local/include
  LDEXTRA = -L/opt/local/lib
else ifeq ($(UNAME_S),FreeBSD)
  OSOPT =
  INCEXTRA = -I/usr/local/include
  LDEXTRA = -L/usr/local/lib
else
  OSOPT =
  INCEXTRA =
  LDEXTRA =
endif

# GCC needs -fgnu89-inline for yarn.c inline functions
ifneq ($(UNAME_S),Darwin)
  OSOPT += -fgnu89-inline
endif

CFLAGS = -fomit-frame-pointer -pthread -O3 $(ARCHOPT) $(OSOPT) $(INCEXTRA)
LDFLAGS = -pthread $(LDEXTRA)
LIBS = -lJudy -lpthread -lm

OBJS = pcfg.o pcfg_parse.o pcfg_train.o pcfg_save.o pcfg_queue.o \
       pcfg_gen.o pcfg_keyboard.o pcfg_multi.o pcfg_omen.o yarn.o

pcfg: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c pcfg.h yarn.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f pcfg $(OBJS)

.PHONY: clean
