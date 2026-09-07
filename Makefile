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
       pcfg_gen.o pcfg_keyboard.o pcfg_multi.o pcfg_omen.o pcfg_utf8.o \
       pcfg_ahf.o yarn.o

pcfg: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c pcfg.h yarn.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f pcfg $(OBJS)

.PHONY: clean install install-bin install-man install-tools

# Man pages. Source only -- man renders per terminal width, locale and
# encoding, and every packager expects roff and compresses it itself.
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

install: install-bin install-tools install-man

install-bin: pcfg
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 pcfg $(DESTDIR)$(BINDIR)/

# tools/stylegen is a Python 3 script, not a build product, so it is installed
# rather than compiled and `make` does not depend on it. It has to keep running
# on Python 3.4.3, which is what the oldest machine carrying the corpora runs.
install-tools:
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 tools/stylegen $(DESTDIR)$(BINDIR)/

install-man:
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 644 man/man1/*.1 $(DESTDIR)$(MANDIR)/man1/
