# Makefile for libsecutils
#
# Copyright (c) Siemens Mobility GmbH, 2021
#
# Authors:
#  David von Oheimb <David.von.Oheimb@siemens.com>
#
# This work is licensed under the terms of the Apache Software License 2.0.
# See the COPYING file in the top-level directory.
#
# SPDX-License-Identifier: Apache-2.0

# Optional OPENSSL_DIR defines absolute or relative (to ../) path to OpenSSL installation.
# Optional OUT_DIR defines absolute or relative (to ./) path where library be produced.
# Optional DEBUG_FLAGS may set to prepend to local CFLAGS and LDFLAGS (default see below).

ROOTFS ?= $(DESTDIR)$(prefix)

OUT_DIR ?= .

VERSION=1.0
# must be kept in sync with latest version in debian/changelog
# PACKAGENAME=libsecutils
# DIRNAME=$(PACKAGENAME)-$(VERSION)

SHELL=bash # This is needed for supporting extended file name globbing

ifeq ($(OS),Windows_NT)
    EXE=.exe
    DLL=.dll
    OBJ=.obj
    LIB=bin
else
    EXE=
    DLL=.so
    OBJ=.o
    LIB=lib
endif

ifeq ($(OPENSSL_DIR),)
    OPENSSL_DIR=$(ROOTFS)/usr
endif
ifeq ($(shell echo $(OPENSSL_DIR) | grep "^/"),)
# $(OPENSSL_DIR) is relative path, assumed relative to ../
    OPENSSL=../$(OPENSSL_DIR)
    OPENSSL_LIB=../$(OPENSSL_DIR)
else
# $(OPENSSL_DIR) is absolute path
    OPENSSL=$(OPENSSL_DIR)
    OPENSSL_LIB=$(OPENSSL_DIR)/$(LIB)
endif

################################################################################
# Basic definitions targeted at debugging
#
# Can be overridden by command line arguments (not ENV variables!)
# Note: stuff for testing purposes should go here
################################################################################

ifdef DEBUG
    DEBUG_FLAGS ?= -g -O0
# Add this to get some additional runtime checks.
# Warning: it's incompatible with tools like Valgrind and you have to add it to the app using this lib too
#	DEBUG_FLAGS += -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all
else
    DEBUG_FLAGS ?= -O2
    override DEBUG_FLAGS += -DNDEBUG=1
endif

override CFLAGS += $(DEBUG_FLAGS) -Wall -Woverflow -Wextra -Wswitch -Wmissing-prototypes -Wstrict-prototypes -Wformat -Wtype-limits -Wundef -Wconversion
override CFLAGS += -Wno-shadow -Wno-conversion -Wno-sign-conversion -Wno-sign-compare -Wno-unused-parameter # TODO clean up code and enable -Wshadow -Wconversion -Wsign-conversion -Wsign-compare -Wunused-parameter
override CFLAGS += -Wformat -Wformat-security -Wno-declaration-after-statement -Wno-vla # -Wpointer-arith -pedantic -DPEDANTIC # -Werror

################################################################################
# Obligatory flags
#
# Can not be overriden
################################################################################

CC ?= gcc
OUTLIB=libsecutils$(DLL)
DEST_LIB=$(ROOTFS)/usr/lib
DEST_DOC=$(ROOTFS)/usr/share/doc/libsecutils# TODO improve
OUTBIN=icvutil$(EXE)
DEST_BIN=$(ROOTFS)/usr/bin
LOCAL_CFLAGS=-std=gnu90 -fPIC
override CFLAGS += -D_FORTIFY_SOURCE=2
override CFLAGS += -isystem $(OPENSSL)/include# # # use of -isystem is critical for selecting wanted OpenSSL version
override CFLAGS += -Iinclude
override CFLAGS += -Iinclude/secutils
ifdef SECUTILS_USE_UTA
    override CFLAGS += -DSECUTILS_USE_UTA=1
endif
ifdef SECUTILS_CONFIG_USE_ICV
    override CFLAGS += -DSECUTILS_CONFIG_USE_ICV=1
endif

override LDFLAGS += $(DEBUG_FLAGS) # needed for -fsanitize=...
override LDFLAGS += -L$(OPENSSL_LIB) -L$(OPENSSL)
ifeq ($(DEB_TARGET_ARCH),) # not during Debian packaging
    override LDFLAGS += -Wl,-rpath=$(OPENSSL_LIB) -Wl,-rpath=$(OPENSSL) # needed for genCMPClient
endif
ifdef SECUTILS_USE_UTA
    override LDFLAGS += -luta
endif
ifdef SECUTILS_NO_TLS
    override CFLAGS += -DSECUTILS_NO_TLS=1
else
    override LDFLAGS += -lssl
endif
override LDFLAGS += -shared -lcrypto

ifeq ($(COMPILE_TYPE), code_coverage)
    override CFLAGS += --coverage
    override LDFLAGS += --coverage
	COV_ENABLED=1
    unexport COMPILE_TYPE
endif

################################################################################
# Helper variables
################################################################################

# Directory for object files
BUILDDIR=tmp

# Path for automatic lookup of source files by Make
# Note: sort removes duplicate entries
VPATH := src
VPATH += $(sort $(dir $(wildcard src/*/)))

################################################################################
# Objects lists
################################################################################

# Target object files lookup in src directory (and mapping to build directory)
OBJS := $(patsubst %.c,$(BUILDDIR)/%$(OBJ),$(notdir $(wildcard src/*/*.c)))

################################################################################
# Targets
################################################################################

# Phony (non-file) targets
.PHONY: all doc util build build_only build_all clean clean_all clean_uta install uninstall deb clean_deb coverage

# Default target
all: build_all doc

build_only: $(OUT_DIR)/$(OUTLIB)

build:
ifeq ($(COV_ENABLED), 1)
	COMPILE_TYPE=code_coverage
endif
	$(MAKE) COMPILE_TYPE=$(COMPILE_TYPE) build_only

util: $(OUT_DIR)/$(OUTLIB)
	$(MAKE) -C util SECUTILS_USE_UTA="$(SECUTILS_USE_UTA)" \
	   CFLAGS="$(CFLAGS) $(LOCAL_CFLAGS)" LDFLAGS="$(LDFLAGS)"

build_all:
	$(MAKE) build
	$(MAKE) util

# Binary output target
$(OUT_DIR)/$(OUTLIB).$(VERSION): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@ -Wl,-soname,$(OUTLIB).$(VERSION)

$(OUT_DIR)/$(OUTLIB): $(OUT_DIR)/$(OUTLIB).$(VERSION)
	ln -sf $(OUTLIB).$(VERSION) $(OUT_DIR)/$(OUTLIB)

# Individual object targets; also provide dependencies on header files of the project (not on system headers)
$(BUILDDIR)/%$(OBJ): %.c
	 $(CC) $(CFLAGS) $(LOCAL_CFLAGS) -c $< -o $@
	@$(CC) $(CFLAGS) $(LOCAL_CFLAGS) -MM $< -MT $@ -MF $(BUILDDIR)/$*.d
DEPS = $(OBJS:$(OBJ)=.d)
ifeq ($(findstring clean,$(MAKECMDGOALS)),)
-include $(DEPS)
endif

# Build directory generation
$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Order-only dependency for objects on build dir - prevents unnecessary rebuilds
# (directories are flagged as changed on every object build)
$(OBJS): | $(BUILDDIR)

deb:
	debuild --preserve-envvar SECUTILS_CONFIG_USE_ICV \
	  --preserve-envvar SECUTILS_USE_UTA -uc -us \
	  --lintian-opts --profile debian # --fail-on none
# alternative:
#	LD_LIBRARY_PATH= dpkg-buildpackage -uc -us # may prepend DH_VERBOSE=1

clean_deb:
	rm -rf debian/tmp debian/libsecutils{,-dev,-bins}
	rm -f debian/{files,debhelper-build-stamp} debian/*.{log,substvars}
	rm -f ../libsecutils{_,-}*

# installation target - append ROOTFS=<path> to install into virtual root
# filesystem
install: doc/html # $(OUT_DIR)/$(OUTLIB)
	install -D $(OUT_DIR)/$(OUTLIB).$(VERSION) $(DEST_LIB)/$(OUTLIB).$(VERSION)
	ln -sf $(OUTLIB).$(VERSION) $(DEST_LIB)/$(OUTLIB)
#install_headers:
	find include -type d -exec install -d '$(ROOTFS)/usr/{}' ';'
	find include -type f -exec install -Dm 0644 '{}' '$(ROOTFS)/usr/{}' ';'
#install_bins:
	install -D $(OUT_DIR)/util/$(OUTBIN) $(DEST_BIN)/$(OUTBIN)
#install_doc:
	cd doc/html && find . -type d -exec install -d '$(DEST_DOC)/{}' ';'
	cd doc/html && find . -type f -exec install -Dm 0644 '{}' '$(DEST_DOC)/{}' ';'

uninstall:
	rm -f $(DEST_LIB)/$(OUTLIB)*
#	find include -type f -exec rm '$(ROOTFS)/usr/{}' ';'
	rm -rf $(ROOTFS)/usr/include/secutils
	rm -f $(DEST_BIN)/$(OUTBIN)
	rm -rf $(DEST_DOC)

clean_uta:
	rm -f $(BUILDDIR)/uta_api$(OBJ) $(BUILDDIR)/files_icv$(OBJ) \
          $(BUILDDIR)/files_dv$(OBJ) \
          $(OUT_DIR)/$(OUTLIB)* $(OUT_DIR)/util/$(OUTBIN) $(OUT_DIR)/util/icvutil.o

clean:
	$(MAKE) -C util clean
	rm -rf $(OUT_DIR)/$(OUTLIB)* $(OUT_DIR)/util/$(OUTBIN) $(BUILDDIR)

clean_all: clean clean_deb
	rm -rf doc refman.pdf *.gcov reports

doc: doc/html refman.pdf

doc/html: Doxyfile $(wildcard include/*/*.h include/*/*/*.h)
	doxygen Doxyfile 1>/dev/null || mkdir -p doc/html # required packages: doxygen graphviz

refman.pdf: doc/html
	mkdir -p doc/latex
	# for producing doc/latex/*, comment out in Doxyfile: GENERATE_LATEX = NO
	# $(MAKE) -C doc/latex && cp -a doc/latex/refman.pdf . # requires latex

coverage: clean
	$(MAKE) COMPILE_TYPE=code_coverage
