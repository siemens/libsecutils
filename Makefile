# libsecutils
#
# Copyright (c) Siemens Mobility GmbH, 2021
# 
# Authors:
#  David von Oheimb <david.von.oheimb@siemens.com>
#
# This work is licensed under the terms of the Apache Software License 2.0.  See
# the COPYING file in the top-level directory.           
#               
# SPDX-License-Identifier: Apache-2.0

# Optional OPENSSL_DIR defines absolute or relative (to ../) path to OpenSSL installation.
# Optional OUT_DIR defines absolute or relative (to ./) path where library be produced.
# Optional DEBUG_FLAGS may set to prepend to local CFLAGS and LDFLAGS (default see below).
OUT_DIR ?= .

PACKAGENAME=libsecutils
VERSION=0.9
DIRNAME=$(PACKAGENAME)-$(VERSION)

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

ifdef NDEBUG
    DEBUG_FLAGS ?= -O2
    override DEBUG_FLAGS += -DNDEBUG=1
else
    DEBUG_FLAGS ?= -g -O0 -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all # not every compiler(version) supports -Og
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
OUTBIN=$(OUT_DIR)/libsecutils$(DLL)
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
override LDFLAGS += -L$(OPENSSL_LIB) -L$(OPENSSL) -Wl,-rpath=$(OPENSSL_LIB) # needed for genCMPClient
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
.PHONY: all doc util build build_all clean clean_all clean_uta install headers_install deb debdir coverage

# Default target
all: build_all doc

build:
ifeq ($(COV_ENABLED), 1)
	COMPILE_TYPE=code_coverage
endif
	$(MAKE) COMPILE_TYPE=$(COMPILE_TYPE) $(OUTBIN)

util:
ifdef SECUTILS_USE_UTA 
	$(MAKE) CFLAGS="$(CFLAGS) $(LOCAL_CFLAGS)" -C util
endif

build_all: util | build

# Binary output target
$(OUTBIN): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

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
	mkdir $(BUILDDIR) || true

# Order-only dependency for objects on build dir - prevents unnecessary rebuilds
# (directories are flagged as changed on every object build)
$(OBJS): | $(BUILDDIR)

# installation target - append ROOTFS=<path> to install into virtual root
# filesystem
install: $(OUTBIN)
	install -Dm 755 $(OUTBIN) $(ROOTFS)/usr/lib/$(OUTBIN)

headers_install:
	find include -type d -exec install -d '$(ROOTFS)/usr/{}' ';'
	find include -type f -exec install -Dm 0644 '{}' '$(ROOTFS)/usr/{}' ';'

uninstall:
	rm -f $(ROOTFS)/usr/lib/$(OUTBIN)
	find include -type f -exec rm '$(ROOTFS)/usr/{}' ';'
	rm -rf $(ROOTFS)/usr/include/secutils

clean_uta:
	rm -f $(BUILDDIR)/uta_api$(OBJ) $(BUILDDIR)/files_icv$(OBJ) $(BUILDDIR)/files_dv$(OBJ) $(OUTBIN)

clean:
	rm -rf $(OUTBIN) $(BUILDDIR) debian/libsecutils debian/libsecutils-dev debian/libsecutils*

clean_all: clean
	$(MAKE) -C util clean
	rm -rf doc refman.pdf *.gcov reports

doc: doc/html refman.pdf

doc/html: Doxyfile
	doxygen Doxyfile 1>/dev/null # required packages: doxygen graphviz

refman.pdf: doc/html
	mkdir -p doc/latex
	# for producing doc/latex/*, comment out in Doxyfile: GENERATE_LATEX = NO
	# $(MAKE) -C doc/latex && cp -a doc/latex/refman.pdf . # requires latex

coverage: clean
	$(MAKE) COMPILE_TYPE=code_coverage
