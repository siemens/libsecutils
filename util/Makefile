#!/usr/bin/make

# Makefile for libsecutils/util
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

# Optional OUT_DIR defines absolute or relative (to ../) path where to place the binary.
# Optional CFLAGS are used, may include -DSECUTILS_USE_UTA
# Optional LDFLAGS are used, may include -luta

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

ifeq ($(shell echo $(OUT_DIR) | grep "^/"),)
# $(OUT_DIR) is relative path, assumed relative to ./
    OUT_REVERSE_DIR=../$(OUT_DIR)
else
# $(OUT_DIR) is absolute path
    OUT_REVERSE_DIR=$(OUT_DIR)
endif

.PHONY: build run clean

build: icvutil$(EXE)

icvutil$(EXE): icvutil.o
	$(CC) $(LDFLAGS) icvutil$(OBJ) -o icvutil$(EXE) -L$(OUT_REVERSE_DIR) -lsecutils -lssl -lcrypto

icvutil.o: icvutil.c
	$(CC) $(CFLAGS) -I../include -c icvutil.c

run: build
	LD_LIBRARY_PATH=../ ./icvutil$(EXE) || true

clean:
	rm -f icvutil$(OBJ) icvutil$(EXE)
