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

build: icvutil

# CFLAGS may include -DSECUTILS_USE_UTA, LDFLAGS may include -luta

icvutil: icvutil.o
	$(CC) $(LDFLAGS) icvutil$(OBJ) -o icvutil$(EXE) -L$(OUT_REVERSE_DIR) -lsecutils

icvutil.o: icvutil.c
	$(CC) $(CFLAGS) -I../include -c icvutil.c

run: build
	LD_LIBRARY_PATH=../ ./icvutil$(EXE) || true

clean:
	rm -f icvutil$(OBJ) icvutil$(EXE)
