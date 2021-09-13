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

.PHONY: build run clean

build: icvutil

icvutil: icvutil.o
	$(CC) $(CFLAGS) icvutil$(OBJ) -o icvutil$(EXE) -L../ -lsecutils

icvutil.o: icvutil.c
	$(CC) $(CFLAGS) -I../include -DSECUTILS_USE_UTA -c icvutil.c

run: build
	LD_LIBRARY_PATH=../ ./icvutil$(EXE) || true

clean:
	rm -f icvutil$(OBJ) icvutil$(EXE)
