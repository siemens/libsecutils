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

.PHONY: build icvutil.o run clean

build: icvutil.o
	$(CC) icvutil$(OBJ) -o icvutil$(EXE) -L../ -lsecutils

icvutil.o: icvutil.c
	$(CC) -I../include -DSECUTILS_USE_UTA -c icvutil.c

run: build
	LD_LIBRARY_PATH=../ ./icvutil$(EXE) || true

clean:
	rm -f icvutil$(OBJ) icvutil$(EXE)
