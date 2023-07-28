# libsecutils

<img src="libsecutils.svg" width="200">

[![](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](COPYING)

## Purpose

The library provides easier access to some of the functions provided by OpenSSL.
It does not attempt to wrap its data types but adds some functionality for
file access, file protection, configuration handling, HTTP and TLS connections,
certificate verification and status checking with CRLs and/or OCSP, and logging.
The [Unified Trust Anchor (UTA)](https://github.com/siemens/libuta/) library
can be used for enhanced file protection.

## Contents

- [libsecutils](#libsecutils)
  - [Purpose](#purpose)
  - [Contents](#contents)
  - [Getting started](#getting-started)
    - [Getting the library](#getting-the-library)
    - [Prerequisites](#prerequisites)
    - [Configuring and building](#configuring-and-building)
    - [Installing](#installing)
    - [Building Debian packages](#building-the-debian-packages)
    - [Building the documentation](#building-the-documentation)
    - [Using the library](#using-the-library)
  - [Library structure](#library-structure)
  - [Copyright](#copyright)
  - [License](#license)


## Getting started


### Getting the library

Clone the git repository, e.g., with

`git clone git@github.com:siemens/libsecutils.git`


### Prerequisites 

This software should work with any flavor of Linux, including [Cygwin](https://www.cygwin.com/),
also on a virtual machine or the Windows Subsystem for Linux ([WSL](https://docs.microsoft.com/windows/wsl/about)),
and with MacOS.

The following network and development tools are needed or recommended.
* Git (for getting the software, tested with versions 2.7.2, 2.11.0, 2.20, 2.30.2, 2.39.2)
* CMake (for using [`CMakeLists.txt`](CMakeLists.txt), tested with versions 3.18.4, 3.26.3, 3.27.0)
* GNU make (tested with versions 3.81, 4.1, 4.2.1, 4.3)
* GNU C compiler (gcc, tested with versions 5.4.0, 7.3.0, 8.3.0, 10.0.1, 10.2.1)
  or clang (tested with version 14.0.3)

The following OSS components are used.
* OpenSSL development edition, at least version 1.1.1. Tested, among others,
  with 1.0.2u, 1.1.0f, 1.1.0g, 1.1.1d, 1.1.1i, 1.1.1l, and 3.0.0.<br>
  **Warning:** OpenSSL 1.1.1 (on Mint 19) contains a bug where used cipher suite (level 3) is empty (1.1.1d on Buster works correctly)

* optionally: [github.com/siemens/libuta](https://github.com/siemens/libuta)

For instance, on a Debian system the prerequisites may be installed simply as follows:
```
sudo apt install cmake libssl-dev libc-dev linux-libc-dev
```
while `apt install git make gcc` usually is not needed as far as these tools are pre-installed.


### Configuring and building

The library assumes that OpenSSL is already installed,
including the C header files needed for development
(as provided by, e.g., the Debian/Ubuntu package `libssl-dev`).

By default any OpenSSL installation available on the system is used.
Set the optional environment variable `OPENSSL_DIR` to specify the
absolute (or relative to `../`) path of the OpenSSL installation to use, e.g.:
```
export OPENSSL_DIR=/usr/local
```
In case its libraries are in a different location, set also `OPENSSL_LIB`, e.g.:
```
export OPENSSL_LIB=$OPENSSL_DIR/lib
```

Since version 2, it is recommended to use CMake to produce the `Makefile`,
for instance as follows:
```
cmake .
```

For backward compatibility it is also possible to use instead of CMake the
pre-defined [`Makefile_v1`](Makefile_v1); to this end symlink it to `Makefile`:
```
ln -s Makefile_v1 Makefile
```
or use for instance `make -f Makefile_v1`.

Build the software with `make`.

By default, builds are done in Debug mode.
For Release mode use `-DCMAKE_BUILD_TYPE=Release` or `NDEBUG=1`.
For switching to Debug mode, use `-DCMAKE_BUILD_TYPE=Debug` and unset `NDEBUG`.

The result is in, for instance, `./libsecutils.so.2.0`.

Use of the UTA library can be enabled
by setting the environment variable `SECUTILS_USE_UTA`.

When `SECUTILS_USE_ICV` is set, configuration files are expected
to be integrity protected with an Integrity Check Value (ICV),
which may be produced using `icvutil`.

The TLS-related functions may be disabled by setting `SECUTILS_NO_TLS`.

When using CMake, `cmake` must be (re-)run
after setting or unsetting environment variables.


### Installing and uninstalling

The software can be installed with, e.g.,
```
sudo make install
```
and uninstalled with
```
sudo make uninstall
```

The destination is `/usr/`, unless specified otherwise by `DESTDIR` or `ROOTFS`.


### Building Debian packages

This repository can build the following Debian and source packages.

* `libsecutils` -- the shared library
* `libsecutils-dev` -- development headers and documentation
* `libsecutils-bin` -- helper binaries;
   so far, there is only `icvutil`, in case `SECUTILS_USE_UTA` is set
* `libsecutils*Source.tar.gz` -- source tarball

The recommended way is to use CPack with the files produced by CMake as follows:
```
make deb
```

Alternatively, [`Makefile_v1`](Makefile_v1) may be used like this:
```
make -f Makefile_v1 deb
```
In this case, the resulting packages are placed in the parent directory (`../`),
and following dependencies need to be installed:
* `debhelper` (needed for `dh`)
* `devscripts` (needed for `debuild`)
* `libssl-dev`
* `libuta-dev` (from [github.com/siemens/libuta](https://github.com/siemens/libuta))
   if `SECUTILS_USE_UTA` is set

The Debian packages may be installed for instance as follows:
```
sudo dpkg -i libsecutils*deb
```


### Building the documentation

To build the documentation, the following dependencies need to be installed:
* `doxygen`
* `latex`, in case LaTeX output is desired; if so, comment out in [`Doxyfile`](Doxyfile): `GENERATE_LATEX = NO`

The documentation is built by
```
make doc
```
or
```
make -f Makefile_v1 doc
```

### Using the library

Most functions of the library can be used directly without specific context.
A few functions that make use of the UTA library require a `uta_ctx` pointer,
which may be non-`NULL` only if `SECUTILS_USE_UTA` is set.
You may have a look at `util/icvutil.c` for a simple example.


## Library structure

The library functionality is organized by topic:

- certstatus
  - validate certificates, optionally with status checks using CRLs and/or OCSP
- config
  - OpenSSL configuration files
- connections
  - HTTP and/or TLS
- credentials
  - credentials consisting of a symmetric key or private key and the corresponding certificate
- crypto
  - AES-256-GCM en-/decryption
- storage
  - protected files, e.g. to store a private key in a PEM file encrypted with a hardware-bound password
- util
  - Utilities used also within in the library, e.g. for logging


## Copyright

Copyright (c) Siemens Mobility GmbH, 2021-2023


## License

This work is licensed under the terms of the Apache Software License 2.0.
See the [COPYING](COPYING) file in the top-level directory.

SPDX-License-Identifier: Apache-2.0
