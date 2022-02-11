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

To build the library, the following libraries must be present on the system, including their headers:

* OpenSSL development edition, at least version 1.0.2. Tested, among others,
  with 1.0.2u, 1.1.0f, 1.1.0g, 1.1.1d, 1.1.1i, 1.1.1l, and 3.0.0.<br>
  **Warning:** OpenSSL 1.1.1 (on Mint 19) contains a bug where used cipher suite (level 3) is empty (1.1.1d on Buster works correctly)

* optionally: [siemens/libuta](https://github.com/siemens/libuta)


### Configuring and building

Build the library with `make`.

The optional environment variable `OPENSSL_DIR` defines absolute or relative
(to `../`) path to of the OpenSSL installation to use.

Use of the UTA library can be enabled by `make SECUTILS_USE_UTA=1`.
When `SECUTILS_CONFIG_USE_ICV` is defined, configuration files are expected
to be integrity protected with an Integrity Check Value (ICV),
which may be produced using `util/icvutil`.

The TLS-related functions may be disabled by defining `SECUTILS_NO_TLS`.

### Installing

The library will be installed (with `make install`)
to `/usr/local`, unless specified otherwise by `ROOTFS`.

### Building Debian packages

This repository can build the following Debian packages.

* `libsecutils` - the shared library
* `libsecutils-dev` - development headers
* `libsecutils-bins` - helper binaries from `util/` - so far, there is only `icvutil`

To build the Debian packages, the following dependencies need to be installed:
* `debhelper`
* `libssl-dev`
* `libuta-dev` (from [github.com/siemens/libuta](https://github.com/siemens/libuta))
   if `SECUTILS_USE_UTA` is defined

Then the packages can be built by
```
make deb
```
where `SECUTILS_USE_UTA=1` and `SECUTILS_CONFIG_USE_ICV=1` may be added.

On success, they are placed in the parent directory (`../`).

### Building the documentation

To build the documentation, the following dependencies need to be installed:
* `doxygen`
* `latex`, in case LaTeX output is desired; if so, comment out in [`Doxyfile`](Doxyfile): `GENERATE_LATEX = NO`

The documentation is built by
```
make doc
```

### Using the library

Most functions of the library can be used directly without specific context.
A few functions that make use of the UTA library require a `uta_ctx` pointer,
which may be non-`NULL` only if `SECUTILS_USE_UTA` is defined.
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

Copyright (c) Siemens Mobility GmbH, 2021

## License

This work is licensed under the terms of the Apache Software License 2.0.
See the [COPYING](COPYING) file in the top-level directory.

SPDX-License-Identifier: Apache-2.0
