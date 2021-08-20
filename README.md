# libsecutils

<img src="libsecutils.svg" width="200">

[![](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](COPYING)

## Purpose

The library provides easier access to some of the functions provided by OpenSSL.
It does not attempt to wrap its data types but adds some functionality for
file access, file protection, configuration handling, HTTP and TLS connections,
certificate verfication and status checking with CRLs and/or OCSP, and logging.
The Unified Trust Anchor (UTA) library can be used for enhanced file protection.

## Contents

- [libsecutils](#libsecutils)
  - [Purpose](#purpose)
  - [Contents](#contents)
  - [Getting Started](#getting-started)
    - [Getting the library](#getting-the-library)
    - [Prerequisites](#prerequisites)
    - [Configuring and building](#configuring-and-building)
    - [Installing](#installing)
    - [Building the Debian packages](#building-the-debian-packages)
    - [Building the documentation](#building-the-documentation)
    - [Using the library](#using-the-library)
  - [Library Structure](#library-structure)
  - [Copyright](#copyright)
  - [License](#license)

## Getting Started


### Getting the library

Clone the git repository with

`git clone <repository>`


### Prerequisites 

To build the library, the following libraries must be present on the system, including their headers:

* OpenSSL at least version 1.0.2. Tested with 1.0.2u, 1.1.0g, 1.1.1d, and 1.1.1i.
  **Warning:** OpenSSL 1.1.1 (on Mint 19) contains a bug where used cipher suite (level 3) is empty (1.1.1d on Buster works correctly)

* optionally: [siemens/libuta](https://github.com/siemens/libuta)


### Configuring and building

Build the library with `make`.
The optional environment variable `OPENSSL_DIR` defines absolute or relative
(to `../`) path to of the OpenSSL installation to use.
The use ofthe UTA library can be enabled by `make SECUTILS_USE_UTA =1`.
When `SECUTILS_CONFIG_USE_ICV` is defined configuration files are expected
to be integrity protected with an Integrity Check Value (ICV),
which may be produced using `util/icvutil`.
The TLS-related functions may be disabled by defining `SECUTILS_NO_TLS`.

### Installing

The library will be installed (with `make install`)
to `/usr/local` if not specified otherwise.

### Building the Debian packages

This repository build three Debian packages.

1. libsecutils - The shared library
2. libsecutils-dev - Development headers
3. libsecutils-bins - Helper binaries from util/

To build the Debian packages the following dependencies have to be installed:
```
libssl-dev
libuta-dev (from github.com/siemens/libuta)
```

Afterwards the packages can be build 
```
dpkg-buildpackage -uc -us
```

### Building the documentation

To build the documentation the following dependencies have to be installed:
```
doxygen
```

Building the documentation is performed using
```
make doc
```

### Using the library

Most functions of the libarary can be used directly without specific context.
A few functions that make use of the UTA library require a `uta_ctx` pointer.
You may have a look at `util/icvutil.c` for a simple example.

## Library Structure

The library functions are split by use case

- certstatus
  - functions to check the validity/status of a certificate using e.g. CRLs or OCSP
- config
  - OpenSSL configuration wrapper functions
- connections
  - Wrappers for HTTP or TLS
- credentials
  - Wrappers to access credentials consisting of a private key and the corresponding certificate
- crypto
  - AES-256-GCM EN-/Decryption Wrappers
- storage
  - Functionality to store or read protected files, e.g. to store a private key in a PEM file encrypted with a hardware-bound password
- util
  - Utility functions used in the library e.g. for logging

## Copyright

Copyright (c) Siemens Mobility GmbH, 2021

## License

This work is licensed under the terms of the Apache Software License 2.0.  See
the COPYING file in the top-level directory.           

SPDX-License-Identifier: Apache-2.0

