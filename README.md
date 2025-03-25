# libcdoc

A encryption/decryption library for CDoc container format.

## Features

- CDoc1 encryption by certificate (RSA/ECC)
- CDoc1 decryption (PKSC11/NCrypt private key)
- CDoc2 encryption by public key (RSA/ECC)
- CDoc2 decryption by private key (PKSC11/NCrypt)
- CDoc2 key-server support
- CDoc2 symmetric encryption (AES)
- CDoc2 symmetric encryption (password-based)

For more information refer [doc/intro.md](doc/intro.md) document.

## Building
[![Build Status](https://github.com/open-eid/libcdoc/workflows/CI/badge.svg?branch=master)](https://github.com/open-eid/libcdoc/actions)

### Ubuntu, Fedora

1. Install dependencies

        # Ubuntu
        sudo apt install cmake libxml2-dev zlib1g-dev
        # Fedora
        sudo dnf install cmake gcc-c++ libtool-ltdl-devel libxml2-devel minizip-ng-compat-devel openssl-devel zlib-devel

	* flatbuffers - required
    * doxygen - Optional, for API documentation
	* libboost-test-dev - Optional, for unit tests
	* swig - Optional, for C# and Java bindings
	* openjdk-17-jdk-headless - Optional, for Java bindings

2. Fetch the source

        git clone https://github.com/open-eid/libcdoc.git
        cd libcdoc

3. Configure

        cmake -B build -S .

4. Build

        cmake --build build

5. Install

        sudo cmake --build build --target install

### macOS

1. Install dependencies from
	* [XCode](https://developer.apple.com/xcode/) - For macOS/iOS development
	* [CMake](https://cmake.org)
	* [Homebrew](https://brew.sh)

2. Fetch the source

        git clone https://github.com/open-eid/libcdoc.git
        cd libdcdoc

3. Install dependencies

        brew install flatbuffers openssl opensc

    * flatbuffers - Required
    * openssl - Required, version 3.0.0 or later
    * opensc - Required, for smart-card operations
	* doxygen - Optional, for API documentation
	* boost - Optional, for unit tests
	* swig - Optional, for C# and Java bindings
	* openjdk - Optional, for Java bindings

4. Configure

        cmake -B build -S .

5. Build

        cmake --build build

6. Install

        sudo cmake --build build --target install

### Windows

1. Install dependencies and necessary tools from
	* [Visual Studio Community 2019/2022](https://www.visualstudio.com/downloads/)
	* [CMake](http://www.cmake.org)
	* [vcpkg](https://vcpkg.io/)
	* [Swig](http://swig.org/download.html) - Optional, for C#, Python and Java bindings
	* [Doxygen](https://www.doxygen.nl/download.html) - Optional, for generating documentation
	* [Wix toolset](http://wixtoolset.org/releases/) - Optional, for creating Windows installation packages
	* [Python](https://www.python.org/downloads/) - Optional, for Python bindings
	* [Java](https://www.oracle.com/java/technologies/downloads/) - Optional, for Java bindings

2. Open desired Visual Studio tools command prompt:
	* x64 Native Tool Command Prompt
	* x86 Native Tool Command Prompt
	* ARM64 Native Tool Command Prompt
	* Or some cross compile combination with target host type

3. Fetch the source

        git clone https://github.com/open-eid/libcdoc.git
        cd libcdoc

4. Configure

        cmake --toolchain vcpkg/scripts/buildsystems/vcpkg.cmake `
              -DVCPKG_TARGET_TRIPLET=x64-windows `
              -DVCPKG_MANIFEST_FEATURES=tests `
              -B build -S .

    
5. Build

        cmake --build build
