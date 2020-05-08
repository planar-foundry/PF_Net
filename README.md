PF_Net
======

## Dependencies

### Compiler

PF_Net uses modern C++ features. It is confirmed working under the following compilers:

* Visual Studio 2019
* GCC 9
* Clang 10

### libsodium

* On Windows, download a libsodium release and set Sodium_DIR to point to the release while invoking cmake: `cmake -DSodium_DIR="path"`  
* On Linux, simply install `libsodium-dev`.
