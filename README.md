Crypto-Example
==============

#### kira tully (ephemeral.cx)

A short, proof-of-concept RSA and AES encryption program with OpenSSL.

Accompanying documentation and walk-through is available at [https://ephemeral.cx/2012/06/openssl-rsa-aes-and-c](https://ephemeral.cx/2012/06/openssl-rsa-aes-and-c)

This example builds two binaries:

1. `crypto_example` reads from stdin and encrypts/decrypts strings in RSA & AES.
2. `crypto_file_example` takes a file as an argument, encrypts it with AES, writes it to a file base64 encoded, reads it back, decrypts it, and writes the decrypted file out.

## Usage

### Prerequisites

You must have a recent version of OpenSSL installed before building.

### Compiling & Running

```
$ make
$ make exec      # Runs the `crypto_example` binary
$ make file_exec # Runs the `crypto_file_example` binary on a lorem ipsum text file
```

## Problems?

Despite going long periods of time without being updated, this repo is actively maintained. Being an example that I don't check often, I rely on users for reports if something breaks. Issues and pull requests are greatly appreciated.

## License

The MIT License (MIT)

Copyright (c) 2013 Kira Tully

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
