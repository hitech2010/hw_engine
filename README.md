# hw_engine

This is an OpenSSL cryptographic hardware acceleration using the ENGINE object type.

## Build

Build as follows:

    $ autoreconf -i
    $ ./configure
    $ make

A quick and easy test goes like this:

    $ OPENSSL_ENGINES=.libs openssl engine -t -c hw_engine

    $ echo "whatever" | OPENSSL_ENGINES=.libs openssl dgst -md5 -engine hw_engine

