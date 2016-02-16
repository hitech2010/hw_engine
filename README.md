# hw_engine

This is an OpenSSL cryptographic hardware acceleration using the ENGINE object type.

## Build

Build as follows:

    $ autoreconf -i
    $ ./configure
    $ make

A quick and easy test goes like this:

    $ OPENSSL_ENGINES=.libs openssl engine -t -c emd5

    $ echo "whatever" | OPENSSL_ENGINES=.libs openssl openssl dgst -md5 -engine emd5

