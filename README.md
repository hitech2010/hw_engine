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


Another test method:

    $ ln -s /root/hw_engine/.libs/libhw_engine.so.0.0.0 /usr/lib/i386-linux-gnu/openssl-1.0.0/engines/libhw_engine.so
    ## Since we have create a soft link to libhw_engine.so.0.0.0 in the environment, we don't need to add the 'OPENSSL_ENGINES=.libs' when we test the functions.
    $ openssl speed sha256 -engine hw_engine

AES usage:
    $ openssl enc -aes-128-cbc -iv 1234 -K 1234 -in test.txt -out test.out
    $ openssl enc -d -aes-128-cbc -iv 1234 -K 1234 -in test.out

# USBKey
Now since the cryptop can only use the HASH_PORT, I must switch to HUAHONG USBKey.
