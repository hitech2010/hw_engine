#!/bin/bash

engine_dir="OPENSSL_ENGINES=.libs"

$engine_dir openssl speed sha1 -engine hw_engine

time dd if=/dev/zero count=10 bs=1M | OPENSSL_ENGINES=.libs openssl sha1
