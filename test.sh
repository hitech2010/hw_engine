#!/bin/bash

engine_dir="OPENSSL_ENGINES=.libs"

$engine_dir openssl speed sha1 -engine hw_engine

