#!/bin/bash

set -ex

pkill sctp-server || true
pkill sctp-client || true

gcc -O3 sctptest.c -o sctp-server -lssl -lcrypto -lsctp
ln -sf sctp-server sctp-client
clang-format --style=chromium -i sctptest.c
./sctp-server &
sleep 0.1
./sctp-client

pkill sctp-server || true
pkill sctp-client || true

