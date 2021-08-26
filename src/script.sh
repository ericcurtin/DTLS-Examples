#!/bin/bash

set -ex

pkill udp-tls || true
#gcc -O0 -ggdb udp-tls.c -o udp-tls -lssl -lcrypto
gcc -O3 udp-tls.c -o udp-tls -lssl -lcrypto -lsctp
clang-format --style=chromium -i udp-tls.c
./udp-tls s 127.0.0.1 5000 udp-tls.c &
sleep 0.1
#timeout 1 valgrind ./udp-tls c 127.0.0.1 5000

pkill udp-tls || true

