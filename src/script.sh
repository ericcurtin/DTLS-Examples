#!/bin/bash

#set -x

pkill udp-tls || true
gcc -O0 -ggdb udp-tls.c -o udp-tls-debug -lssl -lcrypto -lsctp
gcc -O3 udp-tls.c -o udp-tls -lssl -lcrypto -lsctp
clang-format --style=chromium -i udp-tls.c
if [ ! -e "../../200M" ]; then
  base64 /dev/urandom | head -c 209000000 > ../../200M
#  base64 /dev/urandom | head -c 2090000 > ../../200M
fi

printf "Time taken to transfer 200G sctp\n"
./udp-tls s0s0 127.0.0.1 5000 ../../200M & #> /tmp/sctp-server.strace 2>&1 &
sleep 0.1
time ./udp-tls c0s0 127.0.0.1 5000 /dev/null

echo

pkill udp-tls || true

printf "Time taken to transfer 200G tcp\n"
./udp-tls s0t0 127.0.0.1 5000 ../../200M & #> /tmp/tcp-server.strace 2>&1 &
sleep 0.1
time ./udp-tls c0t0 127.0.0.1 5000 /dev/null

echo

pkill udp-tls || true

printf "Time taken to transfer 200G udp (with gso)\n"
./udp-tls s0ug 127.0.0.1 5000 ../../200M & #> /tmp/udp-server.strace 2>&1 &
sleep 0.1
time ./udp-tls c0ug 127.0.0.1 5000 /dev/null

pkill udp-tls || true

printf "Time taken to transfer 200G udp\n"
./udp-tls s0u0 127.0.0.1 5000 ../../200M & #> /tmp/udp-server.strace 2>&1 &
sleep 0.1
time ./udp-tls c0u0 127.0.0.1 5000 /dev/null

pkill udp-tls || true

