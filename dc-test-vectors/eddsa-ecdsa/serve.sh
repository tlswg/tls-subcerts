#! /bin/sh
set -euxo pipefail

tcpdump -UAw /out/dc.pcap -i eth0 port 8081 &
sleep 1
SSLKEYLOGFILE=/out/sslkeylogfile /util/bssl server -delegated-credential dc.cred -delegated-credential-key dckey.pem -cert ed25519.pem -key ed25519key.pem -accept 8081
sleep 1
kill -INT %1