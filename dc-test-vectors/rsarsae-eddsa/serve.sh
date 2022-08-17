#! /bin/sh
set -euxo pipefail

tcpdump -UAw /out/dc.pcap -i eth0 port 8081 &
sleep 1
SSLKEYLOGFILE=/out/sslkeylogfile /util/bssl server -delegated-credential dc.cred -delegated-credential-key dckey.pem -cert rsarsae.pem -key rsarsaekey.pem -accept 8081
sleep 1
kill -INT %1
