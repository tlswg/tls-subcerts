#! /bin/sh
set -euxo pipefail

tcpdump -UAw /out/dc.pcap -i eth0 port 8081 &
sleep 1
SSLKEYLOGFILE=/out/sslkeylogfile /util/serve_dc -cert rsapss.pem -cert-key rsapsskey.pem  -dc dc.cred -dc-key dckey.pem -port 8081
sleep 1
kill -INT %1
