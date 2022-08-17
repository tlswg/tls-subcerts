#! /bin/sh
set -euxo pipefail
openssl ecparam -out /out/rootkey.pem -name secp256r1 -genkey
openssl req -new -key /out/rootkey.pem -x509 -nodes -days 365 -out /out/root.pem -config ca.cnf
openssl genpkey -algorithm ed25519 -out /out/ed25519key.pem
openssl req -config leaf.cnf -new -key /out/ed25519key.pem -out /tmp/ed25519.csr
openssl x509 -req -days 365 -in /tmp/ed25519.csr -CA /out/root.pem -CAkey /out/rootkey.pem -CAcreateserial -out /out/ed25519.pem -extfile leaf.cnf -extensions v3_req
rm /out/root.srl
/util/generate_delegated_credential -cert-path /out/ed25519.pem -key-path /out/ed25519key.pem -signature-scheme PSSPSSWithSHA256 -duration 24h -out-path /out/
