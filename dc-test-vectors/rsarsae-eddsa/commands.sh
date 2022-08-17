#! /bin/sh
set -euxo pipefail
openssl ecparam -out /out/rootkey.pem -name secp256r1 -genkey
openssl req -new -key /out/rootkey.pem -x509 -nodes -days 365 -out /out/root.pem -config ca.cnf
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out /out/rsarsaekey.pem 
openssl req -config leaf.cnf -new -key /out/rsarsaekey.pem -out /tmp/rsarsae.csr
openssl x509 -req -days 365 -in /tmp/rsarsae.csr -CA /out/root.pem -CAkey /out/rootkey.pem -CAcreateserial -out /out/rsarsae.pem -extfile leaf.cnf -extensions v3_req
/util/generate_delegated_credential -cert-path /out/rsarsae.pem -key-path /out/rsarsaekey.pem -signature-scheme Ed25519 -duration 24h -out-path /out/
