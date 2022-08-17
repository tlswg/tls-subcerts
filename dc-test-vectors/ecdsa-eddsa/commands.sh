#! /bin/sh
set -euxo pipefail
openssl ecparam -out /out/rootkey.pem -name secp256r1 -genkey
openssl req -new -key /out/rootkey.pem -x509 -nodes -days 365 -out /out/root.pem -config ca.cnf
openssl genpkey -algorithm EC -out /out/ecdsakey.pem -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve
openssl req -config leaf.cnf -new -key /out/ecdsakey.pem -out /tmp/ecdsa.csr
openssl x509 -req -days 365 -in /tmp/ecdsa.csr -CA /out/root.pem -CAkey /out/rootkey.pem -CAcreateserial -out /out/ecdsa.pem -extfile leaf.cnf -extensions v3_req
rm /out/root.srl
/util/generate_delegated_credential -cert-path /out/ecdsa.pem -key-path /out/ecdsakey.pem -signature-scheme Ed25519 -duration 24h -out-path /out/
