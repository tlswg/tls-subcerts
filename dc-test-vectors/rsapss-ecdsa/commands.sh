#! /bin/sh
set -euxo pipefail
openssl ecparam -out /out/rootkey.pem -name secp256r1 -genkey
openssl req -new -key /out/rootkey.pem -x509 -nodes -days 365 -out /out/root.pem -config ca.cnf
openssl genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out /out/rsapsskey.pem -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32
openssl req -config leaf.cnf -new -key /out/rsapsskey.pem -out /tmp/rsapss.csr
openssl x509 -req -days 365 -in /tmp/rsapss.csr -CA /out/root.pem -CAkey /out/rootkey.pem -CAcreateserial -out /out/rsapss.pem -extfile leaf.cnf -extensions v3_req
rm /out/root.srl
/util/generate_delegated_credential -cert-path /out/rsapss.pem -key-path /out/rsapsskey.pem -duration 24h -signature-scheme ECDSAWithP256AndSHA256 -out-path /out/
