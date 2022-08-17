# Delegated Credential Test Vector Generator

This directory contains all the code necessary to generate test vectors for Delegated Credentials (DCs) in the following six configurations:
| Leaf public key signature algorithm | DC public key signature algorithm |
| --- | --- |
| ECDSA (P-384) | EdDSA (Ed25519) |
| ECDSA (P-384) | RSAPSS (2048 + SHA512) |
| EdDSA (Ed25519) | ECDSA (P-256 + SHA256) |
| EdDSA (Ed25519) | RSAPSS (2048 + SHA256) |
| RSAPSS (2048 + SHA256) | ECDSA (P-256 + SHA256) |
| RSA (2048 + SHA256) | EdDSA (Ed25519)|

## Requirements

To generate the test vectors the following software is needed:
- docker
- docker-compose
- jinja2
- make

## Code structure

There is a folder for each configuration which contains the code necessary for performing a DC connection in the relevant configuration.
Each folder contains a Dockerfile that describes two containers, one that starts a server that will terminate connections with a DC, and a second that makes such connections as a client.

Where two different implementations that support a given configuration exist they both will be used, to provide some level of interoperability testing.

The server will produce a pcap of the connection, and will write it to the `./output/pcaps` folder, along with the `sslkeylogfile` containing the TLS secrets for the connection.

At the top level there is a Makefile.
When `make gen-tests` is run a docker-compose file is generated based on the configurations listed in `data.yml`.
This docker-compose file first runs six containers that produce the necessary keys, certificates, and credentials for each connection and places them in the `./output/keys` folder of their respective configuration.

Once these keys are available the a further twelve containers will be created, and the connections are initiated.

When first run boringssl's `bssl` and a heavily patched version of `go` need to be built, which can take a few minutes. Once these are built however they should be cached by docker, making subsequent runs much faster.


## Issues

### Building fetch_dc and serve_dc

The `cmd` folder contains two `go` programs that need to be compiled with a custom version of go, that is pulled from `https://github.com/jhoyla/go`. 
This version of Go implements RSASSA-PSS-PSS support but has not seen any security analysis, and should not be used outside of this highly controlled use-case.

### Output files owned by root

If your docker setup runs as root by default then the output files will be owned by root / uid 0. This can be solved by `chown`ing the repository:
```
sudo chown $(whoami):$(whoami) -R $PATH_TO_REPO
``` 