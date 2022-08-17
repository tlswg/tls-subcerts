package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	addr     = flag.String("address", "127.0.0.1", "The IP address of the server.")
	port     = flag.Int("port", 8081, "The port of the the server.")
	hostname = flag.String("hostname", "localhost", "The hostname of the server.")
	root     = flag.String("root", "root.pem", "The root certificate of the CA.")
)

func main() {
	flag.Parse()

	inBytes, err := os.ReadFile(*root)
	if err != nil {
		log.Fatalf("failed to read input file: %v", err)
	}

	inPEM, rest := pem.Decode(inBytes)
	if len(rest) != 0 {
		log.Fatalf("input remaining after parsing: %b", rest)
	}

	rCert, err := x509.ParseCertificate(inPEM.Bytes)
	if err != nil {
		log.Fatalf("failed to parse root cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rCert)

	clientConfig := &tls.Config{
		MinVersion:                 tls.VersionTLS13,
		MaxVersion:                 tls.VersionTLS13,
		SupportDelegatedCredential: true,
		RootCAs:                    pool,
		ServerName:                 *hostname,
		PSSSignatureSchemesEnabled: true,
	}

	client, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", *addr, *port), clientConfig)
	if err != nil {
		log.Fatalf("failed to dial server: %v\n", err)
	}
	defer client.Close()

	resp, err := client.Write([]byte(fmt.Sprintf("GET / HTTP/1.1\nHost: %s\n\n", *hostname)))
	if err != nil {
		log.Printf("%d - %v\n", resp, err)
	}
}
