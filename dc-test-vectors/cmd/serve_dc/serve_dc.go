package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

var SigStringMap = map[string]tls.SignatureScheme{
	"PKCS1WithSHA256": 0x0401,
	"PKCS1WithSHA384": 0x0501,
	"PKCS1WithSHA512": 0x0601,

	// RSASSA-PSS algorithms with public key OID rsaEncryption.
	"PSSWithSHA256": 0x0804,
	"PSSWithSHA384": 0x0805,
	"PSSWithSHA512": 0x0806,

	// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
	"ECDSAWithP256AndSHA256": 0x0403,
	"ECDSAWithP384AndSHA384": 0x0503,
	"ECDSAWithP521AndSHA512": 0x0603,

	// EdDSA algorithms.
	"Ed25519": 0x0807,
}

func loadX509WithDC(certPath, certKeyPath, dcPath, dcKeyPath string) (tls.Certificate, error) {
	var cert tls.Certificate

	certBytes, err := os.ReadFile(certPath)
	if err != nil || len(certBytes) == 0 {
		log.Fatalf("Could not read certificate file: %v\n", err)
	}

	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }
	certPEMBlock := certBytes
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return fail(errors.New("tls: failed to find any PEM data in certificate input"))
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}
		return fail(fmt.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	certKeyBytes, err := os.ReadFile(certKeyPath)
	if err != nil || len(certKeyBytes) == 0 {
		return fail(fmt.Errorf("tls: failed to read certificate key"))
	}
	certKeyDerBlock, rest := pem.Decode(certKeyBytes)
	if len(rest) != 0 {
		log.Printf("Some bytes of the certificate key remain")
	}
	certpriv, err := parsePrivateKey(certKeyDerBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate key")
	}
	cert.PrivateKey = certpriv

	dcBytes, err := os.ReadFile(dcPath)
	if err != nil || len(dcBytes) == 0 {
		return fail(fmt.Errorf("tls: failed to read DC"))
	}
	dc, err := tls.UnmarshalDelegatedCredential(dcBytes)
	if err != nil {
		return fail(fmt.Errorf("tls: failed to unmarshal DC: %v", err))
	}

	dcKeyBytes, err := os.ReadFile(dcKeyPath)
	if err != nil || len(dcKeyBytes) == 0 {
		log.Fatalf("Failed to read key file: %v\n", err)
	}

	keyDerBlock, rest := pem.Decode(dcKeyBytes)
	if len(rest) != 0 {
		log.Printf("Some bytes of the key remain: %d\n", len(rest))
	}
	priv, err := parsePrivateKey(keyDerBlock.Bytes)
	if err != nil {
		log.Printf("Failed to parse private key: %s\n", err)
	}
	if dc == nil {
		log.Fatalf("DC is nil")
	}
	if priv == nil {
		log.Fatalf("DC key is nil")
	}
	dc_pair := tls.DelegatedCredentialPair{DC: dc, PrivateKey: priv}
	cert.DelegatedCredentials = append(cert.DelegatedCredentials, dc_pair)

	return cert, nil
}

// Copied from tls.go, because it's private.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

var (
	certPath    = flag.String("cert", "cert.pem", "Path to the server certificate.")
	certKeyPath = flag.String("cert-key", "certkey.pem", "Path to the server certificate key.")
	dcPath      = flag.String("dc", "dc.cred", "Path to the DC.")
	dcKeyPath   = flag.String("dc-key", "dckey.pem", "Path to the DC key.")
	port        = flag.Int("port", 8080, "Port to host server on.")
)

func main() {
	flag.Parse()
	tlsKeyLogFile, exists := os.LookupEnv("SSLKEYLOGFILE")
	var kw *os.File
	var err error
	if exists {
		if tlsKeyLogFile != "" {
			kw, err = os.OpenFile(tlsKeyLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
			if err != nil {
				log.Printf("Cannot open key log file: %s\n", err)
			}
		}
	}

	cert, err := loadX509WithDC(*certPath, *certKeyPath, *dcPath, *dcKeyPath)
	if err != nil {
		log.Fatal("failed to load certificate:", err)
	}

	s := &http.Server{
		Addr: fmt.Sprintf(":%d", *port),
		TLSConfig: &tls.Config{
			Certificates:               []tls.Certificate{cert},
			SupportDelegatedCredential: true,
			KeyLogWriter:               kw,
		},
	}

	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		s.Shutdown(context.TODO())
	})

	log.Print(s.ListenAndServeTLS("", ""))
}
