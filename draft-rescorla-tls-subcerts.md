---
title: Delegated Credentials for TLS
abbrev: 
docname: draft-rescorla-tls-subcerts-latest
category: std

ipr: trust200902
area: Security
workgroup: 
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
       ins: E. Rescorla
       name: Eric Rescorla
       organization: RTFM, Inc.
       email: ekr@rtfm.com
 -
       ins: R. Barnes
       name: Richard Barnes
       organization: Mozilla
       email: rlb@ipv.sx
 -
       ins: S. Iyengar
       name: Subodh Iyengar
       organization: Facebook
       email: subodh@fb.com
 -
       ins: N. Sullivan
       name: Nick Sullivan
       organization: CloudFlare Inc.
       email: nick@cloudflare.com



--- abstract

The organizational separation between the operator of a TLS server and the
certificate authority that provides it credentials can cause problems, for
example when it comes to reducing the lifetime of certificates or supporting new
cryptographic algorithms.  This document describes a mechanism to allow TLS
server operators to create their own credential delegations without breaking
compatibility with clients that do not support this specification.

--- middle

#Introduction

Typically, a TLS server uses a certificate provided by some entity other than
the operator of the server (a "Certification Authority" or CA) {{!RFC5246}}
{{!RFC5280}}.  This organizational separation makes the TLS server operator
dependent on the CA for some aspects of its operations, for example:

* Whenever the server operator wants to deploy a new certificate, it has to
  interact with the CA.
* The server operator can only use TLS authentication schemes for which the CA
  will issue credentials.

These dependencies cause problems in practice.  Server operators often want to
create short-lived certificates for servers in low-trust zones such as CDNs or
remote data centers.  The risk inherent in cross-organizational transactions
makes it infeasible to rely on an external CA for such short-lived credentials.

To remove these dependencies, this document proposes a limited delegation
mechanism that allows a TLS server operator to issue its own credentials
within the scope of a certificate issued by an external CA. Because the above
problems do not relate to the CAs inherent function of validating possession of
names, it is safe to make such delegations as long as they only enable the recipient
of the delegation to speak for names that the CA has authorized.  For clarity,
we will refer to the certificate issued by the CA as a "certificate" and the one
issued by the operator as a "Delegated credential".

# Solution Overview

A Delegated credential is a digitally signed data structure with the following
semantic fields:

* A validity interval
* A public key (with its associated algorithm)

The signature on the credential indicates a delegation from the certificate which
is issued to the TLS server operator. The key pair used to sign a credential is
presumed to be one whose public key is contained in an X.509 certificate that
associates one or more names to the credential.

A TLS handshake that uses credentials differs from a normal handshake
in a few important ways:

* The client provides an extension in its ClientHello that indicates support for
  this mechanism
* The server provides both the certificate chain terminating in its certificate
  as well as the credential.
* The client uses information in the server's certificate to verify the
  signature on the credential and verify that the server is asserting an
  expected identity.
* The client uses the public key in the credential as the server's
  working key for the TLS handshake.

The credential's signature is subject to the negotiated signature algorithms.
A credential cannot be used if the client advertises support for credentials
however a server does not have a certificate which is compatible with any of
the negotiated signature algorithms.

It was noted by [J\"{a}ger et al.] that certificates in use by servers that
support outdated protocols such as SSLv2 can be used to forge signatures for
certificates that contain the keyEncipherment KeyUsage [[RFC5280 section 4.2.1.3]]
In order to prevent this type of cross-protocol attack, clients MUST NOT accept
connections from certificates with the keyEncipherment KeyUsage.

[[ Nick - This is a much less stringent requirement than a new flag, since it means
that all existing ECDSA certificates can be re-used.]]

Credentials allow the server to terminate TLS connections on behalf of the
certificate owner. If a credential is stolen, there is no mechanism for revoking
it without revoking the certificate itself.  To limit the exposure of a delegation
credential compromise, servers MUST NOT issue credentials with a validity period
longer than 7 days. Clients MUST NOT accept credentials with longer validity
periods. [[ TODO: which alert should the client send? ]]

# Related Work

Many of the use cases for Delegated credentials can also be addressed using purely
server-side mechanisms that do not require changes to client behavior (e.g.,
LURK {{?I-D.mglt-lurk-tls-requirements}}).  These mechanisms, however, incur
per-transaction latency, since the front-end server has to interact with a
back-end server that holds a private key.  The mechanism proposed in this
document allows the delegation to be done off-line, with no per-transaction
latency. The figure below compares the message flows for these two mechanisms
with TLS 1.3 {{?I-D.ietf-tls-tls13}}.

~~~~~~~~~~
LURK:

Client            Front-End            Back-End
  |----ClientHello--->|                    |
  |<---ServerHello----|                    |
  |<---Certificate----|                    |
  |                   |<-------LURK------->|
  |<---CertVerify-----|                    |
  |        ...        |                    |


Delegated credentials:

Client            Front-End            Back-End
  |                   |<---Cred Provision--|
  |----ClientHello--->|                    |
  |<---ServerHello----|                    |
  |<---Certificate----|                    |
  |<---CertVerify-----|                    |
~~~~~~~~~~

These two classes of mechanism can be complementary.  A server could use
credentials for clients that support them, while using LURK to support
legacy clients.

It is possible to address the short-lived certificate concerns above by
automating certificate issuance, e.g., with ACME {{?I-D.ietf-acme-acme}}.
In addition to requiring frequent operationally-critical interactions with an
external party, this makes the server operator dependent on the CA's willingness
to issue certificates with sufficiently short lifetimes.  It also fails to
address the issues with algorithm support.  Nonetheless, existing automated
issuance APIs like ACME may be useful for provisioning credentials,
within an operator network.

# Client and Server behavior

This document defines the following extension code point.

~~~~~~~~~~
    enum {
      ...
      delegated_credential(TBD),
      (65535)
    } ExtensionType;
~~~~~~~~~~

A client which supports this document SHALL send an empty "delegated_credential"
extension in its ClientHello.

If the extension is present, the server MAY send a DelegatedCredential extension
containing the credential in the response. If the extension
is not present, the server MUST NOT send a credential.  A credential
MUST NOT be provided unless a Certificate message is also sent.

On receiving a credential and a certificate chain, the client validates the
certificate chain and matches the end-entity certificate to the server's
expected identity following its normal procedures.  It then takes the following
additional steps:

* Verify that the current time is within the validity interval of the
  credential
* Use the public key in the server's end-entity certificate to verify the
  signature on the credential
* Use the public key in the credential to verify the CertificateVerify
  message provided in the handshake
* Verify that the certificate has the correct extensions that allow the use
  of credentials

# Delegated Credentials

While X.509 forbids end-entity certificates from being used as issuers for other
certificates, it is perfectly fine to use them to issue other signed objects as
long as the certificate contains the digitalSignature key usage (RFC5280 section
4.2.1.3). We define a new signed object format that would encode only the
semantics that are needed for this application.  The TLS `digitally-signed`
structure is used:

~~~~~~~~~~
digitally-signed struct {
  uint64 validTime;
  SignatureSchemeList supported_signature_algorithms;
  opaque publicKey<0..2^24-1>;
} DelegatedCredential;
~~~~~~~~~~

validTime: Relative time from the beginning of the certificate's notBefore value
after which the Delegated Credential is no longer valid.

supported_signature_algorithms: The supported signature algorithms compatible
with the publicKey. A server MUST NOT negotiate Delegated credentials if the
neogtiated signature algorithm is not in the list.

publicKey: The Delegated Credential's public key.

The `digitally-signed` structure differs between TLS 1.3 and previous versions.
For TLS 1.3 the SignatureAndHashAlgorithm is replaced with SignatureScheme.

The signature of the DelegatedCredential is computed as the concatenation of:

* A string that consists of octet 42 (0x2A) repeated 64 times
* Big endian serialized 2 bytes ProtocolVersion of the TLS version defined by TLS
* DER encoded X.509 certificate used to sign the DelegatedCredential.
* The DelegatedCredential structure.

This signature has a few desirable properties:

* It is bound to the certificate that signed it
* It is bound to the protocol version that is negotiated. This is inteded to avoid
  cross-protocol attacks with signing oracles.

The code changes to create and verify Delegated credentials would be localized to the
TLS stack, which has the advantage of avoiding changes to security-critical and
often delicate PKI code (though of course moves that complexity to the TLS
stack).

An alternative mechanism to Delegated Credentials for TLS as defined here could be
to adopt proxy certificates for use in TLS. Delegated credentials present a
better alternative for several reasons:

* There is no change needed to client certificate validation at the PKI layer which is
  complex.
* X.509 semantics are very rich. This can cause unintended consequences if a service owner
  creates a proxy cert where the properties differ from the leaf certificate.
  Delegated credentials have very restricted semantics which should not conflict
  with X.509 semantics.
* Proxy certificates rely on the cert path building process to establish a binding between
  the proxy certificate and the server certificate. Since the cert path building process is
  not cryptographically protected, it is possible that a proxy certificate
  could be bound to another certificate with the same public key, with different X.509
  parameters. Delegated credentials, which rely on a cryptographic binding between
  the entire certificate and the Delegated credential, cannot.
* Delegated credentials allow signed messages to be bound to specific versions of TLS. This
  prevents them from being used for other protocols if a service owner allows multiple
  versions of TLS.

## Certificate Requirements

We define an new X.509 extension, DelegationUsage to be used in the certificate when the
certificate permits the usage of Delegated Credentials. When this extension is not present
the client MUST not accept a Delegated Credential even if it is negotiated by the server.
When it is present, the client SHOULD follow the validation procedure.

  id-ce-delegationUsage OBJECT IDENTIFIER ::=  { TBD }

  DelegationUsage ::= BIT STRING { allowed (0) }

Conforming CAs MUST mark this extension as non-critical. This would allow the certificate
to be used by service owners for clients that do not support certificate delegation as well
and not need to obtain two certificates.

# IANA Considerations

# Security Considerations

--- back
