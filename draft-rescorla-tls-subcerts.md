---
title: Sub-Certificates for TLS
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



--- abstract

The organizational separation between the operator of a TLS server and the
certificate authority that provides it credentials can cause problems, for
example when it comes to reducing the lifetime of certificates or supporting new
cryptographic algorithms.  This document describes a mechanism to allow TLS
server operators to create their own delegation certificates without breaking
compatibility with clients that do not support this specification.

--- middle

#Introduction

Typically, a TLS server uses a certificate provided by some entity other than
the operator of the server (a "Certification Authority" or CA) {{?RFC5246}}
{{?RFC5280}}.  This organizational separation makes the TLS server operator
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
("sub-certificates") within the scope of a certificate issued by an external CA.
Because the above problems do not relate to the CAs inherent function of
validating possession of names, it is safe to make such delegations as long as
they only enable the recipient of the delegation to speak for names that the CA
has authorized.  For clarity, we will refer to the certificate issued by the
CA as a "master certificate" and the one issued by the operator as a "sub-certificate".

[[ Ed. - We use the phrase "credential" for the sub-certificates since it's an
open issue whether they will be certificates or not. ]]

# Solution Overview

A sub-certificate is a digitally signed data structure with the following
semantic fields:

* A validity interval
* A public key (with its associated algorithm)

The signature on the sub-certificate indicates a delegation from the
master certificate which is issued to the TLS server operator. The key pair used
to sign a sub-certificate is presumed to be one whose public key is
contained in an X.509 certificate that associates one or more names to
the sub-certificate signing key.

A TLS handshake that uses sub-certificates differs from a normal handshake in a
few important ways:

* The client provides an extension in its ClientHello that indicates support for
  this mechanism
* The server provides both the certificate chain terminating in its master
  certificate as well as the sub-certificate.
* The client uses information in the server's master certificate to verify the
  signature on the sub-certificate and verify that the server is asserting an
  expected identity.
* The client uses the public key in the sub-certificate as the server's
  working key for the TLS handshake.

[[ Ed. - The specifics of how sub-certificates are structured and provided by the
server are still to be determined; see below. ]]



# Related Work


Many of the use cases for sub-certificates can also be addressed using purely
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


Sub-certificates:

Client            Front-End            Back-End
  |                   |<---Sub-Cert Prov---|
  |----ClientHello--->|                    |
  |<---ServerHello----|                    |
  |<---Certificate----|                    |
  |<---CertVerify-----|                    |
~~~~~~~~~~

These two classes of mechanism can be complementary.  A server could use
sub-certificates for clients that support them, while using LURK to support
legacy clients.

It is possible to address the short-lived certificate concerns above by
automating certificate issuance, e.g., with ACME {{?I-D.ietf-acme-acme}}.
In addition to requiring frequent operationally-critical interactions with an
external party, this makes the server operator dependent on the CA's willingness
to issue certificates with sufficiently short lifetimes.  It also fails to
address the issues with algorithm support.  Nonetheless, existing automated
issuance APIs like ACME may be useful for provisioning sub-certificates, within
an operator network.

# Client Behavior

This document defines the following extension code point.

~~~~~~~~~~
    enum {
      ...
      supports_sub_certificate(TBD),
      (65535)
    } ExtensionType;
~~~~~~~~~~

A client which supports this document SHALL send an empty "supports_sub_certificate"
extension in its ClientHello. A server MUST NOT send this extension. If the extension
is present, the server MAY send a sub-certificate.  If the extension is not
present, the server MUST NOT send a sub-certificate.  A sub-certificate MUST NOT
be provided unless a Certificate message is also sent.

On receiving a sub-certificate and a certificate chain, the client validates the
certificate chain and matches the end-entity certificate to the server's
expected identity following its normal procedures.  It then takes the following
additional steps:

* Verify that the current time is within the validity interval of the
  sub-certificate.
* Use the public key in the server's end-entity certificate to verify the
  signature on the sub-certificate
* Use the public key in the sub-certificate to verify the CertificateVerify
  message provided in the handshake

[[Ed. - Should it be possible to restrict the sub-certificate beyond what's
in the master certificate.]]

# Sub-Certificates

[[ Ed. - This section is currently a sketch, intended to lay out the design
space to facilitate discussion ]]

Sub-certificates obviously need to have some defined structure.  It is possible
to re-use X.509, but it may be better to define something new.

The format question also mostly decides the question of how the
sub-certificate will be signed and delivered to the client.  If the
sub-certificate is an X.509 certificate, then it will be signed in
that format, and probably provided in the TLS Certificate message as
the end-entity certificate.  If some new structure is devised, then it
will need to define a signature method, and it will probably make more
sense to carry it as a new TLS certificate format {{!RFC6091}} or
in a TLS extension.

The delivery mechanism is mostly a trivial question, but given that the server
is switching between a normal certificate chain and one including a
sub-certificate based on a ClientHello extension, there could be some impact on
the ease of implementation.  For example, it may be easier to change the
extensions in the ServerHello than to switch the certificate chain, or
alternately it may be easier to simply let the server operator provide
a whole chain terminating in the sub-certificate, depending on how much
sanity checking the server does.


## Option 1a. Name Constraints

It would be consistent with the requirements above to realize sub-certificates
by having the CA issue a subordinate CA certificate to the TLS server operator,
with a nameConstraints extension encoding the names the server operator is
authorized for.  Then the sub-certificates would simply be normal end-entity
certificates issued under this subordinate.

In order for this solution to be safe the subordinate CA certificate needs to
have a critical nameConstraints extension.  Historically, this solution has been
unworkable due to legacy clients that could not process name constraints.
However, since in this case we require the client to indicate support, it may
be possible to have critical name constraints without compatibility impact.

Pro:

* Re-use existing issuance and validation code
* No change to client certificate validation and CertificateVerify processing

Con:

* Requires server operator to get a name-constrained subordinate CA certificate
* Name constraints are not universally recognized
* X.509 provides much richer semantics than required


## Option 1b. End Entities as Issuers

One could also imagine a scheme in which the server could use an end-entity
certificate as the issuer for a sub-certificate.  Since servers are typically
issued end-entity certificates by CAs, this could align better with CA issuance
practices.

It's important to note that this would not enable existing end-entity
certificates to be used to issue sub-certificates.  That would create risks such
as those noted in [Jager et al.].  So there would be a need to define some marker
that would be inserted into an end-entity certificate to indicate that it could
be used to issue sub-certificates.

Pro:

* No change to client CertificateVerify processing (still uses last cert in the
  chain)

Con:

* Violates the semantics of the CA bit in basicConstraints
* Requires change to X.509 validation logic to allow sub-certificates
* X.509 provides much richer semantics than required


## Option 2. Define a New Structure

While X.509 forbids end-entity certificates from being used as issuers for other
certificates, it is perfectly fine to use them to issue other signed objects.
We could define a new signed object format that would encode only the semantics
that are needed for this application.  For example, the TLS `digitally-signed`
structure could be used:

~~~~~~~~~~
digitally-signed struct {
  uint64 notBefore;
  uint64 notAfter;
  SignatureScheme algorithm;
  opaque publicKey<0..2^24-1>;
} SubCertificate;
~~~~~~~~~~

This would avoid any mis-match in semantics with X.509, and would likely require
more processing code in the client.  The code changes would be localized to the
TLS stack, which has the advantage of changing security-critical and often delicate
PKI code (though of course moves that complexity to the TLS stack).

[[OPEN ISSUE: How would you represent non-signature keys?]]

As in the above case, there would be a need for a special marker in the
master certificate that declares that the key pair can be used to issue
sub-certificates.

Pro:

* No change to client certificate validation
* No risk of conflict with X.509 semantics

Con:

* Requires new logic for generating and verifying sub-certificates
* Requires changes to client CertificateVerify processing
* Requires marker in end-entity certificate (as above)

# Open Issue: Use of Signing Certificate {#open-issue}

The master certificate can be configured so tha it is usable directly
as a TLS end-entity certificate (this is the natural design for Option
2) or alternately can be configured so that it is not acceptable for
TLS connections but only for signing other certificates. In the former
case, the server operator need only have one certificate, but with the
risk that if the TLS server is compromised the attacker could issue
themselves an arbitrary number of subordinate
certificates. Conversely, the master certificate may be configured so
that it is not directly usable, thus requiring the name-holder to get
two certificates, one for signing sub-certificates and one for use in its
TLS server. This adds additional complexity for the operator but
allows the master certificate to be offline.

# IANA Considerations

# Security Considerations





--- back
