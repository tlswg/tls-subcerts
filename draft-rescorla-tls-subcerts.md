---
title: Limited Certificate Delegation for TLS
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



--- abstract

This document describes a mechanism for allowing TLS servers to safely
create delegation certificates without breaking existing clients.

--- middle

#Introduction

There are a number of scenarios in which it is desirable for entities
which own a given identity ("name-holders") 
to be able to arrange for subordinate certificates that would allow some
TLS server to act on their behalf. For instance:

* An origin site might wish to have a CDN serve pages for them, but
  be able to revoke that delegation easily if they change vendors.
  This is easiest with short-lived certificates.
* A server operator might wish to deploy servers in data centers with
  weak security and be able to revoke that delegation easily if they suspect
  compromise. Short-lived certificates work here as well.
* A server might want to deploy certificates with keys of a type that
  CAs do not widely support (e.g., static ECDHE keys or
  EdDSA {{?I-D.irtf-cfrg-eddsa}}).

In all of these cases, the name-holder is authorized for some set of
identities and just wishes to obtain new certificates for some or all
of those identities.  In some cases, it is possible for the
end-entities to get these certificates from an existing CA, but in
practice, even with automated protocols such as ACME
{{?I-D.ietf-acme-acme}} it is painful to get large numbers of
certificates, especially if they have unusual properties such as very
short-lifetimes or unsupported key formats. It would be far more
convenient for operators to obtain a single certificate and then use
it to issue new subordinate certifificates with the desired
properties.

In theory, this should be straightforward using existing
PKIX {{!RFC5280}} mechanisms: the CA issues the entity with a suitably
constrained CA certificate that can only be used to issue the
appropriate class of end-entity certificates. In practice, however,
this can not be done safely because clients have limited support
for the appropriate PKIX mechanisms (for instance, Firefox only started
supporting NameConstraints in XXX) and thus may refuse to accept
validly constrained certificates or fail to enforce the constraints
(depending on the precise certificate structure).
Instead, operators are forced to fall back on offline delegation
mechanisms such as those being considered in LURK, with the result
being suboptimal performance.

This document addresses this problem by describing a limited
delegation mechanism intended to address this issue.


# Solution Overview

The basic intuition behind the solution in this document is that a partial
solution is good enough. Consider the case of a CDN which fronts for domain
X using LURK, which means that every full TLS handshake requires a round
trip to the origin server. If we merely remove this round trip for a large
fraction of clients (i.e., those which support this specification) then
that represents a significant performance improvement, and the remaining
clients can fall back to LURK.

This suggests a two-part solution:

* A new TLS extension which allows a client to indicate that it
  supports certificate delegation ({{tls-extension}}).

* A way to mark certificates as being usable for signing subordinate
  certificates {{certificate-format}}.

Clients which support this document indicate the extension, which tells
the server that it can send a suitable subordinate certificate. Otherwise,
the server falls back to its ordinary behavior (LURK, certificates with older
keys, etc.)


# TLS Extension

This document defines the following extension code point.

~~~~
    enum {
      ...
      supports_sub_certificate(TBD),
      (65535)
    } ExtensionType;
~~~~

A client which supports this document SHALL send an empty "supports_sub_certificate"
extension in its ClientHello. A server MUST NOT send this extension. If the extension
is present, the server MAY send a certificate chain in its Certificate message which
contains a certificate as specified in the following section.


# Certificate Format

We need some mechanism for indicating that a certificate may be used to authorize
subcertificates. There are two primary options:

* Take advantage of existing PKIX mechanisms
* Define a new mechanism

In either case, because the client indicates that it supports the mechanism,
we do not need to worry about older clients refusing to accept them. However,
it is critical that it older clients not incorrectly accept them for certificates
outside of their proper scope (e.g., for names that were not authorized by
the CA to the name-holder).


## Existing PKIX Mechanisms

The obvious choice is to use existing PKIX mechanisms [TODO: Barnes to describe.].
In this case, the authorizing certificate would technically be a CA for the
subordinate  certificate and the
resulting certificate chain would be valid per {{RFC5280}}, which
is clearly cleanest.

There are two primary difficulties:

* These mechanisms (principally NameConstraints) are somewhat clunky.
* It is unclear to what extent existing implementations properly handle
  these mechanisms.

[TODO: Add more here.]

## New Mechanism

The alternative design is to define a new certificate extension which indicates
that the certificate may be used to sign subordinate extensions. This extension
could be very simple, just consisting of a single bit indicating that the chain
may be extended by one certificate, with the terminal certificate containing
a subset of the names in the immediately authorizing certificate.

The advantage of this design is that it is definitely safe: any reasonable
existing client will not accept the resulting certificates (and one which
does is almost certainly already insecure). The disadvantage is that it produces
invalid certificate chains, which is inelegant and risks confusing validators.


## Open Issue: Use of Signing Certificate {#open-issue}

The certificate which the CA issues to the name-holder can be configured so that
it is usable directly as a TLS end-entity certificate or alternately can
be configured so that it is not acceptable for TLS connections but only
for signing other certificates. In the former case, the name-holder need only
have one certificate, but with the risk that if the TLS server is compromised
the attacker may issue themselves an arbitrary number of subordinate
certificates. Conversely, it may be configures so that it is not directly
usable, thus requiring the name-holder to get two certificates, one for
signing subordinates and one for use in its TLS server.

# IANA Considerations

# Security Considerations

It is imperative that this mechanism not create new risk for existing clients.
In particular, it must protect against the following risks:

* Existing certificates MUST NOT be able to sign subordinate certificates,
  even with new clients, in order to prevent attacks like those described
  by Jager et al. [REF].

* Holders of certificates compliant with this specification MUST NOT be
  able to sign new certificates for identities other than those authorized
  by the CA.

If certificates may be used both for signing subordinate certificates and
as an end-entity certificate themselves (see {{open-issue}}.





--- back
