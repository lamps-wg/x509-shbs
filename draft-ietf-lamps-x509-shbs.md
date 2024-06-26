---
title: "Internet X.509 Public Key Infrastructure: Algorithm Identifiers for HSS and XMSS"
abbrev: "HSS and XMSS for X.509"
category: std
stand_alone: true # This lets us do fancy auto-generation of references
ipr: trust200902

docname: draft-ietf-lamps-x509-shbs-latest
submissiontype: IETF
v: 3
area: sec
workgroup: LAMPS - Limited Additional Mechanisms for PKIX and SMIME
keyword: Internet-Draft
venue:
  group: LAMPS
  type: Working Group
  mail: spasm@ietf.org
  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "x509-hbs/draft-x509-shbs"

author:
-
    ins: K. Bashiri
    name: Kaveh Bashiri
    org: BSI
    email: kaveh.bashiri.ietf@gmail.com
-
    ins: S. Fluhrer
    name: Scott Fluhrer
    org: Cisco Systems
    email: sfluhrer@cisco.com
-
    ins: S. Gazdag
    name: Stefan Gazdag
    org: genua GmbH
    email: ietf@gazdag.de
-
    ins: D. Van Geest
    name: Daniel Van Geest
    org: CryptoNext Security
    email: daniel.vangeest@cryptonext-security.com
-
    ins: S. Kousidis
    name: Stavros Kousidis
    org: BSI
    email: kousidis.ietf@gmail.com

normative:
  I-D.draft-ietf-lamps-rfc8708bis: rfc8708bis
  RFC5911:
  RFC5280: #v3 cer, v2 crl
  RFC8391: #xmss
  RFC8554: #hsslms
  SP800208:
    target: https://doi.org/10.6028/NIST.SP.800-208
    title: Recommendation for Stateful Hash-Based Signature Schemes
    author:
      -
        ins: National Institute of Standards and Technology (NIST)
    date: 2020-10-29

informative:
  RFC3279:
  RFC8410:
  RFC8411:
  MCGREW:
    target: https://tubiblio.ulb.tu-darmstadt.de/id/eprint/101633
    title: State Management for Hash-Based Signatures
    author:
      -
        ins: D. McGrew
      -
        ins: P. Kampanakis
      -
        ins: S. Fluhrer
      -
        ins: S. Gazdag
      -
        ins: D. Butin
      -
        ins: J. Buchmann
    date: 2016-11-02
  BH16:
    target: https://eprint.iacr.org/2016/1042.pdf
    title: Oops, I did it again – Security of One-Time Signatures under Two-Message Attacks.
    author:
      -
        ins: L. Bruinderink
      -
        ins: S. Hülsing
    date: 2016
  CNSA2.0:
    target: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
    title: Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) Cybersecurity Advisory (CSA)
    author:
      -
        ins: National Security Agency (NSA)
    date: 2022-09-07
  ETSI-TR-103-692:
    target: https://www.etsi.org/deliver/etsi_tr/103600_103699/103692/01.01.01_60/tr_103692v010101p.pdf
    title: State management for stateful authentication mechanisms
    author:
      -
        ins: European Telecommunications Standards Institute (ETSI)
    date: 2021-11
  IANA-LMS:
    target: https://www.iana.org/assignments/leighton-micali-signatures/
    title: Leighton-Micali Signatures (LMS)
    author:
      -
        ins: IANA
  IANA-XMSS:
    target: https://iana.org/assignments/xmss-extended-hash-based-signatures/
    title: "XMSS: Extended Hash-Based Signatures"
    author:
      -
        ins: IANA

--- abstract

This document specifies algorithm identifiers and ASN.1 encoding formats for
the Stateful Hash-Based Signature Schemes (S-HBS) Hierarchical Signature System
(HSS), eXtended Merkle Signature Scheme (XMSS), and XMSS^MT, a multi-tree
variant of XMSS. This specification applies to the Internet X.509 Public Key
infrastructure (PKI) when those digital signatures are used in Internet X.509
certificates and certificate revocation lists.

--- middle

# Introduction

Stateful Hash-Based Signature Schemes (S-HBS) such as HSS, XMSS and XMSS^MT
combine Merkle trees with One Time Signatures (OTS) in order to provide digital
signature schemes that remain secure even when quantum computers become
available. Their theoretic security is well understood and depends only on the
security of the underlying hash function. As such they can serve as an
important building block for quantum computer resistant information and
communication technology.

The private key of S-HBS is a finite collection of OTS keys, hence only a
limited number of messages can be signed and the private key's state must be
updated and persisted after signing to prevent reuse of OTS keys.  While the
right selection of algorithm parameters would allow a private key to sign a
virtually unbounded number of messages (e.g. 2^60), this is at the cost of a
larger signature size and longer signing time. Due to the statefulness of the
private key and the limited number of signatures that can be created, S-HBS
might not be appropriate for use in interactive protocols. However, in some use
cases the deployment of S-HBS may be appropriate. Such use cases are described
and discussed later in {{use-cases-shbs-x509}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Use Cases of S-HBS in X.509 {#use-cases-shbs-x509}

As many cryptographic algorithms that are considered to be quantum-resistant,
S-HBS have several pros and cons regarding their practical usage. On the
positive side they are considered to be secure against a classical as well as a
quantum adversary, and a secure instantiation of S-HBS may always be built as
long as a cryptographically secure hash function exists. Moreover, S-HBS offer
small public key sizes, and, in comparison to other post-quantum signature
schemes, the S-HBS can offer relatively small signature sizes (for certain
parameter sets). While key generation and signature generation may take longer
than classical alternatives, fast and minimal verification routines can be
built.  The major negative aspect is the statefulness.  Private keys always
have to be handled in a secure manner, S-HBS necessitate a special treatment of
the private key in order to avoid security incidents like signature forgery
[MCGREW], [SP800208]. Therefore, for S-HBS, a secure environment MUST be used
for key generation and key management.

Note that, in general, root CAs offer such a secure environment and the number
of issued signatures (including signed certificates and CRLs) is often moderate
due to the fact that many root CAs delegate OCSP services or the signing of
end-entity certificates to other entities (such as subordinate CAs) that use
stateless signature schemes. Therefore, many root CAs should be able to handle
the required state management, and S-HBS offer a viable solution.

As the above reasoning for root CAs usually does not apply for subordinate CAs,
it is NOT RECOMMENDED for subordinate CAs to use S-HBS for issuing end-entity
certificates. Moreover, S-HBS MUST NOT be used for end-entity certificates.

However, S-HBS MAY be used for code signing certificates, since they are
suitable and recommended in such non-interactive contexts. For example, see the
recommendations for software and firmware signing in [CNSA2.0]. Some
manufactures use common and well-established key formats like X.509 for their
code signing and update mechanisms. Also there are multi-party IoT ecosystems
where publicly trusted code signing certificates are useful.

# Algorithm Identifiers and Parameters

In this document, we define new OIDs for identifying the different stateful
hash-based signature algorithms. An additional OID is defined in {{-rfc8708bis}} and
repeated here for convenience. For all of the OIDs, the parameters MUST be
absent.

## HSS Algorithm Identifier

The object identifier and public key algorithm identifier for HSS is defined in
{{-rfc8708bis}}. The definitions are repeated here for reference.

The object identifier for an HSS public key is `id-alg-hss-lms-hashsig`:

    id-alg-hss-lms-hashsig  OBJECT IDENTIFIER ::= {
       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
       smime(16) alg(3) 17 }

Note that the `id-alg-hss-lms-hashsig` algorithm identifier is also referred to
as `id-alg-mts-hashsig`. This synonym is based on the terminology used in an
early draft of the document that became [RFC8554].

The public key and signature values identify the hash function and the height used in the
HSS/LMS tree. [RFC8554] and [SP800208] define these values, but an IANA registry
[IANA-LMS] permits the registration of additional identifiers in the future.

## XMSS Algorithm Identifier

The object identifier for an XMSS public key is `id-alg-xmss-hashsig`:

    id-alg-xmss-hashsig  OBJECT IDENTIFIER ::= {
       TBD }

The public key and signature values identify the hash function and the height used in the
XMSS tree. [RFC8391] and [SP800208] define these values, but an IANA registry
[IANA-XMSS] permits the registration of additional identifiers in the future.

## XMSS^MT Algorithm Identifier

The object identifier for an XMSS^MT public key is `id-alg-xmssmt-hashsig`:

    id-alg-xmssmt-hashsig  OBJECT IDENTIFIER ::= {
       TBD }

The public key and signature values identify the hash function and the height used in the
XMSS^MT tree. [RFC8391] and [SP800208] define these values, but an IANA registry
[IANA-XMSS] permits the registration of additional identifiers in the future.

# Public Key Identifiers

Certificates conforming to [RFC5280] can convey a public key for any public key
algorithm. The certificate indicates the algorithm through an algorithm
identifier. An algorithm identifier consists of an OID and optional parameters.

[RFC8554] and [RFC8391] define the raw octet string encodings of the public
keys used in this document. When used in a SubjectPublicKeyInfo type, the
subjectPublicKey BIT STRING contains the raw octet string encodings of the
public keys.

This document defines ASN.1 OCTET STRING types for encoding the public keys
when not used in a SubjectPublicKeyInfo. The OCTET STRING is mapped to a
subjectPublicKey (a value of type BIT STRING) as follows: the most significant
bit of the OCTET STRING value becomes the most significant bit of the BIT
STRING value, and so on; the least significant bit of the OCTET STRING
becomes the least significant bit of the BIT STRING.

## HSS Public Keys

The HSS public key identifier is as follows:

    pk-HSS-LMS-HashSig PUBLIC-KEY ::= {
       IDENTIFIER id-alg-hss-lms-hashsig
       -- KEY no ASN.1 wrapping --
       PARAMS ARE absent
       CERT-KEY-USAGE
          { digitalSignature, nonRepudiation, keyCertSign, cRLSign } }

The HSS public key is defined as follows:

    HSS-LMS-HashSig-PublicKey ::= OCTET STRING

[RFC8554] defines the raw octet string encoding of an HSS public key using the
`hss_public_key` structure. See [SP800208] and [RFC8554] for more information on
the contents and format of an HSS public key. Note that the single-tree signature
scheme LMS is instantiated as HSS with number of levels being equal to 1.

##  XMSS Public Keys

The XMSS public key identifier is as follows:

    pk-XMSS-HashSig PUBLIC-KEY ::= {
       IDENTIFIER id-alg-xmss-hashsig
       -- KEY no ASN.1 wrapping --
       PARAMS ARE absent
       CERT-KEY-USAGE
          { digitalSignature, nonRepudiation, keyCertSign, cRLSign } }

The XMSS public key is defined as follows:

    XMSS-HashSig-PublicKey ::= OCTET STRING

[RFC8391] defines the raw octet string encoding of an HSS public key using the
`xmss_public_key` structure. See [SP800208] and [RFC8391] for more information
on the contents and format of an XMSS public key.

## XMSS^MT Public Keys

The XMSS^MT public key identifier is as follows:

    pk-XMSSMT-HashSig PUBLIC-KEY ::= {
       IDENTIFIER id-alg-xmssmt-hashsig
       -- KEY no ASN.1 wrapping --
       PARAMS ARE absent
       CERT-KEY-USAGE
          { digitalSignature, nonRepudiation, keyCertSign, cRLSign } }

The XMSS^MT public key is defined as follows:

    XMSSMT-HashSig-PublicKey ::= OCTET STRING

[RFC8391] defines the raw octet string encoding of an HSS public key using the
`xmssmt_public_key` structure. See [SP800208] and [RFC8391] for more information
on the contents and format of an XMSS^MT public key.

# Key Usage Bits

The intended application for the key is indicated in the keyUsage certificate
extension [RFC5280].
When one of the AlgorithmIdentifiers specified in this document appears in the SubjectPublicKeyInfo
field of a certification authority (CA) X.509 certificate [RFC5280], the
certificate key usage extension MUST contain at least one of the
following values: digitalSignature, nonRepudiation, keyCertSign, or
cRLSign. However, it MUST NOT contain other values.

When one of these AlgorithmIdentifiers appears in the SubjectPublicKeyInfo
field of an end entity X.509 certificate [RFC5280], the certificate key usage
extension MUST contain at least one of the following values: digitalSignature
or nonRepudiation. However, it MUST NOT contain other values.

Note that for certificates that indicate `id-alg-hss-lms-hashsig` the above
definitions are more restrictive than the requirement defined in {{Section 4 of
-rfc8708bis}}.

# Signature Algorithms

This section identifies OIDs for signing using HSS, XMSS, and XMSS^MT. When
these algorithm identifiers appear in the algorithm field as an
AlgorithmIdentifier, the encoding MUST omit the parameters field. That is, the
AlgorithmIdentifier SHALL be a SEQUENCE of one component, one of the OIDs
defined in the following subsections.

When the signature algorithm identifiers described in this document are used to
create a signature on a message, no digest algorithm is applied to the message
before signing.  That is, the full data to be signed is signed rather than
a digest of the data.

For HSS, the signature value is described in section 6.4 of [RFC8554]. For XMSS
and XMSS^MT the signature values are described in sections B.2 and C.2 of
[RFC8391], respectively. The octet string representing the signature is encoded
directly in the OCTET STRING without adding any additional ASN.1 wrapping. For
the Certificate and CertificateList structures, the signature value is wrapped
in the "signatureValue" OCTET STRING field.

## HSS Signature Algorithm

The HSS public key OID is also used to specify that an HSS signature was
generated on the full message, i.e. the message was not hashed before being
processed by the HSS signature algorithm.

    id-alg-hss-lms-hashsig OBJECT IDENTIFIER ::= {
       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
       smime(16) alg(3) 17 }

The HSS signature is defined as follows:

    HSS-LMS-HashSig-Signature ::= OCTET STRING

See [SP800208] and [RFC8554] for more information on the contents and
format of an HSS signature.

## XMSS Signature Algorithm

The XMSS public key OID is also used to specify that an XMSS signature was
generated on the full message, i.e. the message was not hashed before being
processed by the XMSS signature algorithm.

    id-alg-xmss-hashsig  OBJECT IDENTIFIER ::= {
       TBD }

The XMSS signature is defined as follows:

    XMSS-HashSig-Signature ::= OCTET STRING

See [SP800208] and [RFC8391] for more information on the contents and
format of an XMSS signature.

The signature generation MUST be performed according to 7.2 of
[SP800208].

## XMSS^MT Signature Algorithm

The XMSS^MT public key OID is also used to specify that an XMSS^MT signature
was generated on the full message, i.e. the message was not hashed before being
processed by the XMSS^MT signature algorithm.

    id-alg-xmssmt-hashsig  OBJECT IDENTIFIER ::= {
       TBD }

The XMSS^MT signature is defined as follows:

    XMSSMT-HashSig-Signature ::= OCTET STRING

See [SP800208] and [RFC8391] for more information on the contents and
format of an XMSS^MT signature.

The signature generation MUST be performed according to 7.2 of
[SP800208].

# Key Generation

The key generation for XMSS and XMSS^MT MUST be performed according to 7.2 of
[SP800208]

# ASN.1 Module {#sec-asn1}

For reference purposes, the ASN.1 syntax is presented as an ASN.1 module here.
This ASN.1 Module builds upon the conventions established in [RFC5911].

~~~
{::include X509-SHBS-2024.asn}
~~~

# Security Considerations

The security requirements of [SP800208] MUST be taken into account.

For S-HBS it is crucial to stress the importance of a correct state management.
If an attacker were able to obtain signatures for two different messages
created using the same OTS key, then it would become computationally feasible
for that attacker to create forgeries [BH16]. As noted in [MCGREW] and
[ETSI-TR-103-692], extreme care needs to be taken in order to avoid the risk
that an OTS key will be reused accidentally.  This is a new requirement that
most developers will not be familiar with and requires careful handling.

Various strategies for a correct state management can be applied:

- Implement a track record of all signatures generated by a key pair associated
  to a S-HBS instance. This track record may be stored outside the
  device which is used to generate the signature. Check the track record to
  prevent OTS key reuse before a new signature is released. Drop the new
  signature and hit your PANIC button if you spot OTS key reuse.

- Use a S-HBS instance only for a moderate number of signatures such
  that it is always practical to keep a consistent track record and be able to
  unambiguously trace back all generated signatures.

- Apply the state reservation strategy described in Section 5 of [MCGREW], where
  upcoming states are reserved in advance by the signer. In this way the number of
  state synchronisations between nonvolatile and volatile memory is reduced.


# Backup and Restore Management

Certificate Authorities have high demands in order to ensure the availability
of signature generation throughout the validity period of signing key pairs.

Usual backup and restore strategies when using a stateless signature scheme
(e.g. SLH-DSA) are to duplicate private keying material and to operate
redundant signing devices or to store and safeguard a copy of the private
keying material such that it can be used to set up a new signing device in case
of technical difficulties.

For S-HBS such straightforward backup and restore strategies will lead to OTS
reuse with high probability as a correct state management is not guaranteed.
Strategies for maintaining availability and keeping a correct state are
described in Section 7 of [SP800208].

# IANA Considerations

IANA is requested to assign a module OID from the "SMI for PKIX Module
Identifier" registry for the ASN.1 module in {{sec-asn1}}.

--- back

# HSS X.509 v3 Certificate Example

This section shows a self-signed X.509 v3 certificate using HSS.

~~~
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            e8:91:d6:06:91:4f:ce:f3
        Signature Algorithm: HSS
        Issuer: C=US, ST=VA, L=Herndon, O=Bogus CA
        Validity
            Not Before: May 14 08:58:11 2024 GMT
            Not After : May 14 08:58:11 2034 GMT
        Subject: C=US, ST=VA, L=Herndon, O=Bogus CA
        Subject Public Key Info:
            Public Key Algorithm: HSS
                HSS public key:
                PQ key material:
                    00:00:00:01:00:00:00:05:00:00:00:04:74:e4:73:
                    a8:23:a6:6a:7e:9f:a5:45:a8:fa:63:c6:fb:17:8f:
                    af:fe:28:d1:82:d3:95:92:3e:f9:e2:5f:92:20:56:
                    00:09:e4:36:f9:39:a8:ea:8d:e7:79:02:61:a8:42
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                D6:FD:27:12:44:AD:D2:76:19:C0:FC:6D:52:95:6B:19:
                1B:F8:4C:9D:37:9E:6E:F0:7A:98:F0:6C:6E:C5:A2:14
            X509v3 Authority Key Identifier:
                D6:FD:27:12:44:AD:D2:76:19:C0:FC:6D:52:95:6B:19:
                1B:F8:4C:9D:37:9E:6E:F0:7A:98:F0:6C:6E:C5:A2:14
            X509v3 Basic Constraints:
                CA:TRUE
            X509v3 Key Usage:
                Certificate Sign, CRL Sign
    Signature Algorithm: HSS
    Signature Value:
        00:00:00:00:00:00:00:00:00:00:00:04:b8:20:60:54:98:f9:
        ca:6b:fb:d4:91:a0:24:0c:19:f6:e2:4c:94:5d:b1:52:41:93:
        85:8f:dd:97:2a:e4:76:8a:cd:36:7f:05:d6:35:ed:c4:8e:ff:
        72:fe:16:41:54:e4:0b:2a:aa:e6:52:8c:03:25:5e:bd:79:b0:
        48:c8:71:65:8c:31:bf:d0:8e:1a:59:88:37:c6:74:8d:62:4d:
        7d:f2:e0:29:6e:46:58:43:a5:cd:6c:6e:65:19:66:50:59:f4:
        94:51:ca:e0:f9:91:ac:92:c4:c0:04:78:cf:5b:9e:36:35:14:
        0e:8b:84:3d:77:af:ef:58:2b:34:2e:c5:01:c5:45:09:ac:28:
        8c:e1:db:c5:bf:19:d1:a8:0e:02:72:21:82:e5:f2:fc:9f:bd:
        1f:72:31:23:62:f7:2b:60:80:49:21:7e:46:b5:cb:80:b2:4d:
        6c:9a:68:8a:2e:84:ec:06:47:80:1b:da:c4:40:07:2f:c2:57:
        02:39:cb:8c:06:9f:38:55:2f:18:80:2a:7d:08:e4:10:d0:f7:
        41:7f:26:0e:4c:6a:73:78:a4:f7:1b:db:2d:b1:6c:16:b8:64:
        f1:9c:69:2e:d7:b4:a8:d9:49:c0:c8:df:33:de:ac:ad:89:1a:
        f1:14:42:b4:39:3c:cb:2d:1a:93:96:61:d8:ba:70:0c:b4:64:
        23:80:ac:17:34:f5:e4:67:36:d1:2c:dc:b1:7c:ec:1a:41:3f:
        be:28:f8:7a:c4:b9:f2:a0:8c:cf:8b:68:c3:98:02:09:5c:72:
        4f:f5:4e:c7:22:37:8f:2d:67:f0:86:75:fc:ab:34:07:a7:bc:
        9c:0c:b8:d6:90:93:a2:92:4c:a0:eb:7b:83:10:ed:ea:73:a2:
        93:ac:8e:d3:e5:6a:93:ac:5f:17:5a:6a:67:84:9e:84:4b:64:
        35:8b:2d:d0:47:8c:9d:9d:8c:d3:d5:99:a2:ed:e4:84:5e:bc:
        5e:9a:f4:07:51:9d:08:94:19:95:46:c5:94:b1:e3:8a:9a:e3:
        0f:80:9e:b7:9a:eb:a2:33:83:40:9f:47:e7:a4:9e:26:01:cf:
        57:60:cf:ae:78:a2:0d:1b:a2:4d:41:aa:45:08:15:4c:ee:ad:
        87:3b:74:58:f1:60:19:67:62:45:2b:da:c8:74:dc:a3:02:d3:
        29:26:2c:b0:55:67:0b:a5:b8:a2:c2:1b:16:6a:9e:5f:23:02:
        9d:b8:4a:61:8a:ab:3e:91:ef:0b:ab:be:ff:46:9d:c3:1f:2a:
        b0:93:1d:86:64:42:d4:d9:31:ec:b1:5b:2c:8e:78:e6:41:4c:
        5d:0a:f7:ec:d7:51:c8:5d:7f:de:df:ef:87:2a:2e:d6:3d:e7:
        23:3b:1e:e1:86:ca:96:95:50:45:60:10:3d:95:f1:47:cf:d2:
        d7:de:5e:db:65:a7:15:9e:bd:dc:f6:96:0e:f8:90:26:1a:8b:
        cb:6a:7b:d2:32:fc:e5:99:4b:82:82:48:ee:56:f4:dc:a9:7c:
        61:7f:60:94:c7:53:53:31:71:fe:5e:31:42:07:4d:9b:d3:4e:
        48:39:75:56:33:67:6a:d6:b5:2c:36:9a:41:fd:a7:c7:fa:10:
        2d:3d:50:a6:d5:c3:f6:2a:ab:ba:31:40:c7:2d:ec:d4:74:43:
        c2:6e:2e:9b:a9:0d:36:9d:b7:c5:55:8e:08:09:8e:54:a2:a1:
        9c:af:61:8d:b3:a3:4a:51:67:2d:60:7a:1c:f0:72:9b:90:5e:
        42:a5:1a:af:74:e8:82:64:e4:78:d9:e9:4d:74:04:35:e3:71:
        fd:0a:c8:f8:3a:fa:e4:a2:fe:08:eb:e1:69:84:ee:d0:ba:60:
        f4:7d:80:8a:06:e6:df:32:68:da:07:4f:15:2e:82:75:92:6c:
        e2:bf:ac:e7:ab:a4:e0:a3:ab:2c:71:1b:81:e5:8d:1d:d8:44:
        c7:fd:a1:46:51:84:7b:e3:8a:b8:9b:04:28:63:26:0d:44:16:
        1d:7f:b0:e2:76:c5:0e:c3:0a:d3:5a:da:ed:b7:28:f7:e9:55:
        e6:d1:1f:0d:46:b9:1d:4a:79:7e:bd:4b:60:d3:bc:54:ef:95:
        e3:e9:1c:57:1e:3a:48:b5:98:89:e4:92:cb:48:aa:db:ab:08:
        31:7f:08:3f:d9:a8:3b:2d:81:40:cf:60:90:08:ba:a2:ca:0a:
        0b:a7:76:2a:98:40:3c:03:e6:a2:a1:ce:8a:a4:bd:ab:04:87:
        35:cc:b5:ef:da:92:d2:be:98:08:74:89:b2:e4:cd:78:75:7f:
        8f:b8:fe:9c:02:07:a2:07:cb:34:e1:0d:e1:9b:4a:74:69:97:
        f1:1c:5e:5f:28:2c:82:97:b8:08:c7:4f:97:33:90:83:df:d1:
        c7:db:7a:28:1d:98:4e:ef:d5:c2:30:4f:a1:b8:ed:c6:c5:15:
        11:d6:ee:f3:97:f4:22:95:48:12:f8:5f:ba:15:71:e5:5f:19:
        44:50:c1:e1:70:bd:3e:48:a8:f3:2c:62:ad:8f:8a:9f:64:c7:
        92:a7:ec:77:8c:5a:78:99:73:7e:77:12:61:28:90:92:a7:e0:
        46:9a:39:29:1d:06:a1:5e:5c:f2:d6:bb:49:73:e2:88:da:ef:
        3f:93:2e:98:b6:7d:01:b5:56:bc:30:08:2a:0a:22:4b:45:92:
        b3:72:94:ff:07:e1:fe:f3:4e:58:38:cf:0e:e1:45:15:e1:93:
        5a:21:52:77:5e:e6:98:17:16:71:b9:e7:8a:a2:2c:5a:d9:d7:
        0b:15:86:70:69:6f:47:80:7e:87:c7:d0:3d:4b:f6:8f:ca:7d:
        8b:6a:45:27:ee:10:72:b7:df:6c:43:1d:75:e3:ae:64:1d:b3:
        30:85:32:32:2a:c2:8f:21:67:58:25:dc:51:6d:a3:6a:06:d1:
        5d:77:b1:dc:33:6c:ba:0c:be:fa:c2:61:8f:30:18:c3:c1:c7:
        6e:6b:d8:17:1d:bf:67:be:ca:af:94:cc:5b:f2:49:a7:00:00:
        00:05:16:46:55:cf:04:6f:4f:43:be:87:22:e6:11:92:45:5d:
        17:31:92:6f:17:15:2c:b5:f6:37:d1:fb:a5:8f:83:1c:ac:7c:
        54:ce:2d:95:ef:b0:d4:44:c8:d5:d8:a3:e5:0a:b4:ba:f0:d0:
        c5:ab:6a:34:88:72:d7:32:22:27:54:13:1b:60:0f:cd:32:e7:
        cc:33:06:47:68:46:80:06:72:11:f7:74:ab:eb:38:23:30:68:
        ad:48:01:e4:77:5e:34:e4:b1:c3:e9:46:a4:96:da:71:12:19:
        b1:c2:7f:53:0f:f6:cd:4a:cf:12:e8:ea:25:1b:89:f6:35:54:
        e9:9b:e1:02:d5:f8:d4:8b:92:56:43:fd:05:3b:4b:0b:dd:8a:
        20:05:2e:18:7e:a1:a8:e8:55:18:3d:40:ff:5e:35:a3:c3:fb
~~~

~~~
-----BEGIN CERTIFICATE-----
MIIGsDCCAYigAwIBAgIJAOiR1gaRT87zMA0GCyqGSIb3DQEJEAMRMD8xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwI
Qm9ndXMgQ0EwHhcNMjQwNTE0MDg1ODExWhcNMzQwNTE0MDg1ODExWjA/MQswCQYD
VQQGEwJVUzELMAkGA1UECAwCVkExEDAOBgNVBAcMB0hlcm5kb24xETAPBgNVBAoM
CEJvZ3VzIENBME4wDQYLKoZIhvcNAQkQAxEDPQAAAAABAAAABQAAAAR05HOoI6Zq
fp+lRaj6Y8b7F4+v/ijRgtOVkj754l+SIFYACeQ2+Tmo6o3neQJhqEKjdTBzMCkG
A1UdDgQiBCDW/ScSRK3SdhnA/G1SlWsZG/hMnTeebvB6mPBsbsWiFDArBgNVHSME
JDAigCDW/ScSRK3SdhnA/G1SlWsZG/hMnTeebvB6mPBsbsWiFDAMBgNVHRMEBTAD
AQH/MAsGA1UdDwQEAwIBBjANBgsqhkiG9w0BCRADEQOCBREAAAAAAAAAAAAAAAAE
uCBgVJj5ymv71JGgJAwZ9uJMlF2xUkGThY/dlyrkdorNNn8F1jXtxI7/cv4WQVTk
Cyqq5lKMAyVevXmwSMhxZYwxv9COGlmIN8Z0jWJNffLgKW5GWEOlzWxuZRlmUFn0
lFHK4PmRrJLEwAR4z1ueNjUUDouEPXev71grNC7FAcVFCawojOHbxb8Z0agOAnIh
guXy/J+9H3IxI2L3K2CASSF+RrXLgLJNbJpoii6E7AZHgBvaxEAHL8JXAjnLjAaf
OFUvGIAqfQjkEND3QX8mDkxqc3ik9xvbLbFsFrhk8ZxpLte0qNlJwMjfM96srYka
8RRCtDk8yy0ak5Zh2LpwDLRkI4CsFzT15Gc20SzcsXzsGkE/vij4esS58qCMz4to
w5gCCVxyT/VOxyI3jy1n8IZ1/Ks0B6e8nAy41pCTopJMoOt7gxDt6nOik6yO0+Vq
k6xfF1pqZ4SehEtkNYst0EeMnZ2M09WZou3khF68Xpr0B1GdCJQZlUbFlLHjiprj
D4Cet5rrojODQJ9H56SeJgHPV2DPrniiDRuiTUGqRQgVTO6thzt0WPFgGWdiRSva
yHTcowLTKSYssFVnC6W4osIbFmqeXyMCnbhKYYqrPpHvC6u+/0adwx8qsJMdhmRC
1Nkx7LFbLI545kFMXQr37NdRyF1/3t/vhyou1j3nIzse4YbKlpVQRWAQPZXxR8/S
195e22WnFZ693PaWDviQJhqLy2p70jL85ZlLgoJI7lb03Kl8YX9glMdTUzFx/l4x
QgdNm9NOSDl1VjNnata1LDaaQf2nx/oQLT1QptXD9iqrujFAxy3s1HRDwm4um6kN
Np23xVWOCAmOVKKhnK9hjbOjSlFnLWB6HPBym5BeQqUar3TogmTkeNnpTXQENeNx
/QrI+Dr65KL+COvhaYTu0Lpg9H2Aigbm3zJo2gdPFS6CdZJs4r+s56uk4KOrLHEb
geWNHdhEx/2hRlGEe+OKuJsEKGMmDUQWHX+w4nbFDsMK01ra7bco9+lV5tEfDUa5
HUp5fr1LYNO8VO+V4+kcVx46SLWYieSSy0iq26sIMX8IP9moOy2BQM9gkAi6osoK
C6d2KphAPAPmoqHOiqS9qwSHNcy179qS0r6YCHSJsuTNeHV/j7j+nAIHogfLNOEN
4ZtKdGmX8RxeXygsgpe4CMdPlzOQg9/Rx9t6KB2YTu/VwjBPobjtxsUVEdbu85f0
IpVIEvhfuhVx5V8ZRFDB4XC9Pkio8yxirY+Kn2THkqfsd4xaeJlzfncSYSiQkqfg
Rpo5KR0GoV5c8ta7SXPiiNrvP5MumLZ9AbVWvDAIKgoiS0WSs3KU/wfh/vNOWDjP
DuFFFeGTWiFSd17mmBcWcbnniqIsWtnXCxWGcGlvR4B+h8fQPUv2j8p9i2pFJ+4Q
crffbEMddeOuZB2zMIUyMirCjyFnWCXcUW2jagbRXXex3DNsugy++sJhjzAYw8HH
bmvYFx2/Z77Kr5TMW/JJpwAAAAUWRlXPBG9PQ76HIuYRkkVdFzGSbxcVLLX2N9H7
pY+DHKx8VM4tle+w1ETI1dij5Qq0uvDQxatqNIhy1zIiJ1QTG2APzTLnzDMGR2hG
gAZyEfd0q+s4IzBorUgB5HdeNOSxw+lGpJbacRIZscJ/Uw/2zUrPEujqJRuJ9jVU
6ZvhAtX41IuSVkP9BTtLC92KIAUuGH6hqOhVGD1A/141o8P7
-----END CERTIFICATE-----
~~~

# Acknowledgments
{:numbered="false"}

Thanks for Russ Housley and Panos Kampanakis for helpful suggestions.

This document uses a lot of text from similar documents [SP800208],
([RFC3279] and [RFC8410]) as well as {{-rfc8708bis}}. Thanks go to the authors of
those documents. "Copying always makes things easier and less error prone" -
[RFC8411].
