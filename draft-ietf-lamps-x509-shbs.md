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
  SMI-PKIX:
    target: https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.6
    title: "SMI Security for PKIX Algorithms"
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
       iso(1) identified-organization(3) dod(6) internet(1) security(5)
       mechanisms(5) pkix(7) algorithms(6) 34 }

The public key and signature values identify the hash function and the height used in the
XMSS tree. [RFC8391] and [SP800208] define these values, but an IANA registry
[IANA-XMSS] permits the registration of additional identifiers in the future.

## XMSS^MT Algorithm Identifier

The object identifier for an XMSS^MT public key is `id-alg-xmssmt-hashsig`:

    id-alg-xmssmt-hashsig  OBJECT IDENTIFIER ::= {
       iso(1) identified-organization(3) dod(6) internet(1) security(5)
       mechanisms(5) pkix(7) algorithms(6) 35 }

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

The id-alg-xmss-hashsig public key OID is also used to specify that an XMSS signature was
generated on the full message, i.e. the message was not hashed before being
processed by the XMSS signature algorithm.

The XMSS signature is defined as follows:

    XMSS-HashSig-Signature ::= OCTET STRING

See [SP800208] and [RFC8391] for more information on the contents and
format of an XMSS signature.

The signature generation MUST be performed according to 7.2 of
[SP800208].

## XMSS^MT Signature Algorithm

The id-alg-xmssmt-hashsig public key OID is also used to specify that an XMSS^MT signature
was generated on the full message, i.e. the message was not hashed before being
processed by the XMSS^MT signature algorithm.

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

One object identifier for the ASN.1 module in Appendix A is requested
for the SMI Security for PKIX Module Identifiers (1.3.6.1.5.5.7.0)
registry:

| Decimal |       Description        |     References       |
| ---     | ---                      | ---                  |
| TBD     | id-mod-pkix1-shbs-2024   | \[EDNOTE: THIS RFC\] |

IANA has updated the "SMI Security for PKIX Algorithms" (1.3.6.1.5.5.7.6)
registry [SMI-PKIX] with two additional entries:

| Decimal |       Description        |     References       |
| ---     | ---                      | ---                  |
| 34      | id-alg-xmss-hashsig      | \[EDNOTE: THIS RFC\] |
| 35      | id-alg-xmssmt-hashsig    | \[EDNOTE: THIS RFC\] |

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

# XMSS X.509 v3 Certificate Example

This section shows a self-signed X.509 v3 certificate using XMSS.

~~~
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            34:64:cf:24:7a:c5:07:1f:2b:46:30:c2:3b:33:c0:1d:
            fc:f5:1e:1f
        Signature Algorithm: xmss
        Issuer: C = FR, L = Paris, OU = Bogus XMSS CA
        Validity
            Not Before: Jul  8 10:01:33 2024 GMT
            Not After : Aug  7 10:01:33 2024 GMT
        Subject: C = FR, L = Paris, OU = Bogus XMSS CA
        Subject Public Key Info:
            Public Key Algorithm: xmss
                xmss public key:
                PQ key material:
                    00:00:00:01:7f:c3:6b:e5:27:22:ed:ce:88:86:01:
                    5d:52:70:0e:50:17:04:4d:6f:8d:0d:c3:88:84:46:
                    19:ec:dd:76:f1:94:fd:bc:75:6c:af:ed:fd:2c:65:
                    01:be:ce:ba:be:49:e1:0d:e3:3b:87:70:6a:9a:60:
                    f4:da:f8:6c:15:78:fc:d9
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                6D:35:FC:62:68:53:3A:76:D1:AC:DD:AE:A9:6B:B2:DA:
                83:29:E9:1D
            X509v3 Authority Key Identifier:
                6D:35:FC:62:68:53:3A:76:D1:AC:DD:AE:A9:6B:B2:DA:
                83:29:E9:1D
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: xmss
    Signature Value:
        00:00:00:00:f5:07:3e:97:33:6c:99:f0:3d:56:a1:df:d9:69:
        bf:2b:2d:14:7b:5b:65:7a:92:d6:02:65:38:73:07:19:17:36:
        09:3e:6c:63:5e:cc:4f:45:68:fd:2e:7f:00:1c:2d:e6:15:5a:
        25:7e:3f:08:f2:93:5f:e5:35:c7:62:84:5c:7a:8f:83:d9:98:
        09:71:27:64:e9:7f:b2:e2:29:24:fd:c8:df:7b:f3:1f:a2:67:
        e0:23:8a:fb:03:da:ec:1c:a9:fc:78:dd:b2:b1:7e:2e:11:6b:
        e2:54:47:63:04:9b:fb:7b:a4:9e:c5:a1:78:3d:8c:34:4c:30:
        ec:43:ab:9d:dc:89:c9:a5:a0:5f:b4:ba:7d:44:a2:cc:9f:82:
        9b:cf:84:c9:4f:e2:ff:50:01:f1:f1:26:80:c9:6d:80:62:71:
        ca:65:64:54:e3:72:82:0b:cb:f1:c4:33:29:2f:0d:c1:76:f4:
        b4:65:56:8e:03:19:db:83:bb:49:0c:ba:4e:2a:f5:05:50:84:
        07:5a:85:e4:57:4e:fd:0a:9c:bd:0f:e2:dc:ff:4c:df:65:68:
        05:fb:06:28:2d:de:9d:98:77:23:cf:2b:70:b9:73:88:98:c6:
        6a:54:44:46:6f:51:a6:7e:64:f2:2d:ff:cd:42:bf:81:17:a4:
        fe:88:2b:97:47:e4:cc:e3:6e:7f:f2:cc:68:06:0e:ed:67:20:
        aa:42:44:68:1f:28:3d:c5:3d:f7:90:82:11:63:1c:e6:e3:b9:
        b8:c5:77:6c:8e:11:e1:37:f4:f3:d3:6c:40:58:64:02:09:7f:
        7e:04:db:80:3b:1a:a7:6e:e1:3f:99:33:07:d4:ab:cf:cc:5f:
        da:c7:c7:04:71:e6:bc:3c:09:0c:4b:92:e2:d8:1b:79:4d:95:
        32:25:f1:5e:a7:ac:d4:fa:9a:b6:2c:a3:39:e0:99:ad:48:3d:
        6f:40:66:8c:30:09:8f:b2:bf:46:b6:b0:f2:da:6c:61:94:f7:
        94:be:8a:3b:5d:1e:22:a5:b1:70:65:6b:16:cc:a2:3d:63:8b:
        c9:eb:74:22:b5:7f:0d:f1:3b:23:5a:58:9c:ec:de:72:0f:ea:
        81:c1:60:f0:d1:3e:36:3c:f8:56:4f:c0:c4:45:8c:02:0c:fd:
        af:46:69:c1:80:09:ee:62:81:92:58:08:cc:7f:a9:cc:47:c7:
        52:5a:ce:f9:5d:85:48:50:1e:af:e8:3b:5f:76:63:2b:f1:d7:
        80:ab:79:40:3f:73:29:d6:65:e7:a1:60:12:0f:07:42:85:38:
        d1:60:f2:27:41:4b:71:66:1c:7d:7b:22:6d:59:c3:c6:c4:33:
        78:6a:9d:82:04:1a:3b:16:00:03:80:b5:47:91:b0:2b:e8:7f:
        30:6f:57:eb:9f:fc:3b:35:14:a6:1f:8f:cf:f7:be:73:06:3e:
        52:48:80:37:03:a5:6c:46:b6:23:b5:75:69:bf:eb:36:8a:08:
        ec:c8:49:14:a1:9e:cc:26:08:24:26:0a:73:df:59:1b:e1:34:
        d6:10:9a:5f:40:8f:8f:51:d8:ac:99:2e:d7:99:ed:66:2f:c7:
        41:d1:ed:6f:8c:4a:a9:ed:8c:01:c7:37:ba:53:33:19:e9:ac:
        b0:31:50:ec:a0:26:90:e0:9a:d4:38:35:b3:d7:7a:b5:b1:9a:
        f4:fd:68:85:a7:c9:77:95:6a:15:6c:8a:3d:1a:ec:12:b0:b7:
        cc:75:96:da:74:64:73:32:fc:1a:55:da:e2:c1:92:fc:ec:5c:
        1f:38:59:e9:bf:5e:ca:10:d1:37:d2:4c:0a:f1:d4:d8:a8:ab:
        3d:84:91:2b:44:fd:85:e0:ca:aa:60:65:21:a4:7c:33:17:a8:
        c1:6e:b1:94:4f:3d:1f:c6:88:df:29:63:a3:6c:c2:1f:b6:c2:
        2f:f5:39:f8:97:ca:3d:67:7d:f7:7a:aa:14:86:da:16:a1:eb:
        d8:f7:28:56:ce:d1:a6:72:8e:be:e8:d3:50:d4:39:f0:db:01:
        18:c4:23:0e:89:e3:13:c6:3f:31:9b:22:33:35:85:5c:7b:fa:
        fa:28:63:88:83:80:d9:cb:17:58:08:51:6a:87:c0:ee:1f:5f:
        cc:c7:14:50:c7:07:c4:b5:14:ba:1f:6b:ee:bd:82:c4:a1:00:
        43:bd:4b:fb:8b:b5:77:70:33:b7:9a:65:fb:ce:2d:77:7d:8d:
        ed:26:38:19:7b:75:c0:ff:be:c2:ef:9e:87:3d:1b:92:6e:ee:
        a6:1b:ce:9b:22:2d:70:5f:3e:f7:58:b6:47:ae:f5:a5:9e:96:
        ca:4d:08:d8:13:6c:d4:b9:40:15:aa:c0:70:0d:ea:2f:83:b7:
        8c:96:23:86:1f:56:03:be:62:2c:a6:8a:7b:fb:90:ae:9f:8c:
        9b:18:49:59:17:d6:d7:01:96:f4:6a:62:83:3e:f3:51:32:2e:
        ca:36:c1:07:bd:44:b5:7c:f0:5d:01:d9:a8:34:6d:eb:a2:e6:
        e1:18:2c:c6:15:fa:b4:b0:f6:6d:81:3d:99:d2:49:20:b4:6a:
        de:c0:30:3d:56:79:d1:69:78:0e:4a:95:28:ef:d2:39:a6:29:
        b1:21:16:ce:9f:ef:65:cd:c5:c1:6e:0d:0e:49:20:7c:de:5b:
        5f:5c:22:5e:7c:20:a7:5f:0e:0f:cf:ea:a6:02:97:4d:f1:b3:
        aa:b7:7a:71:1c:6a:7f:18:ad:47:f6:5f:1f:4b:ab:08:9d:ae:
        29:f2:3e:02:3f:b9:6f:bd:77:05:94:64:e2:cb:80:5b:08:9a:
        23:6a:c3:c8:04:53:39:a5:b6:26:06:0b:24:6c:e1:a5:34:2c:
        07:9e:49:29:bb:b3:d5:2a:7c:a2:79:35:de:8a:9c:99:0a:27:
        af:f8:ff:ad:e0:db:64:ca:67:82:84:78:da:70:a4:0e:f4:37:
        b0:0a:a0:79:7b:5a:15:4a:ff:28:c3:82:3f:55:54:b4:0e:de:
        de:0c:9d:de:ea:50:8a:e2:c2:db:1f:58:9a:be:8d:ed:29:de:
        b3:45:f3:06:4d:3d:77:3e:32:21:49:32:ce:6b:b8:5b:48:e0:
        ed:50:44:b9:e9:a8:dd:7d:4a:1b:fa:06:76:d0:90:8e:64:0f:
        da:4e:1b:f5:45:91:58:9b:b4:2d:a6:70:44:d3:ec:01:71:2e:
        86:a4:54:dc:0f:fa:ef:84:b5:8a:a8:bc:81:42:7b:90:8b:9c:
        19:63:98:8c:a2:d0:fd:2e:20:f0:3b:c5:2a:ed:a2:1f:50:0b:
        95:c2:64:6b:cc:3b:67:3e:3c:54:02:2d:23:92:14:e9:7b:77:
        5c:c1:16:5d:f0:43:ad:bf:d2:bb:22:e6:35:be:60:a6:b7:71:
        72:ec:48:0f:f1:8b:94:13:de:ad:10:5a:98:f3:bc:93:9a:d9:
        f8:ca:34:c5:15:52:a9:9e:df:8c:ff:4b:76:c8:31:96:56:eb:
        50:40:17:9f:3e:8f:9c:f9:c4:77:6e:c9:2d:aa:14:63:01:af:
        1c:2f:ed:5c:65:50:a6:35:18:a5:30:ef:7c:a7:b5:a6:f9:65:
        2e:a9:d3:c8:51:b0:e6:3a:07:a5:f4:56:a3:8c:58:f3:91:90:
        ca:80:38:ed:cc:64:07:37:b2:17:45:6d:3b:3e:c8:bb:43:33:
        47:61:be:77:b9:27:c0:99:34:35:3e:ab:6c:44:1e:80:a6:d5:
        3f:8c:e0:d9:aa:f5:68:8b:f3:f0:f3:99:a2:92:9e:b5:a2:4a:
        ae:cb:3e:66:c9:cb:bb:cc:63:04:f2:02:2f:a1:fa:1c:35:68:
        22:9e:37:f6:db:de:7f:0d:27:46:05:29:2a:2c:03:22:0e:66:
        a1:d5:e4:48:95:9e:18:e0:c1:53:19:08:1b:90:7a:2a:31:b5:
        91:70:53:e9:17:68:5f:0d:7c:11:08:7a:cd:46:5a:85:57:86:
        5d:59:42:63:c3:c9:84:00:52:b1:a0:ef:ff:6f:9a:df:67:76:
        0c:c2:68:d8:46:43:d2:88:42:8e:54:fc:75:1d:ca:3c:da:7e:
        2e:cb:51:fb:bf:fa:95:49:cf:b6:47:cb:ab:cd:80:e7:11:5c:
        b5:4d:88:7c:d7:47:df:e8:06:00:22:6f:3c:b2:b7:90:51:de:
        d9:92:30:d3:37:e9:8e:b4:81:c9:7f:4e:6c:e0:5c:4d:cd:4d:
        91:96:0c:c1:9a:7e:32:f2:bb:ce:de:d8:52:1b:2b:f2:77:21:
        9f:5a:dd:54:56:b1:3c:0e:07:5d:ba:66:49:c2:a1:7a:6a:e6:
        17:49:3d:39:b7:21:85:f7:b3:f6:44:50:03:eb:11:68:92:24:
        3e:6a:ac:21:ea:b2:a7:d0:23:34:be:85:3f:bf:78:7e:5d:d9:
        e9:9e:16:47:0a:66:3f:24:3b:7c:3a:cb:36:ee:4d:03:44:10:
        50:66:28:99:d5:c2:98:43:9e:d4:62:32:41:8c:96:74:96:ed:
        d1:d1:1e:df:3f:82:a6:38:38:b5:ee:85:45:91:db:53:04:b5:
        17:da:5e:f6:ae:06:ee:f7:c3:97:52:82:f7:dc:e2:32:e6:28:
        37:8c:74:3a:17:50:4d:b0:8b:33:ee:3d:63:0e:6d:b2:1b:4e:
        84:6c:35:bb:08:03:ca:df:2b:a9:39:e6:50:e0:cb:fb:78:41:
        60:2f:c3:4b:21:5d:9f:6b:80:5d:08:58:26:c1:18:f6:e5:b8:
        40:2c:ca:1c:89:82:79:5c:35:fa:0f:3e:1a:0e:c9:a1:2d:83:
        27:97:2f:78:40:1c:62:f3:f1:75:4d:85:0e:72:7e:99:70:04:
        15:8b:77:48:19:af:29:6b:df:f4:b7:c7:ee:12:75:6e:a1:ca:
        e0:42:41:a0:5e:e0:88:78:f7:70:94:13:a6:03:46:1b:d7:4e:
        a9:7c:01:31:5b:7a:ca:97:04:ca:58:c0:d3:60:7a:fe:f2:8b:
        68:25:7b:a7:10:ac:f2:e9:6e:e0:44:b3:eb:c4:3e:d1:20:07:
        0a:1e:12:11:a4:49:88:be:fb:c6:83:48:2d:d3:24:f9:b9:8b:
        13:5f:7b:23:37:f1:0d:f5:14:6c:71:f1:93:99:cb:8c:3b:4b:
        58:c3:22:e7:f1:ad:4b:f1:5e:17:7b:c1:b8:14:25:df:e0:3d:
        e1:80:af:60:76:54:15:55:a2:7a:c1:34:20:e4:c4:68:68:5b:
        f0:1c:30:36:5e:a6:e0:eb:77:46:f8:2a:00:5e:45:88:dc:cb:
        dd:c6:9d:d3:21:03:c5:18:cb:44:42:33:13:8d:93:75:4a:58:
        1c:3b:cf:2c:2c:d4:f6:07:a5:51:27:5e:39:59:f2:63:f3:3f:
        b6:8a:5c:ab:cb:93:87:5a:ec:c8:e9:bd:2d:42:2b:d3:6b:33:
        d0:8f:c4:87:9f:27:92:d9:01:90:80:ca:77:b4:1d:1e:87:ce:
        1d:19:2a:e2:f4:92:27:0f:a9:89:13:c8:92:97:36:27:37:bc:
        a3:03:de:0d:bd:97:07:5a:04:19:88:14:96:e6:80:ea:96:fe:
        2b:3a:ce:76:8e:17:91:60:df:61:9e:63:a9:ab:29:4b:4a:87:
        b7:eb:7d:41:fa:12:74:5e:a1:55:cb:68:38:d4:9a:2d:ef:73:
        a9:16:ed:59:b8:6d:f9:e8:83:3e:cb:9a:7a:3d:c2:a4:ca:aa:
        ba:f7:ee:22:1e:60:2d:c2:fd:a7:d6:59:43:68:e1:a2:08:6e:
        da:11:84:e4:85:74:0d:c9:52:b0:97:2d:a1:9c:03:21:dd:0d:
        80:4a:10:b8:7e:91:00:e8:f1:5f:73:be:fb:7e:d6:8b:65:c6:
        dd:a3:ed:39:b9:13:20:61:ba:f7:c0:cf:1c:70:98:f3:ac:f2:
        03:09:41:78:e9:72:e6:3f:99:21:5a:29:77:ad:c3:06:d9:0a:
        58:ba:82:5a:a0:12:b7:4f:6b:d4:be:63:b8:30:70:62:17:ff:
        1e:2a:97:2c:c3:82:f9:58:1c:59:1b:33:3b:dc:04:1d:6a:4f:
        26:4f:9f:dc:4b:ac:47:a2:a8:7d:ae:0d:1d:84:9d:e3:57:18:
        b4:60:48:6a:8a:8b:3c:7d:2e:fa:63:2c:7b:7e:51:bb:7d:cf:
        fc:98:0e:8b:21:7e:ca:91:59:55:51:a8:0a:b9:5e:1c:2f:1a:
        ef:45:c7:92:55:19:bb:09:3d:6b:70:61:d6:39:4e:ff:1a:8d:
        39:65:65:33:9a:2b:f3:8a:94:9d:34:39:9f:ec:ff:f3:8c:e0:
        7d:f4:40:98:be:83:e9:57:1c:a0:12:54:9d:89:48:48:35:32:
        f2:9a:ca:6f:82:5f:f3:24:46:c7:59:76:2c:91:ec:74:95:de:
        1a:28:28:cf:6d:b2:6a:70:78:c4:87:12:d1:70:b0:d3:b0:1d:
        64:67:3d:20:d2:5c:61:4d:07:3d:ca:f0:d4:56:70:a7:c2:92:
        21:3b:7c:36:8c:cd:a1:3f:79:e9:07:d7:2d:98:c0:f0:86:c3:
        3b:43:01:e1:82:04:9d:93:c8:48:c0:ca:25:7e:79:7f:b8:84:
        99:03:38:01:90:bb:5a:f0:57:b7:5f:d7:be:ef:92:09:45:7a:
        3d:67:db:5b:11:6d:30:6c:be:a4:73:27:1d:ed:e4:59:ac:b6:
        5f:a8:38:7c:4e:63:dd:12:f4:12:7a:ac:45:5c:e9:64
~~~

~~~
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
~~~

# XMSS^MT X.509 v3 Certificate Example

This section shows a self-signed X.509 v3 certificate using XMSS^MT.

~~~
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            75:34:f3:ec:ac:43:63:74:2d:96:b2:28:99:f5:ca:9c:
            c0:55:9d:9c
        Signature Algorithm: xmssmt
        Issuer: C = FR, L = Paris, OU = Bogus XMSSMT CA
        Validity
            Not Before: Jul  8 10:06:57 2024 GMT
            Not After : Aug  7 10:06:57 2024 GMT
        Subject: C = FR, L = Paris, OU = Bogus XMSSMT CA
        Subject Public Key Info:
            Public Key Algorithm: xmssmt
                xmssmt public key:
                PQ key material:
                    00:00:00:01:14:f4:49:78:f0:17:f3:d7:55:69:97:
                    c6:10:19:f0:f6:79:da:27:95:4f:ef:9c:43:7c:c6:
                    9a:02:57:ca:ac:8f:a3:54:53:5d:45:a1:86:23:f1:
                    66:89:58:d2:bf:1e:7a:ec:3e:c8:a9:4a:77:bd:27:
                    e5:ff:87:44:14:2d:81:ea
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                7F:C5:C8:AC:4C:1F:05:28:53:54:5F:C6:70:71:A5:A4:
                09:08:2F:9E
            X509v3 Authority Key Identifier:
                7F:C5:C8:AC:4C:1F:05:28:53:54:5F:C6:70:71:A5:A4:
                09:08:2F:9E
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: xmssmt
    Signature Value:
        00:00:00:e4:65:12:e4:f4:c5:f3:30:85:e7:d9:26:89:7a:40:
        cd:06:93:00:3b:73:1f:b1:45:23:35:3a:87:ba:b4:b4:32:c5:
        70:17:df:37:81:73:5a:d0:1f:07:e7:e8:29:92:e9:c6:d3:69:
        db:4e:f8:47:fd:94:97:bb:d0:f9:e7:0f:bb:c8:28:ff:88:20:
        c2:b2:c8:49:4d:81:91:b9:60:6c:c8:b3:28:d7:cf:c4:90:23:
        70:33:dd:a9:68:b4:97:0e:d3:15:24:23:f3:e8:16:71:9b:80:
        46:81:94:61:69:47:87:8d:b5:d2:d9:d1:d1:bd:d7:dd:79:4b:
        61:f6:07:cb:eb:6a:26:69:d4:d8:27:c3:86:76:56:91:7f:95:
        53:00:23:78:7e:e4:cd:42:92:71:9b:b8:3f:37:c3:60:08:65:
        3d:42:2d:4a:6f:ed:76:e1:b6:da:da:72:c5:18:9b:20:f4:b9:
        cb:02:e5:0f:d8:bc:da:96:9c:7d:4d:67:be:20:29:1e:16:1a:
        9a:89:a9:9a:47:57:a5:08:94:97:2d:6c:6f:c2:77:e0:81:3b:
        55:95:48:8d:90:98:ad:73:b9:cb:a4:89:ee:83:73:ff:38:09:
        9e:6b:0b:53:27:5d:50:33:6e:72:d7:70:73:11:cb:d4:81:21:
        f6:01:12:ab:35:f4:fa:33:37:b7:ca:40:a1:ed:22:f1:58:0e:
        bd:ba:b3:3d:c5:ac:fa:2a:2f:ae:a3:ec:bd:a5:79:cc:d8:f6:
        0f:1c:cc:d2:02:f3:76:66:b9:c6:5f:ab:95:d6:d5:e2:75:52:
        37:f0:4d:da:b9:ca:cc:c5:df:f7:46:a1:28:f7:91:cd:32:45:
        40:06:83:15:78:2c:12:ed:ab:8d:80:8f:7a:7a:01:f1:01:c3:
        b8:b2:04:a3:0d:bf:a1:6c:30:ce:ad:9c:fb:c4:69:2b:28:c3:
        f5:32:f5:32:dd:dc:11:9c:08:fa:98:03:3e:47:8f:07:cb:69:
        c1:a3:8d:43:a0:e0:3e:9e:2f:1d:66:c0:fa:52:a3:39:5e:a6:
        76:ae:cf:b8:9d:64:75:12:7c:01:ba:d7:43:d4:8f:fa:1f:8a:
        fb:6d:e8:0a:e5:91:84:0b:b9:31:c7:07:f2:19:d3:ae:f2:92:
        04:44:79:e7:4d:3e:3f:81:f3:b0:d1:6c:d7:0d:91:52:ce:d0:
        d3:c9:60:d2:11:a4:10:18:46:82:7a:ec:56:2d:28:31:88:dc:
        32:06:9f:6c:9e:b3:d3:54:1e:eb:6a:aa:37:36:09:cf:fc:a7:
        f4:5b:4b:31:13:16:41:cf:49:cc:40:2d:8b:4a:a5:b2:30:02:
        a9:27:91:55:ca:33:4c:3e:ba:ab:fb:5a:c6:98:82:4f:f7:81:
        a7:d7:a6:d5:0d:df:cf:2b:5d:06:74:8d:78:23:91:71:c6:ab:
        fe:3e:f8:91:55:fa:31:22:f4:51:98:9a:6e:d7:81:aa:6c:08:
        f3:a4:58:1d:ed:bc:65:31:82:0d:1a:b2:ad:60:2b:71:7f:63:
        9d:c7:b6:e4:e4:0f:9c:4b:7e:6c:4a:e7:7f:96:1f:52:26:c4:
        5f:52:d0:4d:b2:a8:38:71:95:37:06:c6:ff:f7:a4:b6:e4:3f:
        12:bd:15:1e:49:46:24:db:42:5c:65:cf:1a:9c:98:e5:ac:8c:
        c5:04:b2:9c:4a:15:25:c5:45:66:8b:90:95:b2:62:92:99:8c:
        9f:87:9a:d5:a2:18:ab:77:a9:10:c8:6c:2c:5d:9e:3a:84:f3:
        b6:58:64:f0:1c:ce:ec:50:9a:82:b6:59:b8:ae:81:0a:75:46:
        00:5c:56:ef:44:3b:80:5c:72:f1:ef:5b:2c:a1:ed:14:27:cc:
        55:5e:52:17:8d:bd:34:ae:a0:bb:be:f5:a8:15:9e:3b:59:8e:
        f8:07:87:d8:06:68:83:f3:51:c8:64:bd:a5:d4:3f:ad:20:93:
        62:09:62:84:ab:d0:db:2d:c9:2e:ef:63:1c:00:02:23:52:09:
        2a:e9:6d:a7:15:6c:d4:28:1b:24:2f:5d:35:9f:2b:b5:57:be:
        5f:5e:55:e1:c9:cb:5b:8f:99:b2:5f:d6:61:00:4e:e2:2e:2e:
        25:5c:8c:cc:e6:e6:aa:52:aa:51:11:2f:f9:ba:63:61:ba:4e:
        26:ea:46:2f:68:1d:06:31:fe:97:a1:62:04:b4:b5:cd:ff:7c:
        99:d6:80:05:46:6e:7a:ef:a2:04:cb:de:d5:f2:21:ae:a1:62:
        b5:a0:f2:f5:a7:04:d2:6c:a3:9e:31:06:c4:a1:0b:3e:c8:92:
        2c:93:05:e3:3a:51:94:c3:23:3a:66:7f:df:2c:a5:19:e2:17:
        2b:c5:4a:31:37:50:ec:02:5f:84:43:90:69:a0:ca:4f:64:fa:
        99:1b:19:e3:11:e0:a6:27:57:94:06:99:03:93:f8:89:da:e9:
        61:28:26:8f:3c:9a:f9:8f:f8:64:fb:23:1d:f1:dd:a0:87:e6:
        a4:02:9c:60:e8:0b:43:3e:f1:b7:65:6e:0b:ab:7f:4e:80:ac:
        68:3e:d5:df:7c:94:da:c3:98:b6:d9:3b:d2:70:34:7f:5e:1d:
        fd:0d:70:fe:fb:e8:85:e7:91:6e:95:f7:f4:f3:48:6c:82:db:
        74:02:4e:e4:65:05:ea:17:a5:82:40:95:7d:c1:84:f7:11:37:
        a6:f1:34:f5:cb:60:66:cf:a1:79:73:7d:d8:b0:d0:85:09:68:
        a5:c8:db:fb:70:d5:1b:91:9f:d6:1c:f6:0b:ee:b5:f0:b5:60:
        15:30:57:1d:e8:68:fb:e0:c6:64:ec:41:43:90:87:cb:0f:ed:
        b1:6f:43:3d:88:6f:b7:20:30:13:7d:97:67:d7:a4:ab:4e:47:
        c4:ac:09:7e:49:c3:b0:c7:0e:65:3f:3b:d6:15:c0:fa:62:44:
        11:03:47:14:bc:56:43:9d:77:eb:d2:31:21:7d:8e:5c:b1:bb:
        1e:d6:2f:3d:93:e9:3d:49:ac:63:de:ba:2c:e5:48:95:8b:81:
        d8:7b:d1:51:7d:36:6f:8b:43:30:db:e4:10:98:5c:08:4b:94:
        ec:ff:80:20:58:b9:94:76:e6:ca:9a:ed:cf:20:77:a8:e3:ff:
        81:4a:71:97:c3:17:b0:ce:17:46:50:eb:bb:af:ee:f8:3c:02:
        a1:09:4c:8f:0d:30:38:e6:e6:d6:21:0b:a8:7c:e9:fe:0a:b6:
        18:58:79:5d:cd:04:df:18:71:b6:d0:a5:7a:01:d4:4d:51:c7:
        22:13:3b:1c:eb:06:d1:b1:dd:b3:9f:3d:ce:90:79:c8:87:c1:
        c6:9a:a0:3f:76:cd:52:d0:8c:eb:be:a9:74:c7:86:19:e3:d3:
        2b:1e:2d:29:6b:6e:0a:5e:7e:2b:8a:77:51:0b:a4:9b:33:44:
        9e:c0:33:4c:e4:02:45:29:40:c4:60:94:a0:19:ce:45:df:6a:
        2a:c4:da:af:cc:c5:b3:36:87:df:50:79:3b:9f:9c:e2:f0:ef:
        01:1d:1d:73:11:ec:02:8b:3f:e4:43:cb:c6:95:26:fd:17:af:
        c0:ec:af:2c:e6:81:d5:20:16:1e:22:95:80:c3:58:62:68:7e:
        1f:a8:19:ba:08:75:d1:b1:5f:b6:d3:88:48:1f:24:1a:62:b8:
        38:76:29:7a:3a:e6:c4:39:d5:3c:b8:c6:ef:a3:4e:8d:97:d6:
        dd:70:ed:bd:5e:d7:a9:10:a7:d3:c4:a8:98:a8:bf:53:8e:3d:
        7b:83:fb:b6:84:2a:24:63:44:fe:d5:92:2e:eb:1e:2e:8d:5b:
        9e:25:ca:5c:6b:e1:2d:0c:03:c5:e7:d8:91:51:89:a9:7e:8c:
        1c:2e:b1:b6:bf:ce:2b:17:80:ca:8e:f9:c0:b6:ae:59:e2:07:
        30:fb:10:41:36:0e:29:b0:bc:6c:ef:86:7e:60:4c:1d:e2:9b:
        6d:2e:aa:d6:e5:ff:8b:f2:14:d2:f7:96:54:51:d2:7d:b4:23:
        87:f4:6b:99:7e:97:99:1a:86:46:2f:79:1d:69:f3:be:51:23:
        b2:47:24:f8:ca:b2:0c:25:e8:1c:bb:b4:96:e1:82:57:e8:c6:
        78:3d:0b:fc:02:6b:60:1a:56:06:13:a9:cd:81:ba:d1:45:b4:
        9f:51:8f:f9:19:34:c4:ae:95:5f:6d:23:b6:8d:0f:1e:30:ae:
        e1:84:96:cb:69:f9:99:cb:0d:35:4a:a7:bb:58:69:a7:61:2c:
        80:cf:0f:ba:bb:de:10:e9:d2:cb:25:74:d0:80:1e:f8:a6:51:
        61:dc:70:42:1d:32:be:e6:e3:42:21:0b:aa:5c:e8:02:a4:7a:
        ca:f3:47:ea:89:84:ff:b8:9a:83:99:b8:82:98:af:71:9e:28:
        fe:a9:e2:b6:22:91:ce:db:e9:65:bb:83:0c:7a:28:3e:01:97:
        66:58:e0:fc:22:eb:37:c6:b3:7d:94:63:53:32:68:c2:d2:2c:
        46:56:b4:5c:f6:3c:d6:ff:81:c5:53:eb:d5:82:8f:7d:20:2e:
        be:b1:83:a5:29:fa:96:28:fb:2f:4e:f2:61:d4:5c:16:bd:e1:
        e3:2e:34:9f:4a:6b:1d:2d:d4:6c:55:f1:d2:cd:82:1a:40:84:
        7b:f8:f3:ba:c4:72:5a:01:12:08:86:57:cf:6a:ab:92:c3:b5:
        af:bb:db:f8:43:a5:85:e1:cd:65:c0:45:79:84:9e:2b:6c:37:
        86:5b:df:eb:54:46:b6:70:7b:53:16:5b:03:49:d3:b5:23:a4:
        42:31:57:f3:bd:72:4f:64:46:07:10:3b:27:14:37:e6:8a:5f:
        ea:cb:5e:a3:9e:e4:1e:5c:2f:49:31:9c:3d:ad:03:99:b0:e8:
        0a:64:1f:b0:c2:c9:7c:e9:e0:d4:98:99:a3:dc:3f:6b:22:b8:
        48:c6:ae:74:b3:ae:44:f6:15:ae:7f:4a:c4:df:d5:f7:4f:19:
        99:bc:84:b4:e4:b9:50:91:66:9f:a9:0a:c6:fd:d9:ac:d6:17:
        19:da:bf:d6:be:95:ac:37:6d:e5:61:09:2f:db:f0:d8:23:8b:
        2f:89:a1:1a:95:e0:32:ad:6c:ca:90:19:bf:ca:06:0d:5a:5f:
        20:5f:9d:6b:22:83:ff:35:87:83:07:54:47:4b:e3:0d:0c:f1:
        92:30:85:ed:68:18:92:fa:0e:de:9e:b4:77:2b:14:f8:88:d5:
        30:43:9e:d7:da:02:54:79:c8:b0:00:91:3b:17:8c:52:3c:26:
        69:5a:3d:59:38:ce:b4:11:b2:a2:74:f8:4d:85:e7:b0:72:27:
        a2:2c:4c:2f:e4:7d:c7:b4:8c:c2:fb:1c:1e:e2:8d:47:f0:68:
        d3:8d:62:eb:91:5d:1a:76:2d:4e:f3:24:7d:15:a8:73:e1:3d:
        bf:0c:05:a6:05:c0:c0:9b:21:f6:28:d0:a5:67:da:7f:b1:d7:
        cd:a0:79:d3:46:5e:cd:c4:c1:99:7a:4d:7b:c1:78:36:c2:55:
        6c:65:bb:5e:a0:fd:95:f5:04:35:82:d3:76:50:8e:69:52:d3:
        c1:ce:af:24:5d:bc:f7:37:c2:6e:d2:51:da:bb:bc:af:58:d7:
        3d:91:f7:73:a5:11:df:fe:73:03:68:4a:47:ff:89:31:5c:56:
        8a:64:ca:8f:34:e6:8c:0f:80:83:36:93:df:0a:9a:d2:5e:f1:
        33:86:cc:94:05:38:bc:a2:e8:28:d5:8d:e6:d8:08:96:a5:9a:
        b8:53:5a:13:53:7d:08:62:1c:63:01:c1:63:0f:00:48:bf:58:
        6f:63:c5:d1:80:14:47:e2:f8:05:9d:c7:b5:41:09:99:09:63:
        d0:c8:68:cd:7f:9a:42:73:dd:37:95:d3:7e:42:a1:56:dc:c8:
        0d:40:29:af:4e:97:42:cb:8b:aa:00:3d:cd:98:85:b5:3e:f5:
        24:d5:50:f5:1b:38:66:85:3f:ac:0b:0f:84:26:91:81:0d:90:
        a7:bd:3e:17:9d:b3:c9:05:1f:ee:3d:fe:d2:d4:9a:2f:0d:ee:
        7b:6a:48:d4:74:bb:35:8e:40:75:31:0d:e1:da:34:3a:83:70:
        9c:9d:72:14:f8:12:fd:8a:d4:09:87:be:23:82:0f:ab:1b:13:
        f6:87:af:f5:0d:33:f3:0b:2e:2e:6d:97:d3:1c:2f:76:54:34:
        da:8e:64:11:e8:b6:e3:15:7b:5a:27:e0:0a:3c:14:98:71:28:
        d1:93:a1:1f:f3:f4:b9:33:40:73:b8:00:77:17:fb:6c:03:fa:
        dd:3f:2e:70:21:44:5a:d6:e3:b0:65:45:16:e5:42:6e:b2:7b:
        8f:00:1f:81:57:f6:7a:ea:b2:cf:74:f6:f3:58:91:e8:1f:16:
        ee:0d:5f:d6:f9:eb:30:2f:49:e1:1f:4a:f7:d0:c9:26:af:fc:
        36:7c:8d:1e:a5:df:04:fc:0a:7b:c4:aa:c4:26:e8:62:56:fe:
        0d:96:c7:be:4e:da:14:2a:81:ad:54:ab:b1:13:54:29:61:a2:
        62:67:e9:49:63:93:37:36:93:dc:35:1b:49:c5:53:19:82:c2:
        1a:67:0e:1d:9d:92:08:d0:13:04:5e:ba:9e:2a:6c:a7:08:b0:
        e4:ec:15:ea:b4:9b:fe:c5:f6:c9:f7:5c:0f:5c:a6:c7:1a:cf:
        40:66:3f:dc:2d:d7:7c:cb:99:c0:a2:50:72:b6:b2:ce:88:65:
        48:5d:bd:10:17:97:51:f2:7a:3d:65:e8:1d:30:96:6c:e1:73:
        9f:99:3a:35:29:41:08:0a:11:63:da:eb:a2:33:8b:2f:c5:bd:
        e5:28:1e:30:eb:3a:fc:17:48:ac:fd:37:e7:d9:0b:62:39:b3:
        8f:d3:0c:3b:d8:0c:eb:84:fa:ec:90:61:4e:c1:c2:62:b6:1e:
        cc:30:e1:6d:cf:e0:a3:9a:0c:6c:7b:ab:4c:73:c8:be:9c:34:
        05:fc:b1:df:ea:22:f8:f2:54:09:c3:c8:dd:a6:c5:d1:a4:7d:
        85:39:9f:f2:68:4e:d8:20:d6:84:d0:30:98:1c:35:d3:23:6d:
        a5:37:c0:e7:01:8d:ab:d2:f6:94:f1:cf:81:dd:22:25:13:37:
        86:54:f3:6c:e3:5c:43:a2:f5:10:6f:84:a2:50:d3:94:9f:b0:
        a5:81:39:5b:e7:4a:af:63:e6:2c:0e:d1:f2:f4:74:8b:da:5a:
        5a:d5:f4:88:4a:2a:4b:18:c6:9f:44:88:43:81:24:1b:d9:da:
        59:20:4f:97:15:44:89:9e:f7:92:22:61:c4:c0:5c:06:f7:4a:
        33:d2:55:e3:45:55:92:42:78:ed:fb:74:96:86:90:96:86:b6:
        aa:ca:c3:3c:bb:91:8f:55:77:35:45:ef:bf:17:e1:3e:d2:f9:
        df:95:8b:8b:63:aa:c7:68:a0:1d:cf:f1:9d:c4:69:d9:d9:ee:
        30:f8:83:f4:b9:77:ec:7d:fa:f8:da:b9:35:52:f0:81:23:c6:
        36:1b:2d:c7:6f:33:11:6e:ab:0e:c1:43:4e:0a:0a:48:5c:f5:
        31:62:68:8c:a0:d0:f2:64:5c:27:13:aa:67:0b:cf:53:73:c0:
        1d:24:3b:66:75:5f:b0:60:d7:11:e0:a0:f7:8c:06:7d:f8:51:
        8d:85:98:c6:3f:77:a9:61:5f:62:43:15:1e:4d:95:86:11:1d:
        01:17:67:53:2c:ef:94:05:05:f7:20:bd:20:10:e0:26:8c:33:
        c5:51:e2:5d:b4:d0:6a:79:fc:5b:78:d3:84:cc:bf:8b:98:aa:
        70:9d:78:d4:ad:2b:4d:0d:72:21:e7:a8:18:1b:3a:29:93:80:
        35:f6:f2:88:fa:6f:d6:a0:b0:a9:bc:27:b6:4a:89:de:07:89:
        36:d7:e1:e8:95:5d:17:14:db:41:1c:05:76:58:37:c4:8d:65:
        f1:1c:72:b8:f7:f0:3c:96:30:d7:7e:4a:9c:3d:d2:1d:17:bc:
        3b:7b:d7:45:d9:c0:0b:03:f8:7b:d6:f5:ae:4b:65:90:06:49:
        27:b5:bb:79:d1:ba:43:65:56:b6:e2:1b:b2:d4:0d:81:a2:c5:
        d8:31:8e:12:12:5f:2b:d9:e6:e0:4a:b1:b6:42:6c:0f:fd:9d:
        5e:c2:54:d9:c2:92:08:bf:4e:69:2e:39:7b:11:29:5a:8c:a1:
        7c:62:65:91:58:36:13:9e:28:b7:1a:d6:d8:ef:85:2e:46:b1:
        45:37:bd:dc:19:0c:56:eb:b3:a4:9a:f1:d1:34:e7:79:76:41:
        ee:26:e5:67:ad:1a:2f:2e:b3:76:76:96:af:d8:bb:8e:87:67:
        c7:b0:1c:05:c1:51:d7:59:8d:0f:eb:75:4e:4b:b7:be:b6:10:
        c2:b2:66:ba:85:d1:dc:26:9e:8f:02:70:f4:6b:2b:bf:1e:04:
        bb:29:79:f1:74:eb:c1:2f:33:1f:dc:f5:99:e7:7c:cb:b0:7a:
        a7:27:02:25:12:e0:d1:2a:80:a7:9c:1c:68:f8:f2:5d:3a:26:
        9e:7f:9a:2b:fb:da:7e:56:e1:a9:30:eb:95:4d:dd:c5:bf:a1:
        2b:74:3b:62:93:58:76:83:28:a9:eb:1d:f3:e7:fa:64:95:7f:
        90:0f:a0:9e:3f:0e:fe:aa:51:9d:10:25:b5:41:a9:a1:aa:10:
        a0:96:30:9f:07:ad:02:ab:64:9d:24:dc:33:b7:98:f5:67:1d:
        e1:c3:cd:49:a9:b4:c1:b2:42:92:4f:7e:ad:f0:01:85:cf:39:
        7f:07:f5:b3:c1:32:87:b7:6f:1a:cb:f1:5f:9c:eb:52:8c:ec:
        65:77:78:6e:6e:60:d7:c4:00:e5:b3:d5:27:5e:a9:72:ab:d7:
        a3:09:44:ae:f9:00:af:5e:9d:7a:61:cc:b7:43:49:34:f6:53:
        2a:dd:09:ca:af:af:a4:14:6a:d2:17:b5:f7:97:49:05:80:72:
        fb:93:8a:62:a9:73:4f:7c:1b:a4:11:05:55:43:08:5e:7e:59:
        5b:9c:89:e1:d8:6c:2d:8b:b7:ac:06:7e:83:44:bf:5e:c2:ba:
        31:c0:1b:0b:f3:3a:5b:60:6e:fa:fc:1b:8b:df:69:53:7a:c4:
        95:85:4a:78:b2:ea:4c:ea:91:36:ef:a5:50:48:67:e9:55:fd:
        76:03:9f:70:a1:e2:a9:66:b0:02:54:05:8e:04:61:57:8b:60:
        bc:2a:8c:cc:5b:38:e0:ee:4c:28:cf:9c:ea:35:50:26:99:f7:
        5e:08:1c:98:36:8a:18:a0:d8:66:9c:1d:f8:c9:6c:c4:ab:6c:
        2c:1c:63:48:16:fe:71:01:01:c3:33:8d:7f:a4:51:72:f0:10:
        11:3e:ab:78:66:7b:27:97:3a:c2:f2:f9:7c:9b:ec:dd:72:59:
        80:97:43:ea:fd:f6:d6:80:6f:e7:75:10:22:71:a7:3e:5e:39:
        34:e2:a4:2d:56:64:f4:52:60:c4:7c:7a:39:88:e5:9b:19:c3:
        a1:7a:9f:dc:e7:7b:83:de:a3:93:d3:c0:61:44:ae:f2:1a:a4:
        0f:fc:32:98:ff:6a:65:4d:21:ab:b7:3c:35:80:a2:e6:76:06:
        5f:71:e7:23:e8:f2:96:fd:5b:dd:21:5b:c9:27:48:f3:65:f8:
        dd:1d:f3:cf:9a:b3:06:e1:1f:9b:c4:e2:e7:fe:26:77:fa:90:
        3e:60:1a:66:d4:44:e3:24:36:cc:2e:8d:af:95:fe:0a:a8:86:
        d9:a9:77:50:d1:22:f2:70:6b:9b:67:0f:60:e9:e2:b0:9d:ed:
        ce:f8:db:5d:28:0c:73:b9:f6:ee:14:0b:4d:34:b2:f5:b0:1b:
        6b:52:b4:ed:a4:df:f9:9e:28:0e:3b:f0:c6:09:c6:2a:ef:6a:
        76:ac:9f:4d:27:9c:79:25:97:ee:ed:be:01:9a:2e:04:6f:9b:
        7c:61:17:8e:83:26:6b:82:c2:97:fb:61:bd:a5:5b:da:db:af:
        12:ce:be:86:d8:76:d5:7b:0a:af:c9:ae:a3:33:6f:57:88:17:
        82:e4:33:49:63:58:b8:87:66:de:d4:f2:95:4b:05:29:5d:72:
        ae:f0:36:2a:fd:7a:3e:e8:86:3a:c7:e5:9e:f9:5c:ff:8f:c7:
        6e:1d:ff:ba:e6:99:5b:54:8b:16:1c:b6:88:9b:6b:1f:a8:09:
        2e:64:51:b9:6e:e7:a5:79:98:74:c6:25:31:a5:6c:fb:87:f9:
        12:5d:dd:ac:5c:08:c3:2f:98:03:a8:9f:00:77:7d:a2:a1:5f:
        88:b8:2f:0c:7c:4d:21:db:42:2f:b7:60:82:52:67:c3:07:da:
        6e:fc:aa:b4:dd:d2:cd:77:f9:6e:43:49:b4:dd:f6:da:b0:e9:
        fa:44:4b:9d:9c:3e:08:cb:93:a7:cf:98:82:7f:a0:14:43:41:
        d3:aa:09:ab:9c:9f:09:b7:c0:49:7f:b5:38:4b:9c:20:ae:13:
        a5:ad:44:0f:97:85:64:f7:8e:e8:5d:34:c9:d8:75:34:9c:28:
        78:bb:03:dd:71:dc:c8:4d:de:e8:43:01:c1:a4:9d:1f:d2:34:
        6e:88:82:93:73:0c:96:82:09:07:6f:6a:55:0b:a3:f9:9e:bc:
        6b:25:47:a6:c3:2c:57:de:fd:90:a2:0c:9e:de:14:ee:be:40:
        de:20:51:ff:40:a3:4e:1b:91:d6:ff:ee:75:56:7a:4c:50:1f:
        89:f2:af:de:b4:f5:1c:b3:52:f4:e0:61:43:c2:54:73:58:8e:
        cb:80:c5:7e:14:4e:05:d8:ce:49:0c:3e:fd:27:72:25:1c:40:
        52:16:2e:d7:59:ef:24:01:8f:4e:03:6a:2c:2c:bd:fc:05:2a:
        42:60:a9:9a:6f:97:2c:32:4a:8b:e2:9b:ed:cf:f2:19:7e:91:
        0e:03:2c:03:7a:ef:97:71:63:77:60:91:cc:6e:c1:b5:5e:17:
        da:c6:0e:bb:fd:ba:ba:3c:5e:ba:27:c0:60:ed:5e:98:04:35:
        71:a1:16:bf:91:91:1e:b3:e4:61:dc:71:fd:1f:53:6b:cf:d0:
        74:a0:60:62:7b:a1:dc:f3:25:17:94:90:03:2f:bd:60:85:dd:
        e8:eb:19:63:fe:af:c6:5c:f9:a9:08:1c:60:3e:87:41:12:58:
        8b:4c:e2:62:ae:82:c9:d6:aa:30:35:6a:ae:4f:6e:de:e3:1d:
        9b:4f:23:47:64:28:9b:4c:2d:20:54:1c:bf:62:7b:4e:30:59:
        a8:8b:62:f6:e5:1c:09:fb:2e:6b:ab:28:0c:ea:50:f4:02:8a:
        75:fd:18:b0:e7:1f:b2:05:6c:d3:e2:cb:f6:11:4e:48:25:72:
        dc:6d:e2:4a:63:27:1e:4a:a7:9b:dc:0c:3d:75:6a:95:ae:c5:
        fa:2c:a5:68:32:02:b5:5a:69:a4:76:fe:9d:1b:92:61:b3:3e:
        e7:8f:77:e2:12:6d:bf:51:72:ff:ee:29:2d:44:1c:79:8a:de:
        04:fd:70:12:6b:2d:01:d0:1c:74:b9:41:6a:9c:ef:83:7f:62:
        cd:47:9f:c4:39:f9:b3:89:18:81:b8:89:c5:1d:db:c5:2a:ed:
        9a:de:ff:79:6e:5e:11:a9:f8:4f:de:e0:a4:63:e9:74:08:81:
        6e:01:3b:2a:9c:3c:fa:ad:a0:08:62:28:8b:86:e2:43:76:aa:
        a4:3f:09:80:56:b8:8c:d8:c1:2f:df:1f:a3:f0:e1:98:96:e4:
        7b:c5:51:c2:52:8b:de:db:b1:61:56:34:e1:11:92:ce:3d:9c:
        95:90:13:32:a7:4d:65:9b:bb:56:31:9e:9a:5c:38:e5:21:74:
        61:bf:09:20:ad:f0:53:8e:5f:4d:6a:86:fe:17:a7:ed:86:92:
        dd:19:7b:ad:79:f0:69:80:71:30:eb:0c:f9:43:93:32:fc:28:
        1a:2d:36:65:72:f0:f1:24:51:5c:80:67:21:0b:f3:b4:9d:09:
        d9:e9:04:9f:e8:08:fe:de:a5:f4:ee:6a:03:c0:81:5f:37:05:
        6c:05:70:19:12:52:02:89:40:33:b6:5b:5c:bd:54:1d:ca:24:
        46:66:66:b4:fd:b6:22:05:91:f8:ed:8b:7f:cd:bc:4a:cb:e3:
        b4:ce:df:cd:ff:d2:f1:72:7b:1a:b2:e9:aa:aa:51:e4:9a:4c:
        ee:dc:f6:42:b5:b1:ba:02:1d:53:36:2e:01:0d:df:c5:1b:e9:
        75:e3:51:0b:08:df:b5:19:25:f4:1c:ec:8c:38:30:41:ad:c9:
        78:1a:c8:92:e7:53:67:1e:89:d0:06:de:ef:90:28:32:2c:a8:
        02:10:24:44:2f:fb:dd:cc:7f:8c:1c:c5:a2:ca:21:2a:fc:ea:
        e8:b2:90:5d:90:80:6b:95:1d:e5:77:1e:27:38:c9:72:e0:cb:
        8b:74:df:0c:03:99:43:84:49:e0:9f:e1:95:3e:7d:80:3c:6f:
        3a:1d:77:7b:7e:d2:5a:38:80:04:ba:af:0a:3a:90:12:2c:1a:
        b2:62:31:0d:06:15:6a:23:9a:33:6f:2d:55:8d:cb:a8:6e:db:
        7a:f2:60:e0:a7:10:d7:07:68:be:09:43:21:95:f9:61:5a:d7:
        48:74:d4:9d:ed:08:51:7d:5e:14:30:7f:5d:72:37:34:18:17:
        89:81:d3:96:ca:ed:16:b6:01:41:69:43:1c:5c:61:72:ec:90:
        7e:11:af:b2:54:e1:82:9c:c7:1f:1d:50:2e:fa:e8:d2:cc:f9:
        0d:01:3e:3a:78:cc:5c:a8:b0:f8:a9:bf:4f:43:62:3c:00:b1:
        21:2d:98:df:ac:5a:5f:f4:6e:a2:ea:58:22:e7:21:59:a4:a0:
        46:f0:ce:85:e4:93:26:dd:8c:f7:5c:e5:a7:2e:d1:d6:56:31:
        b5:1c:1d:99:0c:3c:d4:b8:35:15:52:cb:b9:50:69:ca:90:89:
        db:98:61:fb:f8:15:9b:63:47:db:71:41:83:9c:25:78:4e:f3:
        1d:32:02:19:75:ce:6d:e1:d4:f3:12:bb:de:6a:b1:40:a9:63:
        17:88:98:dc:b9:06:a4:2d:19:28:14:08:2a:54:c3:e8:be:da:
        b4:7a:2c:57:68:2f:ab:32:1b:bd:b2:1a:06:4c:ea:e4:93:11:
        67:60:27:eb:41:13:39:0a:6a:4c:9c:78:68:d6:bd:b1:78:47:
        ba:04:bb:68:1d:01:4a:a9:6f:d8:80:58:1f:7b:6e:92:71:ed:
        a8:93:a3:bd:2c:48:9f:31:ff:85:d6:ee:ed:dd:5c:ff:a6:8f:
        55:03:93:2c:88:71:38:8c:4d:f7:60:f2:86:01:a7:1e:7d:47:
        8c:56:76:67:d8:9b:22:ce:cc:12:1f:f6:ad
~~~

~~~
-----BEGIN CERTIFICATE-----
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
fUeMVnZn2JsizswSH/at
-----END CERTIFICATE-----
~~~

# Acknowledgments
{:numbered="false"}

Thanks for Russ Housley and Panos Kampanakis for helpful suggestions.

This document uses a lot of text from similar documents [SP800208],
([RFC3279] and [RFC8410]) as well as {{-rfc8708bis}}. Thanks go to the authors of
those documents. "Copying always makes things easier and less error prone" -
[RFC8411].
