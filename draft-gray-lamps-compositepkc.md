---
title: Composite ML-DSA for use in X.509 Public Key Infrastructure
abbrev: Composite ML-DSA
docname: draft-ietf-lamps-pq-composite-sigs-latest

ipr: trust200902
area: Security
wg: LAMPS
kw: Internet-Draft
cat: std

venue:
  group: LAMPS
  type: Working Group
  mail: spams@ietf.org
  arch: https://datatracker.ietf.org/wg/lamps/about/
  github: lamps-wg/draft-composite-sigs
  latest: https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html

coding: utf-8
pi:  # can use array (if all yes) or hash here
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:
  -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: mike.ounsworth@entrust.com
  -
    ins: J. Gray
    name: John Gray
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: john.gray@entrust.com
  -
    ins: M. Pala
    name: Massimiliano Pala
    org: OpenCA Labs
    city: New York City, New York
    country: United States of America
    email: director@openca.org
  -
    ins: J. Klaussner
    name: Jan Klaussner
    org: Bundesdruckerei GmbH
    email: jan.klaussner@bdr.de
    street: Kommandantenstr. 18
    code: 10969
    city: Berlin
    country: Germany
  -
    ins: S. Fluhrer
    name: Scott Fluhrer
    org: Cisco Systems
    email: sfluhrer@cisco.com


normative:
  #RFC2119: -- does not need to be explicit; added by bcp14 boilerplate
  RFC2986:
  RFC3279:
  # RFC4210: -- obsoleted by 9810
  RFC4211:
  RFC5280:
  RFC5480:
  RFC5639:
  RFC5652:
  RFC5758:
  RFC5915:
  RFC5958:
  RFC6090:
  RFC6234:
  RFC8017:
  RFC8032:
  #RFC8174: -- does not need to be explicit; added by bcp14 boilerplate
  RFC8410:
  RFC9810:
  X.690:
      title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
      date: November 2015
      author:
        - org: ITU-T
      seriesinfo:
        ISO/IEC: 8825-1:2015
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    date: May 21, 2009
    author:
      - org: "Certicom Research"
    target: https://www.secg.org/sec1-v2.pdf
  SEC2:
    title: "SEC 2: Recommended Elliptic Curve Domain Parameters"
    date: January 27, 2010
    author:
      - org: "Certicom Research"
    target: https://www.secg.org/sec2-v2.pdf
  X9.62–2005:
    title: "Public Key Cryptography for the Financial Services Industry The Elliptic Curve Digital Signature Algorithm (ECDSA)"
    date: "November 16, 2005"
    author:
      - org: "American National Standards Institute"
  FIPS.186-5:
    title: "Digital Signature Standard (DSS)"
    date: February 3, 2023
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
  FIPS.202:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    date: August 2015
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
  FIPS.204:
    title: "Module-Lattice-Based Digital Signature Standard"
    date: August 13, 2024
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
    seriesinfo:
      "FIPS PUB": "204"


informative:
  RFC3092:
  RFC5914:
  RFC7292:
  RFC7296:
  RFC8411:
  RFC8446:
  RFC8551:
  RFC9180:
  RFC9794:
  RFC9881:
  I-D.draft-ietf-pquip-hybrid-signature-spectrums-07:
  TestVectors:
    title: "Test vectors for Composite-ML-DSA"
    target: https://github.com/lamps-wg/draft-composite-sigs/tree/main/src
  Bindel2017:
    title: "Transitioning to a quantum-resistant public key infrastructure"
    target: "https://link.springer.com/chapter/10.1007/978-3-319-59879-6_22"
    author:
      -
        ins: N. Bindel
        name: Nina Bindel
      -
        ins: U. Herath
        name: Udyani Herath
      -
        ins: M. McKague
        name: Matthew McKague
      -
        ins: D. Stebila
        name: Douglas Stebila
    date: 2017
  BSI2021:
    title: "Quantum-safe cryptography - fundamentals, current developments and recommendations"
    target: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Brochure/quantum-safe-cryptography.pdf
    author:
      - org: "Federal Office for Information Security (BSI)"
    date: October 2021
  ANSSI2024:
    title: "Position Paper on Quantum Key Distribution"
    target: https://cyber.gouv.fr/sites/default/files/document/Quantum_Key_Distribution_Position_Paper.pdf
    author:
      - org: "French Cybersecurity Agency (ANSSI)"
      - org: "Federal Office for Information Security (BSI)"
      - org: "Netherlands National Communications Security Agency (NLNCSA)"
      - org: "Swedish National Communications Security Authority, Swedish Armed Forces"
  eIDAS2014:
    title: "Regulation (EU) No 910/2014 of the European Parliament and of the Council of 23 July 2014 on electronic identification and trust services for electronic transactions in the internal market and repealing Directive 1999/93/EC"
    author:
     - org: European Parliament and Council
    target: https://eur-lex.europa.eu/eli/reg/2014/910/oj/eng
  codesigningbrsv3.8:
    title: "Baseline Requirements for the Issuance and Management of Publicly‐Trusted Code Signing Certificates Version 3.8.0"
    author:
     - org: CA/Browser Forum
    target: https://cabforum.org/working-groups/code-signing/documents/

--- abstract

This document defines a small, backwards‑compatible* change to composite ML-DSA that **cryptographically binds the signature to the specific composite public key**. It does so by defining a **Public‑Key Context** value (`pkc`) equal to a hash of the **serialized composite public key**, and by setting the composite context field to that value. Concretely:

```

M' = Prefix || Label || len(pkc) || pkc || PH(M)

```

where `pkc = Hash_ctx(SerializePublicKey(mldsaPK, tradPK))`. This prevents **key reuse** and **cross‑key forgeries** across different composite keys, while preserving the API surface of Composite ML‑DSA and related encodings. The construction introduces two helper procedures to compute `pkc` from either the composite private key or the composite public key.

> *Note: Protocols and encoders remain unchanged; howeve, wire interoperability requires **new algorithm identifiers (OIDs)** for “PKC‑bound” variants.

# Status of this Memo

This Internet-Draft is submitted in full conformance with the provisions of BCP 78 and BCP 79.

--- middle

# Introduction

Composite signature schemes (e.g., Composite ML‑DSA) pre-hash the application message and prepend a **Prefix**, an algorithm‑specific **Label**, and an application‑provided **ctx** byte string to form the message representative `M'`, which is then signed by each component primitive. The current composite signature construction:

```

M' = Prefix || Label || len(ctx) || ctx || PH(M)

```

The `ctx` is an application context of up to 255 bytes.

While the existing design already mitigates several cross‑protocol issues via `Prefix` and `Label`, and explicitly **forbids key reuse**, operational reality suggests some deployments may still reuse component keys or attempt to combine component signatures across keys. This opens the door to **cross‑key “mix‑and‑match” forgeries** (splicing a valid ML‑DSA component from one composite with a valid traditional component from another).

This document proposes a **minimal, mechanical change**: set `ctx` to a **hash of the composite public key**. Because the hash depends on the *exact* public key bytes, both component signatures become bound to the same key material, preventing cross‑key recombination.

## Notational and Terminology Alignment

This document inherits the notation of the Composite ML‑DSA draft (e.g., `Prefix`, `Label`, `PH`, `SerializePublicKey`, etc.) and the conventional **KeyGen/Sign/Verify** API of a signature scheme.

Key words **MUST**, **SHOULD**, etc., are to be interpreted as described in BCP 14 \[RFC2119\] and \[RFC8174\].

# Threat Model and Goals

*Goal*: prevent an adversary from taking valid component signatures produced under **different** composite keys and combining them into a valid composite signature for a target key. The base document notes SUF‑CMA subtleties and “mix and match” where `(M, (mldsaSig1, tradSig2))` could be valid if both were obtained separately.

*Approach*: bind both component signatures to the **same exact composite public key** by including `pkc = H(SerializePublicKey(..))` inside `M'`. Because `pkc` changes with any bit of the key, component signatures extracted from different keys no longer verify together.

> This does **not** change the malleability properties of individual primitives (e.g., ECDSA); therefore SUF‑CMA is still not claimed. It primarily removes **cross‑key** splicing and reduces the impact of accidental key reuse.

# Overview of the Construction

This construction proposes `len(pkc)` as the length of the `len(ctx)` and `pkc` as the `ctx` value; all signature computation remains as specified in the base document.

Let `Hash_ctx` denote the hash function chosen by the algorithm’s OID (e.g., SHA‑256, SHA‑512, SHAKE256/64). The **Public‑Key Context** is:

```

pkc = Hash_ctx( ctx || SerializePublicKey(mldsaPK, tradPK) )

```

The new message representative is:

```

M' := Prefix || Label || len(pkc) || pkc || PH(M)

```

`Prefix` and `Label` are unchanged. `len(pkc)` is encoded as a single unsigned byte, which is sufficient because the mandated hash outputs are ≤ 64 bytes. The `PH(M)` is the pre‑hash of the application message as in the base document.

# Public‑Key Context (PKC) Routines

This draft defines two convenience routines to compute `pkc` from either the composite private key or the composite public key.

## ComputePublicKeyContext from Private Key

```

Composite-ML-DSA<OID>.ComputePublicKeyContext(sk) -> pkc

Inputs:
sk: composite private key (serialized as in Section 4.2 of the base spec)

Implicit inputs (from <OID>):
Hash_ctx: the hash function for PKC (same as the algorithm’s PH unless specified otherwise)

Process:

1.  (mldsaSeed, tradSK) = DeserializePrivateKey(sk)
2.  (_, mldsaSK) = ML-DSA.KeyGen_internal(mldsaSeed)        // base spec, seed-based expansion
3.  mldsaPK = ML-DSA.PublicKey(mldsaSK)                     // or derived during step 2
4.  tradPK  = Trad.PublicKey(tradSK)                        // algorithm-specific derivation
5.  pk = SerializePublicKey(mldsaPK, tradPK)                // base spec Section 4.1
6.  pkc = Hash_ctx(pk)
7.  return pkc

```

> Notes: The seed‑based ML‑DSA private key representation and the ability to re‑derive `mldsaPK` from `mldsaSeed` are already normative in the base specification.

#TODO Add the text on how to computer public from Private (like we did in Composite KEM).

## ComputePublicKeyContext from Public Key

```

Composite-ML-DSA<OID>.ComputePublicKeyContext(pk) -> pkc

Inputs:
pk: composite public key (serialized as in Section 4.1 of the base spec)

Implicit inputs (from <OID>):
Hash_ctx

Process:
1.  pkc = Hash_ctx(pk)
2.  return pkc

```

# Algorithms

Both `Composite-ML-DSA<OID>.Sign(sk, M, ctx)` and `Composite-ML-DSA<OID>.Verify(pk, M, s, ctx)` remain the same.   The only difference is that pkc is passed in as the ctx value.

The signature interface remains the same.

Note:  The application specific `ctx` argument is **ignored** with this current design.  To keep that property, a future version of this specification could set `pkc = HASH (ctx || publickey)`.

# Serialization and ASN.1 Usage

This document **does not** change the composite public/private key or signature **serialization formats** from the base spec—keys and signatures remain concatenations of the component encodings. It also does not change DER wrapping in SPKI/PKCS#8.

Because wire compatibility requires peers to know whether `ctx` is application‑set or PKC‑bound, this document registers **new algorithm identifiers** for each PKC‑bound combination (see IANA).

> Example names (OIDs TBD):
> `id-MLDSA65-ECDSA-P256-SHA512-PKC`, Label: `COMPSIG-MLDSA65-ECDSA-P256-SHA512-PKC`, `PH=SHA512`, `Hash_ctx=SHA512`.

Labels MUST be unique and MUST include a “-PKC” suffix to prevent cross‑label confusion and to strengthen non‑separability when labels appear inside higher‑layer signed objects.

# Security Considerations

**Key Reuse**: The base spec strictly forbids reusing component keys across composite and non‑composite contexts or across composites. Binding `ctx` to `pkc` provides a cryptographic backstop: even if component keys were (improperly) reused, cross‑key splicing will fail because `pkc` differs for each public key instance.

**Non‑separability**: The base construction achieved Weak Non‑Separability (WNS) and a limited form of SNS for ML‑DSA via the `mldsa_ctx=Label`. PKC‑binding additionally prevents forming `(mldsaSig1, tradSig2)` under different keys, because both signatures are now bounded to the same `pkc`. This does **not** fix primitive‑level malleability (e.g., ECDSA) and therefore does not claim SUF‑CMA.  However, for algorithms like EdDSA or Ed448 which are SUF secure, this property should remain. 

**Prefix Guard**: Existing **Prefix** and **Label** remain unchanged; deployments that implemented the optional Prefix guard for traditional verifiers can keep it as is.

**Hash Choices**: `Hash_ctx` MUST be the algorithm’s registered pre‑hash function (e.g., SHA‑256, SHA‑512, SHAKE256/64). This keeps implementation complexity minimal and ensures digest sizes fit within the ctx length field.

**Privacy**: `pkc` reveals nothing beyond what the public key already reveals; it is a hash of public data.

# Implementation Considerations

**Signer Access to pk**: The signer computes `pkc` either by reconstructing `mldsaPK` from the seed (already required in the base spec’s signing flow) and deriving `tradPK` from `tradSK`, or by keeping a cached copy of `pk` alongside `sk`.

**ctx Parameter**: PKC‑bound algorithms **ignore** any externally supplied `ctx`. Libraries SHOULD expose `Sign(sk, M)` and `Verify(pk, M, s)` without a free‑form `ctx` for the PKC variants to avoid misuse.

**Interoperability**: Because `M'` changes, peers MUST advertise the PKC OIDs. Profiles may recommend a small subset, similar to the profiling advice in the base document.

# Use within X.509 and PKIX

SPKI and OneAsymmetricKey wrapping are unchanged. Only the **AlgorithmIdentifier** (OID/Label) differs. Verification builds `pkc` from the BIT STRING `subjectPublicKey` to reconstruct `M'`. The same rules for `keyUsage` apply.

# IANA Considerations

Allocate new OIDs under `1.3.6.1.5.5.7.6` for PKC‑bound variants of the composites registered in the base document. Each registration lists: OID, Label (with `-PKC` suffix), `PH`, ML‑DSA variant, traditional primitive and parameters. The ASN.1 module follows the base style with `sa-CompositeSignature`/`pk-CompositeSignature`, “no ASN.1 wrapping” for value fields, and `PARAMS ARE absent`.

# References

TBD

# Acknowledgments

Thanks to the Composite ML‑DSA authors and LAMPS WG for the existing combiner design and analyses of pre‑hashing, non‑separability, and key‑reuse risks which this document builds upon.

--- back
