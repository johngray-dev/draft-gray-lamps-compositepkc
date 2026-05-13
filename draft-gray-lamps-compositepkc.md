---
title: "Preventing Key Reuse and Cross‑Key Forgeries in Composite ML-DSA"
abbrev: "Composite-PKC-Context"
category: info

docname: draft-gray-lamps-compositepkc-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Limited Additional Mechanisms for PKIX and SMIME"
keyword:
 - composite signatures
 - public key binding

author:
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


normative:
  I-D.draft-ietf-lamps-pq-composite-sigs:
  I-D.draft-ietf-lamps-pq-composite-kem:
  FIPS.204:
    title: "Module-Lattice-Based Digital Signature Standard"
    date: August 13, 2024
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
    seriesinfo:
      "FIPS PUB": "204"

informative:
   I-D.draft-ietf-pquip-hybrid-signature-spectrums-07:
...

--- abstract

This document defines a small, backwards‑compatible change to composite ML-DSA that **cryptographically binds the signature to the specific composite public key**. It does so by defining a **Public‑Key Context** value (`pkc`) equal to a hash of the **serialized composite public key**, and by setting the composite context field to that value. This prevents **key reuse** and **cross‑key forgeries** across different composite keys, while preserving the API of Composite ML‑DSA. The construction introduces two helper procedures to compute `pkc` from either the composite private key or the composite public key.

--- middle

# Introduction

Composite signature schemes (e.g., Composite ML‑DSA) pre-hash the application message and prepend a **Prefix**, an algorithm‑specific **Label**, and an application‑provided **ctx** byte string to form the message representative `M'`, which is then signed by each component primitive. The current composite signature construction:

~~~
M' :=  Prefix || Label || len(ctx) || ctx || PH( M )
~~~

The `ctx` is an application context of up to 255 bytes.

While the existing design already mitigates several cross‑protocol issues via `Prefix` and `Label`, and explicitly **forbids key reuse**, operational reality suggests some deployments may still reuse component keys or attempt to combine component signatures across keys. This opens the door to **cross‑key “mix‑and‑match” forgeries** (splicing a valid ML‑DSA component from one composite with a valid traditional component from another).

This document proposes a **minimal change**: set `ctx` to a **hash of the composite public key**. Because the hash depends on the *exact* public key bytes, both component signatures become bound to the same key material, preventing cross‑key recombination.


# Conventions and Definitions

This document inherits the notation of the Composite ML‑DSA draft (e.g., `Prefix`, `Label`, `PH`, `SerializePublicKey`, etc.) and the conventional **KeyGen/Sign/Verify** API of a signature scheme.

{::boilerplate bcp14-tagged}

# Threat Model and Goals

*Goal*: prevent an adversary from taking valid component signatures produced under **different** composite keys and combining them into a valid composite signature for a target key. The base document notes SUF‑CMA subtleties and “mix and match” where `(M, (mldsaSig1, tradSig2))` could be valid if both were obtained separately.

*Approach*: bind both component signatures to the **same exact composite public key** by including `pkc = H(SerializePublicKey(..))` inside `M'`. Because `pkc` changes with any bit of the key, component signatures extracted from different keys no longer verify together.

> This does **not** change the malleability properties of individual primitives (e.g., ECDSA); therefore SUF‑CMA is still not claimed. It primarily removes **cross‑key** splicing and reduces the impact of accidental key reuse.

# Overview of the Construction

This construction proposes `len(pkc)` as the length of the `len(ctx)` and `pkc` as the `ctx` value; all signature computation remains as specified in the base document.

Let `Hash_ctx` denote the hash function chosen by the algorithm’s OID (e.g., SHA‑256, SHA‑512, SHAKE256/64). The **Public‑Key Context** is:

~~~
pkc = Hash_ctx( SerializePublicKey(mldsaPK, tradPK) )
~~~

The new message representative is:

~~~
M' := Prefix || Label || len(pkc) || pkc || PH(M)
~~~

`Prefix` and `Label` are unchanged. `len(pkc)` is encoded as a single unsigned byte, which is sufficient because the mandated hash outputs are ≤ 64 bytes. The `PH(M)` is the pre‑hash of the application message as in the base document.

# Public‑Key Context (PKC) Routines

This draft defines two convenience routines to compute `pkc` from either the composite private key or the composite public key.

## ComputePublicKeyContext from Private Key

~~~
Composite-ML-DSA<OID>.ComputePublicKeyContext(sk) -> pkc

Inputs:
sk: composite private key

Implicit inputs (from <OID>):
Hash_ctx: the hash function for PKC (same as the algorithm’s PH unless specified otherwise)

Process:

1.  (mldsaSeed, tradSK) = DeserializePrivateKey(sk)
2.  (mldsaPK, mldsaSK) = ML-DSA.KeyGen_internal(mldsaSeed)     // FIPS 204, seed-based expansion
4.  tradPK  = Trad.PublicKey(tradSK)                        // derive public key from private key
5.  pk = SerializePublicKey(mldsaPK, tradPK)
6.  pkc = Hash_ctx(pk)
7.  return pkc
~~~

> Notes: The seed‑based ML‑DSA private key representation and the ability to re‑derive `mldsaPK` from `mldsaSeed` are already normative in {{I-D.ietf-lamps-pq-composite-sigs}}

During the signing operation, access to the public key is required.  The above method suggests generating the composite public key from the composite private key by Deserializing the private key into its component keys, deriving the public component key for ML-DSA and the public component key for the traditional component, and then using the SerializePublicKey() method as defined in section 4.1 {{I-D.ietf-lamps-pq-composite-sigs}}.  This is only one of several options, but is a non-normative, non-exhautive list.

1. Derive or extract from private key as suggested above. Many cryptographic modules expose functionality to obtain an RSA or EC public key from the corresponding private key. For applications where such functionality does not exist, see section 10.4.1 and 10.4.2 in {{I-D.ietf-lamps-pq-composite-kem}} for mechanisms for extracting the public keys from private keys for RSA and ECDSA respectively. It is assumed that this is not required for Ed25519 or Ed448 since those private keys are seeds from which the public key can be obtained.

2. Fetch it from an external data source, for example from the public-key certificate corresponding to this private key.

3. If the composite signature private key is being carried within a PKCS#8 OneAsymmetricKey object, place the full composite public key within the optional OneAsymmetricKey.publicKey field (and re-encode as necessary for correctly using it in the context).

4. Use an alternate private key encoding that explicitly carries the composite public key.


## ComputePublicKeyContext from Public Key

~~~
Composite-ML-DSA<OID>.ComputePublicKeyContext(pk) -> pkc

Inputs:
pk: composite public key

Implicit inputs (from <OID>):
Hash_ctx

Process:
1.  pkc = Hash_ctx(pk)
2.  return pkc
~~~

# Algorithms

Both `Composite-ML-DSA<OID>.Sign(sk, M, ctx)` and `Composite-ML-DSA<OID>.Verify(pk, M, s, ctx)` remain the same.   The only difference is that pkc is passed in as the ctx value.

The signature interface remains the same.

Note:  The application specific `ctx` argument is **ignored** with this current design.  To keep that property, a future version of this specification could set `pkc = HASH (ctx || publickey)`.

# Serialization and ASN.1 Usage

This document **does not** change the composite public/private key or signature **serialization formats** from {{I-D.ietf-lamps-pq-composite-sigs}} and signatures remain concatenations of the component encodings. It also does not change DER wrapping in SPKI/PKCS#8.

Because wire compatibility requires peers to know whether `ctx` is application‑set or PKC‑bound, this document could haved registered **new algorithm identifiers** for each PKC‑bound combination.  However, that is not within the scope of this document.  This is meant for specific application context use-cases where the preventing key reuse is a desired security property.  For example, applications which choose to profile a set of composite signatures could choose to also adopt the use of this context.

# Security Considerations

**Key Reuse**: {{I-D.ietf-lamps-pq-composite-sigs}} strictly forbids reusing component keys across composite and non‑composite contexts. Binding `ctx` to `pkc` provides a cryptographic backstop: even if component keys were (improperly) reused, cross‑key splicing will fail because `pkc` differs for each public key instance.

**Non‑separability**: {{I-D.ietf-lamps-pq-composite-sigs}} achieved Weak Non‑Separability (WNS) and a limited form of SNS for ML‑DSA via the `mldsa_ctx=Label`. PKC‑binding additionally prevents forming `(mldsaSig1, tradSig2)` under different keys, because both signatures are now bounded to the same `pkc`. This does **not** fix primitive‑level malleability (e.g., ECDSA) and therefore does not claim SUF‑CMA.  However, for algorithms like EdDSA or Ed448 which are SUF secure, this property should remain.

**Prefix**: Existing **Prefix** and **Label** remain unchanged; deployments that implemented the optional Prefix in traditional verifiers can keep it as is.

**Hash Choices**: `Hash_ctx` MUST be the algorithm’s registered pre‑hash function (e.g., SHA‑256, SHA‑512, SHAKE256/64). This keeps implementation complexity minimal and ensures digest sizes fit within the ctx length field.

**Privacy**: `pkc` reveals nothing beyond what the public key already reveals; it is a hash of public data.


# Implementation Considerations

**Signer Access to pk**: The signer computes `pkc` either by deriving `compositePK` from `compositeSK`, or by keeping a cached copy of `compositepk` alongside `compositesk`.

**Interoperability**: Because `M'` changes when this context type is used, peers MUST know that this context will be used.  One way to achieve this is for application specific use cases to specify use of this context type as part of the usage.


# IANA Considerations

None

--- back

# Acknowledgments

Thanks to the Composite ML‑DSA authors and LAMPS WG for the existing design and analyses of pre‑hashing, non‑separability, and key‑reuse risks which this document builds upon.  Thanks to Lucas Prabel for his feedback on this document.
