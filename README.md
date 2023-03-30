
# BBS for Verifiable Credentials

In this repository we develop code to demonstrate the key steps in applying the BBS signature suite to verifiable credentials. We fill in the gaps in the specification with the most reasonable or straight forward approach and provide justification here.

## References

* [W3C: BBS+ Signatures 2020 Draft Community Group Report](https://w3c-ccg.github.io/vc-di-bbs/)
* [GitHub: BBS+ Signature Linked Data Proofs](https://github.com/w3c-ccg/ldp-bbs2020/)
* [DIF: BBS Signature Draft](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#)
* [GitHub DIF BBS](https://github.com/decentralized-identity/bbs-signature) Uses markdown and tooling to produce draft. Has test fixtures/vectors.
* [The BBS Signature Scheme (IRTF draft)](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-02.html)

## Multikey Verification Method

The CCG spec is out of date the [BBS draft only uses a public key in the G2 group](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-subgroup-selection). In the [multiformats table](https://ipfs.io/ipfs/QmXec1jjwzxWJoNbxQF5KffL8q6hFXm9QwUGaa3wKGk6dT/#title=Multicodecs&src=https://raw.githubusercontent.com/multiformats/multicodec/master/table.csv)

```text
name                    tag     code    status       description
bls12_381-g2-pub	    key     0xeb	draft	     BLS12-381 public key in the G2 field
```

Note that the [did:key draft](https://w3c-ccg.github.io/did-method-key/#format) uses Base58-btc. So we will too. The [did:key BLS12381](https://w3c-ccg.github.io/did-method-key/#bls-12381) appears to be for the G2 public key since they get the same prefix that I do in [BBSMultiKey.js](BBSMultiKey.js).

## VC Data Integrity Proof Options/Configuration

Within a VC we can have a `proof` field. Note that this can be either a *BBS signature* or *BBS proof*. We have a **collision** of terminology (VC data integrity and BBS) and one must be careful! Below we show
the possible contents of this field for the BBS case. The following is based on the VC Data Integrity model rather than coming up with a new `type` as done in the old CCG draft. An important addition in the BBS case is the `requiredRevealStatements` field.

```javascript
{
    // Not showing the VC data for brevity
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "bbs-2023", // Issue need to differentiate BBS sig from BBS proof?
    "created": "2020-11-05T19:23:24Z",
    "verificationMethod": "https://di.example/issuer#zUC7Fk29SRjBb5D4T8KbvsG562YHrVChFoZDw9mjfze4fmSUoMv6pop4kk9DRbjXXyCqmoprwikuEeRLt5ybxk2m88hAYJQLHU7o7S9LB7Y4Q8Lvu84v4YB4PXcGCCei1Qex2XF",
    "proofPurpose": "assertionMethod",
    "requiredRevealStatements": [ 4, 5 ], // Optional but important for BBS
    "proofValue": "zQeVbY4oey5q2M3XKaxup3tmzN4DRFTLVqpLMweBrSxMY2xHX5XTYV8nQApmEcqaqA3Q1gVHMrXFkXJeV6doDwLWx"
    }
}
```

Concerning the CCG draft says:

> A linked data document featuring a BBS+ Signature data integrity proof MUST contain a `requiredRevealStatements` attribute with a value that is an array of un-signed integers representing the indices of the statements in the canonical form that MUST always be revealed in a derived proof.

Note that they also say:

> The indices corresponding to the statements for the verificationMethod and proofPurpose as apart of the data integrity proof MUST always be present.

However this doesn't make sense since in all previous cases the VC *proof config/options* has been kept separate from the content as is *required*. Part of the problem is the current CCG draft does not address this. However the IETF BBS signature draft has a very good mechanism for dealing with "associated data" via its `header` parameter.

**Issue**: Need to make it easy for issuer to specify the `requiredRevealStatements`. We can use the "Framing" procedure, see [FrameCheck.js](FrameCheck.js) to get the indices the issuer wants to require to be revealed.

## Signing Algorithm

### Messages

The CCG draft proposes a reasonable way to handle the what the BBS algorithm would call *messages*. However, this does result in "double hashing" since the first thing BBS does with messages is "hash them to scalars" using built in hash algorithm (two variants SHA-256 or SHAKE-256).

From section 4.1.1:

 The algorithm defined below, outlines the process of obtaining the data in the form required for both signing and verifying.

1. Canonicalize the input document using the canonicalization algorithm to a set of statements represented as n-quads.
2. Initialize an empty array of length equal to the number of statements, let this be known as the statement digests array.
3. For each statement in order:
    1. Apply the statement digest algorithm to obtain a statement digest
    2. Insert the statement digest into the statement digests array which MUST maintain same order as the order of the statements returned from the canonicalization algorithm.
4. Returned the statement digests array.

**Note** the statement digest algorithm in the CCG draft is *Blake2b*. See [Wikipedia: BLAKE](https://en.wikipedia.org/wiki/BLAKE_(hash_function)), [BLAKE2](https://www.blake2.net), [RFC7693](https://www.rfc-editor.org/rfc/rfc7693). Can use [@noble/hashes](https://www.npmjs.com/package/@noble/hashes) for implementation. However see note on "double hashing".

### Canonicalization Issues

BBS signatures work on a ordered list of *messages*. Raw VCs containing assertions are not structured in this way. Some canonicalization methods can produce an ordered list of statements that can be used as BBS *messages*, e.g., [RDF Dataset Canonicalization](https://www.w3.org/TR/rdf-canon/), others do not, e.g., [RFC8785: JCS](https://www.rfc-editor.org/rfc/rfc8785). We will start with RDF based canonicalization.

Issues with canonicalization:

1. Stability of "blank node" ids. This seems only to be an issue with BBS proof creation. See [Matter blank node handling](https://github.com/mattrglobal/jsonld-signatures-bbs/blob/cd936ea71a871633ddead4f91a0e2de1c0ed82cc/src/BbsBlsSignatureProof2020.ts#L127-L158)

### VC Proof Options

VC Data Integrity says: "Let *hashData* be the result of hashing the *transformedData* according to a hashing algorithm associated with the cryptographic suite and the *options* parameters provided as inputs to the algorithm." By options they mean the "proof options". This needs refinement for particular cases.

In the VC approaches for EdDSA they have a procedure to create [proof configuration](https://w3c.github.io/vc-di-eddsa/#proof-configuration-eddsa-2022), which basically includes everything that would go into the VC `proof` field except the `proofValue` field. This information needs to be protected from modification and becomes an input to the signature algorithm (hence why proofValue can't be in it!).

These options need to be canonized and protected by the signature. I recommend supplying the canonized information into the BBS `header` parameter. Note that this parameter gets hashed so there is no need for additional hashing (however there may be reasons to hash for consistency with the message processing).

Note that in Mattr's implementation they [concatenate the lists of statements from the proof options with the document statements](https://github.com/mattrglobal/jsonld-signatures-bbs/blob/cd936ea71a871633ddead4f91a0e2de1c0ed82cc/src/BbsBlsSignature2020.ts#L262-L276) and use that as the *messages* to BBS. This uses Mattr's older [BBS implementation](https://github.com/mattrglobal/node-bbs-signatures) that doesn't match the IETF BBS draft, i.e., no `header` field. It also has an open issue on "required revealed".

### Revised Signing Algorithm

1. Unsigned document ==> canonize to quads ==> separate to messages ==> UTF-8 encode to bytes ==> array of octet messages. These will be the messages given to BBS and processed by [map message to scalar as hash](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-4.3.1).
2. Furnish sufficient info to *issuer* to enable them to set
3. Proof options ==> canonize

## Derived Proof Algorithm

From [Section 8](https://w3c-ccg.github.io/ldp-bbs2020/#derive-proof-algorithm):

Definitions (my emphasis):

* *input proof document*: A data integrity proof document featuring a data integrity proof that supports proof derivation.
* *reveal document*: A JSON-LD document in the form of a **frame** which describes the desired transform to apply to the input proof document using the framing algorithm defined in [JSON-LD-FRAMING]. 
* *revealed document*: A data integrity proof document which is the product of the derive proof algorithm. 


1. Apply the canonicalization algorithm to the *input proof document* to obtain a set of statements represented as n-quads. Let this set be known as the input proof document statements.
2. Record the total number of statements in the input proof document statements. Let this be known as the total statements.
3. Apply the framing algorithm to the input proof document. Let the product of the framing algorithm be known as the *revealed document*.
4. Canonicalize the *revealed document* using the canonicalization algorithm to obtain the set of statements represented as n-quads. Let these be known as the revealed statements.
5. Initialize an empty array of length equal to the number of revealed statements. Let this be known as the revealed indices array.
6. For each statement in order:
    1. Find the numerical index the statement occupies in the set input proof document statements.
    2. Insert this numerical index into the revealed indicies array
7. Returned the revealed indices array, total statements and input proof document statements.


# JSON-LD and Selective Disclosure and Linkability

The original document (set of messages) from the issue and the transformation prior to signing can have big impacts on privacy in terms of data leakage and linkability. BBS proofs offer *unlinkability* however a major selling point of JSON-LD is *linkability*. For example basic concepts in JSON-LD include [node identifiers](https://www.w3.org/TR/json-ld/#node-identifiers) which are in turn based on [IRI](https://www.w3.org/TR/json-ld/#iris).

This also leads to the notion of *blank nodes*:

> A node in a graph that is neither an IRI, nor a literal. A blank node does not contain a de-referenceable identifier because it is either ephemeral in nature or does not contain information that needs to be linked to from outside of the linked data graph. In JSON-LD, a blank node is assigned an identifier starting with the prefix _:.