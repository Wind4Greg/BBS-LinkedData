
# BBS for Verifiable Credentials

In this repository we develop code to demonstrate the key steps in applying the BBS signature suite to verifiable credentials. We fill in the gaps in the specification with the most reasonable or straight forward approach and provide justification here.

**Issue**: Since BBS is built with 3 party model should we associate "BBS signature" with the original issuing of the *verifiable credential* and "BBS proofs" (which are derived from the signature) with a *verifiable presentation*? Otherwise we need a way to indicate in the *cryptosuite* whether we are dealing with a *BBS signature* or *BBS proof*. Another way of handling this is some type of multiformat for the `proofValue` field. For now we are assuming "BBS signature" with a signed credential and a "BBS proof" with a verifiable presentation.

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

Hmm in all previous cases the VC *proof config/options* has been hashed separate from the other VC content then the combined hash has been signed. Also what is the relationship between the VC and the VP proofs? In the VC Data Model V2 they have a section on [ZKPs](https://www.w3.org/TR/vc-data-model-2.0/#zero-knowledge-proofs) and show including some of the original proof with the VC in the presentation. Hence it seems like we should break up the *proof config/options* into separate quads too.

**Issue**: Need to make it easy for issuer to specify the `requiredRevealStatements`. Can we use the "Framing" procedure, see [FrameCheck.js](FrameCheck.js) to get the indices the issuer wants to require to be revealed? Trying this... Should more constraints be put on this field? Sorted, no out of bound indices?

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

These options need to be canonized and protected by the signature.

Note that in Mattr's implementation they [concatenate the lists of statements from the proof options with the document statements](https://github.com/mattrglobal/jsonld-signatures-bbs/blob/cd936ea71a871633ddead4f91a0e2de1c0ed82cc/src/BbsBlsSignature2020.ts#L262-L276) and use that as the *messages* to BBS.

### Revised Signing Algorithm

Features: no "double" hashing of messages;

1. Unsigned document ==> canonize to quads ==> separate to list ==> UTF-8 encode to bytes ==> array of document byte messages. These will be the messages given to BBS and processed by [map message to scalar as hash](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-4.3.1).
2. Proof options ==> canonize ==> separate to list ==> UTF-8 encode to bytes ==> array of option byte messages. **Note**: proof options cannot contain `proofValue` or `requiredRevealStatements` since they haven't been computed yet. We could protect the `requireRevealStatements` via the BBS `header`. Currently calculating but not protecting yet.
3. Concatenate option list with document list to get the list of BBS messages
4. Furnish sufficient info to *issuer* to enable them to set the `requiredRevealStatements`. Tried using a JSON-LD framing procedure for this. Do this across both document and options.
5. Run BBS's "message to scalar" function on the byte messages from step 3.
6. BBS preliminaries: make sure there are enough generators for the number of "messages".
7. BBS sign

## Verification Algorithm

This was rather straight forward based on the above signing:

1. Separate signed VC document into unsigned document and proof.
2. Canonize unsigned document and convert into array of quads.
3. Derive "proof options" from proof, e.g.,  make a copy and remove the `proofValue` and `requireRevealStatements` fields. Add in context from unsigned document, canonize, and convert into an array of quads., process this like in the signing algorithm to recreate the BBS `header` input.
4. Concatenate quads arrays from proof options and unsigned document.
5. Recover the public key and run BBS verify against `proofValue` (convert to bytes from base58btc)

## BBS Derived Proofs and Verifiable Presentations

BBS has the concept of "proofs" that are derived from the original list of messages and associated BBS signature. The recipient of the original list of message can choose to selectively disclose a subset of the messages and produce a "proof" that will verify against the original issuers public key (as long as the disclosed messages haven't been modified). The value of the *proof* can be made unlinkable to any other "proof value" that the recipient may generate.

Such usage seems to call for the concept of a [verifiable presentation](https://www.w3.org/TR/vc-data-model-2.0/#presentations) (VP) and we will use a VP to hold our "BBS proofs". The [presentation data model](https://www.w3.org/TR/vc-data-model-2.0/#presentations-0). Note that in this model the VP contains the VC and that the contained VC may have `proof` information. We will apply "selective disclosure" and "required reveal" to both the VC and its included proof.

### Suggested Procedure

**Input**: VC signed with BBS signature per the signing algorithm (above).
**Output**: A VP "signed" via a "BBS proof". The VP contains a VC and containing `proof` that have been subject to "required reveal" constraints from the specification and from the issuer, and subject to "selective disclosure" constraints from the *holder*.

1. Decompose the original signed VC into *unsigned* document (VC without proof) and *VCOptions* (just the proof) pieces
2. Canonize and convert the unsigned document to an array of quads
3. Extract the `proofValue`(BBS signature) and `requiredRevealStatements`(indexes for quads that must be revealed) from the *VCOptions* portion.
4. Remove the `proofValue` and `requiredRevealStatements` from the *VCOptions*. Canonize and convert to an array of quads.
5. Concatenate quad arrays for *VCOptions* and *unsigned* in that order. Call this *allQuads*
6. Run a JSON-LD framing based procedure to determine quads to be selectively disclosed for the *unsigned* document.
7. Run a JSON-LD framing based procedure to determine quads to be selectively disclosed for the *VCOptions*.
8. Obtain the indexes of the quads in the *allQuads* array for the selective disclosure quads in the previous two steps. These are the *selectiveDisclosure* indexes. Take a set union of these indexes with the `requiredRevealStatements` (these are indexes too). Save these to the `disclosedIndexes`.
9. Create an "proof options" for the VP. *vpOptions*. Add the `disclosedIndexes` to it. Canonize, and convert to bytes base on UTF-8 encoding. This will be the *ph* (presentation header).
10. Compute the BBS proof = ProofGen(PK, signature, header, ph, messages, disclosed_indexes). Use base58btc encoding and add this information to the *vpOptions* `proofValue` field.
11. Created a new VC based on relevant quads according to `disclosedIndexes` and the *allQuads*; Create a new "proof" field for this VC based on the corresponding `disclosedIndexes` and *allQuads*. 
12. Assemble the VP from the new VC and *vpOptions* field.

### Existing CCG draft algorithm

From [Derive proof algorithm](https://w3c-ccg.github.io/vc-di-bbs/#derive-proof-algorithm):

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