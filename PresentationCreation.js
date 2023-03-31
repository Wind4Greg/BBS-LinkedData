/*
    Figuring out steps for BBS proof/verifiable presentation creation.
    Note: Not currently doing blank node processing stuff.
    **TODO**: Update for BBS header change...
*/
/*global console, TextEncoder, URL*/
import {
  hexToBytes, messages_to_scalars, prepareGenerators, proofGen,
  publicFromPrivate
} from '@grottonetworking/bbs-signatures';
import {readFile, writeFile} from 'fs/promises';
import {base58btc} from 'multiformats/bases/base58';
import jsonld from 'jsonld';
import {localLoader} from './documentLoader.js';

jsonld.documentLoader = localLoader; // Local loader for JSON-LD
const te = new TextEncoder(); // For UTF-8 to byte conversion

// Read input document from a file or just specify it right here.
const document = JSON.parse(
  await readFile(
    new URL('./output/signedDocBBS.json', import.meta.url)
  )
);

// Separate document from proof
const proof = document.proof;
const unsigned = Object.assign({}, document);
delete unsigned.proof;

// Canonize the unsigned document
const canonDoc = await jsonld.canonize(unsigned);
// console.log("Canonized unsigned document:")
// console.log(cannonDoc);
writeFile('./output/canonDocBBS.txt', canonDoc);

// Let's determine selective disclosure indices via the frame method
// These would be specified by holder.
const selectiveFrame = {
  '@context': document['@context'],
  '@type': 'VerifiableCredential', // Seems required, don't know why
  '@explicit': true,
  name: {}, // They want to reveal the credential name
  credentialSubject: { // This seems to work to get at something inside...
    '@explicit': true,
    email: {} // They will reveal email
  }
};

// Selecting stuff via frame
const framed = await jsonld.frame(document, selectiveFrame);
console.log('Framed document:');
console.log(framed, '\n');

// Canonize framed and original document
const canonFramed = await jsonld.canonize(framed);
console.log('Canonical Framed:');
console.log(canonFramed, '\n');
writeFile('./output/canonFramedBBS.txt', canonFramed);
console.log('Canonical Document:');
console.log(canonDoc, '\n');

// Put quads into arrays
const docQArray = canonDoc.split('\n');
docQArray.pop(); // Get rid of empty element at end
const frameQArray = canonFramed.split('\n');
frameQArray.pop(); // Get rid of empty element at end

// Figure out the selective disclosure indices
const selDisclose = [];
docQArray.forEach(function(quad, i) {
  if(frameQArray.includes(quad)) {
    selDisclose.push(i);
  }
});
console.log(`selective disclosure indices: ${selDisclose}`);
console.log(`required reveal indices: ${proof.requiredRevealStatements}`);

const s = new Set(selDisclose);
proof.requiredRevealStatements.forEach(ind => s.add(ind));
const discloseIndices = [...s];
discloseIndices.sort((a, b) => a - b);
console.log(`disclosed indices: ${discloseIndices}`);

// Recreate VC based on selective disclosure choices
const selDocQuads = docQArray.filter((m, i) => discloseIndices.includes(i));
const selDocTxt = selDocQuads.join('\n');
const selDoc = await jsonld.fromRDF(selDocTxt,
  {format: 'application/n-quads'});
const selDocCompact = await jsonld.compact(selDoc, document['@context']);
console.log(JSON.stringify(selDocCompact, null, 2));

// Assemble proof options from original signature to recreate the BBS header
const proofOptions = Object.assign({}, proof);
delete proofOptions.proofValue;

// canonize proof options and convert to bytes
proofOptions['@context'] = document['@context'];
const canonProof = await jsonld.canonize(proofOptions);
const canonProofBytes = te.encode(canonProof);
const header = canonProofBytes;

// convert document quads to bytes and map to scalars
const docQByteArray = docQArray.map(q => te.encode(q));
const messageScalars = await messages_to_scalars(docQByteArray);

// Need to create proof options for the presentation

const presentProofOptions = {
  '@context': document['@context'], // just for canonicalization
  type: 'DataIntegrityProof',
  cryptosuite: 'bbs-2023',
  created: '2023-03-29T19:23:24Z',
  verificationMethod: 'https://di.example/issuer#zUC7Fk29SRjBb5D4T8KbvsG562YHrVChFoZDw9mjfze4fmSUoMv6pop4kk9DRbjXXyCqmoprwikuEeRLt5ybxk2m88hAYJQLHU7o7S9LB7Y4Q8Lvu84v4YB4PXcGCCei1Qex2XF',
  proofPurpose: 'assertionMethod',
};

// canonize proof options and convert to bytes

const canonPresentProof = await jsonld.canonize(presentProofOptions);
writeFile('./output/canonPresentProof.txt', canonProof);
const canonPresentProofBytes = te.encode(canonPresentProof);
const ph = canonPresentProofBytes;

// Get ready create proof, just need the public key
const privateKey = hexToBytes('4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7');
const publicKey = publicFromPrivate(privateKey);
const gens = await prepareGenerators(messageScalars.length);
const signature = base58btc.decode(proof.proofValue);
// // Signing
// const header = canonProofBytes;
// const signature = await sign(privateKey, publicKey, header, messageScalars,
//   gens);

const presentProofValue = await proofGen(publicKey, signature, header, ph,
  messageScalars, discloseIndices, gens);

// Assemble VP proof
const presentProof = Object.assign({}, presentProofOptions,
  {proofValue: base58btc.encode(presentProofValue)});
delete presentProof['@context'];
console.log(JSON.stringify(presentProof, null, 2));

// Create Verifiable Presentation
delete selDocCompact['@context'];
const vp = {
  '@context': document['@context'],
  type: 'VerifiablePresentation',
  verifiableCredential: selDocCompact,
  proof: presentProof
};

const presentationText = JSON.stringify(vp, null, 2);
console.log(presentationText);
writeFile('./output/presentation.json', presentationText);

