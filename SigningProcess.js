/*
    Figuring out steps for BBS signature preprocessing.
    Note: Not currently doing blank node processing stuff.
*/
/*global console, TextEncoder, URL*/
import {hexToBytes, messages_to_scalars, prepareGenerators, publicFromPrivate,
  sign} from '@grottonetworking/bbs-signatures';
import {readFile, writeFile} from 'fs/promises';
import {base58btc} from 'multiformats/bases/base58';
import jsonld from 'jsonld';
import {localLoader} from './documentLoader.js';

jsonld.documentLoader = localLoader; // Local loader for JSON-LD
const te = new TextEncoder(); // For UTF-8 to byte conversion

// Read input document from a file or just specify it right here.
const document = JSON.parse(
  await readFile(
    new URL('./input/unsigned.json', import.meta.url)
    // new URL('./input/unsignedNoIds.json', import.meta.url)
  )
);

// Canonize the unsigned document
const canonDoc = await jsonld.canonize(document);
// console.log("Canonized unsigned document:")
// console.log(cannonDoc);
writeFile('./output/canonDocBBS.txt', canonDoc);

// Let's determine required disclosure indices via frame method
// These would be specified by issuer.
// This produces two extra pieces of information in my tests
// type info and the id of the credentialSubject.
const reqDiscloseFrame = {
  '@context': document['@context'],
  '@type': 'VerifiableCredential', // Seems required, don't know why
  '@explicit': true,
  issuer: {}, // Must disclose
  validFrom: {}, // Must disclose
  credentialSubject: { // This seems to work to get at something inside...
    '@explicit': true,
    jobTitle: {} // Must disclose
  }
};

// Selecting stuff via frame
const framed = await jsonld.frame(document, reqDiscloseFrame);
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

// Figure out the required disclosure indices as needed for VC proof config
const reqDisclose = [];
docQArray.forEach(function(quad, i) {
  if(frameQArray.includes(quad)) {
    reqDisclose.push(i);
  }
});
console.log(`required disclosure indices: ${reqDisclose}`);

// Assemble proof options
const proofOptions = {
  '@context': document['@context'], // just for canonicalization
  type: 'DataIntegrityProof',
  cryptosuite: 'bbs-2023',
  created: '2020-11-05T19:23:24Z',
  verificationMethod: 'https://di.example/issuer#zUC7Fk29SRjBb5D4T8KbvsG562YHrVChFoZDw9mjfze4fmSUoMv6pop4kk9DRbjXXyCqmoprwikuEeRLt5ybxk2m88hAYJQLHU7o7S9LB7Y4Q8Lvu84v4YB4PXcGCCei1Qex2XF',
  proofPurpose: 'assertionMethod',
  requiredRevealStatements: reqDisclose,
};

// canonize proof options and convert to bytes

const canonProof = await jsonld.canonize(proofOptions);
writeFile('./output/canonProof.txt', canonProof);
const canonProofBytes = te.encode(canonProof);

// convert document quads to bytes and map to scalars
const docQByteArray = docQArray.map(q => te.encode(q));
const messageScalars = await messages_to_scalars(docQByteArray);

// Get ready to sign
let privateKey = hexToBytes("4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7");
const publicKey = publicFromPrivate(privateKey);
const gens = await prepareGenerators(messageScalars.length);

// Signing
const header = canonProofBytes;
const signature = await sign(privateKey, publicKey, header, messageScalars,
  gens);

// Assemble VC proof
const proof = Object.assign({}, proofOptions, 
  {proofValue: base58btc.encode(signature)});
delete proof['@context'];

// Add proof to document
document.proof = proof;
const signedDocText = JSON.stringify(document, null, 2);
console.log(signedDocText);
writeFile('./output/signedDocBBS.json', signedDocText);
