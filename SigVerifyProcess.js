/*
    Figuring out steps for BBS signature verification processing.
    Run this after running SigningProcess.js
    Note: Not currently doing blank node processing stuff.

*/
/*global console, TextEncoder, URL*/
import {messages_to_scalars, prepareGenerators, verify}
  from '@grottonetworking/bbs-signatures';
import {base58btc} from 'multiformats/bases/base58';
import jsonld from 'jsonld';
import {localLoader} from './documentLoader.js';
import {readFile} from 'fs/promises';

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

// Put quads into arrays
const docQArray = canonDoc.split('\n').filter(item => item.length > 0);

// Assemble proof options
const proofOptions = Object.assign({}, proof);
delete proofOptions.proofValue;
const requiredRevealStatements = proofOptions.requiredRevealStatements;
delete proofOptions.requiredRevealStatements;

// canonize proof options and convert to bytes
proofOptions['@context'] = document['@context'];
const canonOptions = await jsonld.canonize(proofOptions);
const proofQArray = canonOptions.split('\n').filter(item => item.length > 0);
const allQArray = proofQArray.concat(docQArray);

// convert document quads to bytes and map to scalars
const allQByteArray = allQArray.map(q => te.encode(q));
const messageScalars = await messages_to_scalars(allQByteArray);

// Recreate header from required reveal statement information
const headerDoc = { // This would be standardized...
  '@context': [{requiredRevealStatements:
    'https://grotto-networking.com/bbsld/reqreveal'}],
  '@id': 'urn:uuid:d5a758aa-c83f-495d-b8f5-be9b308429d5',
  requiredRevealStatements
};
const headerCanon = await jsonld.canonize(headerDoc);
const header = te.encode(headerCanon);

// Get ready to verify, Get the public key bytes
const pubKeyEncoded = proof.verificationMethod.split('#')[1];
let publicKey = base58btc.decode(pubKeyEncoded);
publicKey = publicKey.slice(2);
const gens = await prepareGenerators(messageScalars.length);

// Verify
const signature = base58btc.decode(proof.proofValue);
const verified = await verify(publicKey, signature, header, messageScalars,
  gens);
console.log(`VC signature verified: ${verified}`);
