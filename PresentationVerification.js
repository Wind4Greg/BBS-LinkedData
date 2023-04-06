/*
    Figuring out steps for the verification of BBS verifiable presentation.
*/
/*global console, TextEncoder, URL*/
import {messages_to_scalars, numUndisclosed, prepareGenerators, proofVerify}
  from '@grottonetworking/bbs-signatures';
import {readFile, writeFile} from 'fs/promises';
import {base58btc} from 'multiformats/bases/base58';
import jsonld from 'jsonld';
import {localLoader} from './documentLoader.js';

jsonld.documentLoader = localLoader; // Local loader for JSON-LD
const te = new TextEncoder(); // For UTF-8 to byte conversion

// Read input document from a file or just specify it right here.
const presentation = JSON.parse(
  await readFile(
    new URL('./output/presentation.json', import.meta.url)
  )
);

// Separate document from presentation
const context = presentation['@context'];
const presentOptions = presentation.proof;
const document = presentation.verifiableCredential;
const proof = document.proof;
const unsigned = Object.assign({}, document);
delete unsigned.proof;

// Canonize the unsigned document
unsigned['@context'] = context;
const canonDoc = await jsonld.canonize(unsigned);

// Put quads into arrays
const docQArray = canonDoc.split('\n').filter(item => item.length > 0);

// Assemble VC proof options and get all revealed quads
const proofOptions = Object.assign({}, proof);
proofOptions['@context'] = context;
const canonOptions = await jsonld.canonize(proofOptions);
const proofQArray = canonOptions.split('\n').filter(item => item.length > 0);
const allQArray = proofQArray.concat(docQArray);
writeFile('./output/presentVerifyAllQuads.json',
  allQArray.join('\n'));
console.log(`Options quad length ${proofQArray.length},`,
  `Unsigned quad length ${docQArray.length}`);

// Recreate presentation proof options
const proofValue = base58btc.decode(presentOptions.proofValue);
delete presentOptions.proofValue;
const disclosedIndexes = presentOptions.disclosedIndexes;
delete presentOptions.disclosedIndexes;
const requiredRevealStatements = presentOptions.requiredRevealStatements;
delete presentOptions.requiredRevealStatements;
presentOptions['@context'] = context;
const canonPresentProof = await jsonld.canonize(presentOptions);
writeFile('./output/canonPresentProof.txt', canonPresentProof);
const canonPresentProofBytes = te.encode(canonPresentProof);
const ph = canonPresentProofBytes;

// Recreate header from required reveal statement information
const headerDoc = { // This would be standardized...
  '@context': [{requiredRevealStatements:
    'https://grotto-networking.com/bbsld/reqreveal'}],
  '@id': 'urn:uuid:d5a758aa-c83f-495d-b8f5-be9b308429d5',
  requiredRevealStatements
};
const headerCanon = await jsonld.canonize(headerDoc);
const header = te.encode(headerCanon);

// convert combined quads to bytes and map to scalars
const docQByteArray = allQArray.map(q => te.encode(q));
const messageScalars = await messages_to_scalars(docQByteArray);

// Get ready create proof, just need the public key
const pubKeyEncoded = proof.verificationMethod.split('#')[1];
let publicKey = base58btc.decode(pubKeyEncoded);
publicKey = publicKey.slice(2);
const U = numUndisclosed(proofValue); // Number Undisclosed
const R = messageScalars.length; // Number Disclosed
console.log(`Number undisclosed: ${U}, number revealed: ${R}`);
const gens = await prepareGenerators(U + R);

const proofValid = await proofVerify(publicKey, proofValue, header, ph,
  messageScalars, disclosedIndexes, gens);
console.log(`Presentation Proof verified: ${proofValid}`);
