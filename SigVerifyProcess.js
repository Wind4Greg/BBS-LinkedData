/*
    Figuring out steps for BBS signature verification processing.
    Run this after running SigningProcess.js
    Note: Not currently doing blank node processing stuff.

*/
/*global console, TextEncoder, URL*/
import {hexToBytes, messages_to_scalars, prepareGenerators, publicFromPrivate,
  verify} from '@grottonetworking/bbs-signatures';
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
let proof = document.proof;
let unsigned = Object.assign({}, document);
delete unsigned.proof;

// Canonize the unsigned document
const canonDoc = await jsonld.canonize(unsigned);
// console.log("Canonized unsigned document:")
// console.log(cannonDoc);

// Put quads into arrays
const docQArray = canonDoc.split('\n');
docQArray.pop(); // Get rid of empty element at end


// Assemble proof options
const proofOptions = Object.assign({}, proof);
delete proofOptions.proofValue;
delete proofOptions.requiredRevealStatements;

// canonize proof options and convert to bytes
proofOptions['@context'] = document['@context'];
const canonOptions = await jsonld.canonize(proofOptions);
const proofQArray = canonOptions.split('\n');
proofQArray.pop(); // Get rid of empty element at end
const allQArray = proofQArray.concat(docQArray);


// convert document quads to bytes and map to scalars
const allQByteArray = allQArray.map(q => te.encode(q));
const messageScalars = await messages_to_scalars(allQByteArray);

// Get ready to verify
const privateKey = hexToBytes("4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7");
const publicKey = publicFromPrivate(privateKey);
const gens = await prepareGenerators(messageScalars.length);

// Verify
const header = new Uint8Array();
const signature = base58btc.decode(proof.proofValue);
const verified = await verify(publicKey, signature, header, messageScalars,
  gens);
console.log(`VC signature verified: ${verified}`);
