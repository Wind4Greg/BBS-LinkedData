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
// Put doc quads into array
const docQArray = canonDoc.split('\n').filter(item => item.length > 0);

// Assemble proof options
const proofOptions = {
  '@context': document['@context'], // just for canonicalization
  id: 'urn:uuid:eca3bb18-49c1-4602-a6dd-01bad440dcd9',
  type: 'DataIntegrityProof',
  cryptosuite: 'bbs-2023',
  created: '2020-11-05T19:23:24Z',
  verificationMethod: 'https://di.example/issuer#zUC7Fk29SRjBb5D4T8KbvsG562YHrVChFoZDw9mjfze4fmSUoMv6pop4kk9DRbjXXyCqmoprwikuEeRLt5ybxk2m88hAYJQLHU7o7S9LB7Y4Q8Lvu84v4YB4PXcGCCei1Qex2XF',
  proofPurpose: 'assertionMethod'
  // no requiredRevealStatements field yet
};
console.log(JSON.stringify(proofOptions, null, 2));
writeFile('./output/proofOptions.json', JSON.stringify(proofOptions, null, 2));
// canonize proof options and convert to bytes

const canonOptions = await jsonld.canonize(proofOptions);
writeFile('./output/canonProof.txt', canonOptions);
// Put proofOptions quads into array
const proofQArray = canonOptions.split('\n').filter(item => item.length > 0);
console.log('Proof Quad Array:');
console.log(proofQArray);
const allQArray = proofQArray.concat(docQArray);
writeFile('./output/allQuads.txt', allQArray.join('\n'));

// Figure out the required disclosure indices as needed for VC proof config
// These would be specified by issuer.
// This produces two extra pieces of information in my tests
// type info and the id of the credentialSubject.
const reqDocDiscloseFrame = {
  '@context': document['@context'],
  '@type': 'VerifiableCredential', // Seems required, don't know why
  '@explicit': true,
  issuer: {}, // Choose Must disclose
  validFrom: {}, // Choose Must disclose
  credentialSubject: { // This seems to work to get at something inside...
    '@explicit': true,
    jobTitle: {} // Choose Must disclose
  }
};
// required revealed options
const reqOptionDiscloseFrame = {
  '@context': document['@context'],
  '@type': 'DataIntegrityProof', // Don't know why this is needed
  '@explicit': true,
  verificationMethod: {}, // Draft CCG Must disclose
  proofPurpose: {}, // Draft CCG Must disclose
};
const reqDisclose = await getIndices(document, reqDocDiscloseFrame,
  proofOptions, reqOptionDiscloseFrame, allQArray);
console.log(`required disclosure indices: ${reqDisclose}`);

// convert document quads to bytes and map to scalars
const allQByteArray = allQArray.map(q => te.encode(q));
const messageScalars = await messages_to_scalars(allQByteArray);

// Get ready to sign
const privateKey = hexToBytes('4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7');
const publicKey = publicFromPrivate(privateKey);
const gens = await prepareGenerators(messageScalars.length);

// Protect required reveal statement information by putting canonized version
// into the header.
const headerDoc = { // This would be standardized...
  '@context': [{requiredRevealStatements:
    'https://grotto-networking.com/bbsld/reqreveal'}],
  '@id': 'urn:uuid:d5a758aa-c83f-495d-b8f5-be9b308429d5',
  requiredRevealStatements: reqDisclose
};
const headerCanon = await jsonld.canonize(headerDoc);
const header = te.encode(headerCanon);

// Signing
const signature = await sign(privateKey, publicKey, header, messageScalars,
  gens);

// Assemble VC proof
const proof = Object.assign({}, proofOptions,
  {requiredRevealStatements: reqDisclose},
  {proofValue: base58btc.encode(signature)});
delete proof['@context'];

// Add proof to document
document.proof = proof;
const signedDocText = JSON.stringify(document, null, 2);
console.log(signedDocText);
writeFile('./output/signedDocBBS.json', signedDocText);

/**
 * Computes the required revealed indices for BBS based on combined
 * set of messages from document and options.
 *
 * @param {object} document - Unsigned document with context.
 * @param {object} reqDocDiscloseFrame - Frame for required reveal portions of
 *  the document.
 * @param {object} proofOptions - VC proof options with context.
 * @param {object} reqOptionDiscloseFrame - Frame for required reveal portions
 * of the VC proof options.
 * @param {Array} allQArray - Array contains the quads from the canonized
 * options and canonized document combined.
 * @returns {Array} - Of indices in the quad array that match with quads
 * obtained from the input frames.
 */
async function getIndices(document, reqDocDiscloseFrame, proofOptions,
  reqOptionDiscloseFrame, allQArray) {

  // Selecting required reveal for document stuff via frame
  const docFramed = await jsonld.frame(document, reqDocDiscloseFrame);
  console.log('Framed document:');
  console.log(docFramed, '\n');

  // Canonize framed document
  const canonDocFramed = await jsonld.canonize(docFramed);
  console.log('Canonical Framed:');
  console.log(canonDocFramed, '\n');
  writeFile('./output/canonFramedBBS.txt', canonDocFramed);

  const frameDocQArray = canonDocFramed.split('\n').filter(
    item => item.length > 0);

  // Selecting required reveal for document stuff via frame
  const optionFramed = await jsonld.frame(proofOptions, reqOptionDiscloseFrame);
  console.log('Framed Options:');
  console.log(optionFramed, '\n');

  // Canonize framed options
  const canonOptionFramed = await jsonld.canonize(optionFramed);
  // console.log('Canonical Option Framed:');
  // console.log(canonOptionFramed, '\n');
  writeFile('./output/canonOptionFramedBBS.txt', canonOptionFramed);

  const frameOptionQArray = canonOptionFramed.split('\n').filter(
    item => item.length > 0);
  const allRequired = frameOptionQArray.concat(frameDocQArray);

  // Figure out the required disclosure indices as needed for VC proof config
  const reqDisclose = [];
  allQArray.forEach(function(quad, i) {
    if(allRequired.includes(quad)) {
      reqDisclose.push(i);
    }
  });
  return reqDisclose;
}
