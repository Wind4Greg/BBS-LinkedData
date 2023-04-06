/*
    Figuring out steps for BBS proof/verifiable presentation creation.
    Note: Not currently doing blank node processing stuff.
*/
/*global console, TextEncoder, URL*/
import {messages_to_scalars, prepareGenerators, proofGen}
  from '@grottonetworking/bbs-signatures';
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

// Put quads into arrays
const docQArray = canonDoc.split('\n').filter(item => item.length > 0);

// Assemble proof options
const proofOptions = Object.assign({}, proof);
delete proofOptions.proofValue;
const requiredRevealStatements = proofOptions.requiredRevealStatements;
delete proofOptions.requiredRevealStatements;

// canonize VC proof options
proofOptions['@context'] = document['@context'];
const canonOptions = await jsonld.canonize(proofOptions);
const proofQArray = canonOptions.split('\n').filter(item => item.length > 0);
const allQArray = proofQArray.concat(docQArray);
writeFile('./output/presentAllQuads.txt',
  allQArray.join('\n'));
console.log(`Options quad length ${proofQArray.length},`,
  `Unsigned quad length ${docQArray.length}`);

// Let's determine selective disclosure indices via the frame method
// These would be specified by holder.
const selectDocFrame = {
  '@context': document['@context'],
  '@type': 'VerifiableCredential', // Seems required, don't know why
  '@explicit': true,
  name: {}, // They want to reveal the credential name
  credentialSubject: { // This seems to work to get at something inside...
    '@explicit': true,
    email: {} // They will reveal email
  }
};

const selectOptFrame = {
  '@context': document['@context'],
  '@type': 'DataIntegrityProof', // Don't know why this is needed
  '@explicit': true,
};
const selDisclose = await getIndices(unsigned, selectDocFrame, proofOptions,
  selectOptFrame, allQArray);
console.log(`selective disclosure indices: ${selDisclose}`);
console.log(`required reveal indices: ${requiredRevealStatements}`);

const s = new Set(selDisclose);
requiredRevealStatements.forEach(ind => s.add(ind));
const discloseIndices = [...s];
discloseIndices.sort((a, b) => a - b);
console.log(`disclosed indices: ${discloseIndices}`);

// Recreate unsigned and options based on selective disclosure choices
const proofN = proofQArray.length;
const selDocQuads = allQArray.filter((m, i) =>
  discloseIndices.includes(i) && i >= proofN);
const selDocTxt = selDocQuads.join('\n');
const selDoc = await jsonld.fromRDF(selDocTxt,
  {format: 'application/n-quads'});
const selDocCompact = await jsonld.compact(selDoc, unsigned['@context']);
writeFile('./output/selDocCompact.json',
  JSON.stringify(selDocCompact, null, 2));

const selOptQuads = allQArray.filter((m, i) =>
  discloseIndices.includes(i) && i < proofN);
const selOptTxt = selOptQuads.join('\n');
const selOpt = await jsonld.fromRDF(selOptTxt,
  {format: 'application/n-quads'});
const selOptCompact = await jsonld.compact(selOpt, unsigned['@context']);
writeFile('./output/selOptCompact.json',
  JSON.stringify(selOptCompact, null, 2));

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

// Need to create proof options for the presentation

const presentProofOptions = {
  '@context': document['@context'], // just for canonicalization
  type: 'DataIntegrityProof',
  cryptosuite: 'bbs-2023',
  created: '2023-03-29T19:23:24Z',
  proofPurpose: 'assertionMethod',
};

// canonize proof options and convert to bytes

const canonPresentProof = await jsonld.canonize(presentProofOptions);
writeFile('./output/canonPresentProof.txt', canonPresentProof);
const canonPresentProofBytes = te.encode(canonPresentProof);
const ph = canonPresentProofBytes;

// Get ready create proof, just need the public key
const pubKeyEncoded = proof.verificationMethod.split('#')[1];
let publicKey = base58btc.decode(pubKeyEncoded);
publicKey = publicKey.slice(2);
const gens = await prepareGenerators(messageScalars.length);
const signature = base58btc.decode(proof.proofValue);

const presentProofValue = await proofGen(publicKey, signature, header, ph,
  messageScalars, discloseIndices, gens);

// Assemble VP proof
const presentProof = Object.assign({}, presentProofOptions,
  {proofValue: base58btc.encode(presentProofValue),
    disclosedIndexes: discloseIndices,
    requiredRevealStatements
  });
delete presentProof['@context'];
// console.log(JSON.stringify(presentProof, null, 2));

// Create Verifiable Presentation
delete selDocCompact['@context'];
delete selOptCompact['@context'];
selDocCompact.proof = selOptCompact;
const vp = {
  '@context': document['@context'],
  type: 'VerifiablePresentation',
  verifiableCredential: selDocCompact,
  proof: presentProof
};

const presentationText = JSON.stringify(vp, null, 2);
// console.log(presentationText);
writeFile('./output/presentation.json', presentationText);

async function getIndices(document, reqDocDiscloseFrame, proofOptions,
  reqOptionDiscloseFrame, allQArray) {

  // Selecting required reveal for document stuff via frame
  const docFramed = await jsonld.frame(document, reqDocDiscloseFrame);
  // console.log('Framed document:');
  // console.log(docFramed, '\n');

  // Canonize framed document
  const canonDocFramed = await jsonld.canonize(docFramed);
  // console.log('Canonical Framed:');
  // console.log(canonDocFramed, '\n');

  const frameDocQArray = canonDocFramed.split('\n').filter(
    item => item.length > 0);

  // Selecting required reveal for document stuff via frame
  const optionFramed = await jsonld.frame(proofOptions, reqOptionDiscloseFrame);
  // console.log('Framed Options:');
  // console.log(optionFramed, '\n');

  // Canonize framed options
  const canonOptionFramed = await jsonld.canonize(optionFramed);
  // console.log('Canonical Option Framed:');
  // console.log(canonOptionFramed, '\n');

  const frameOptionQArray = canonOptionFramed.split('\n').filter(
    item => item.length > 0);
  const allRequired = frameOptionQArray.concat(frameDocQArray);
  // console.log('All required quads:');
  // console.log(allRequired.join('\n'));

  // Figure out the required disclosure indices as needed for VC proof config
  const reqDisclose = [];
  allQArray.forEach(function(quad, i) {
    if(allRequired.includes(quad)) {
      reqDisclose.push(i);
    }
  });
  return reqDisclose;
}
