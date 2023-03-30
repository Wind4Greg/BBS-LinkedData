/*
    Figuring out steps for BBS signature preprocessing.
    Note: Not currently doing blank node processing stuff.
*/

import { readFile, writeFile } from 'fs/promises';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

// Read input document from a file or just specify it right here.
let document = JSON.parse(
    await readFile(
      new URL('./input/unsigned.json', import.meta.url)
    )
  );

// Canonize the unsigned document
let canonDoc = await jsonld.canonize(document);
// console.log("Canonized unsigned document:")
// console.log(cannonDoc);
writeFile('./output/canonDocBBS.txt', canonDoc);

// Let's determine required disclosure indices via frame method
// These would be specified by issuer. 
let reqDiscloseFrame = {
    "@context": document['@context'],
    "@type": "VerifiableCredential",
    "@explicit": true,
    "@omitGraph": true,
    "issuer": {}, // Must disclose
    "validFrom": {}, // Must disclose
    "credentialSubject": { // This seems to work to get at something inside...
        "@explicit": true,
         "jobTitle": {} // Must disclose
      }
  };

// Selecting stuff via frame
let framed = await jsonld.frame(document, reqDiscloseFrame);
console.log("Framed document:")
console.log(framed, "\n");

// Canonize framed and original document
let canonFramed = await jsonld.canonize(framed);
console.log("Canonical Framed:")
console.log(canonFramed, "\n");
writeFile('./output/canonFramedBBS.txt', canonFramed);
console.log("Canonical Document:");
console.log(canonDoc, "\n");

// Put quads into arrays
let docQArray = canonDoc.split('\n');
docQArray.pop(); // Get rid of empty element at end
let frameQArray = canonFramed.split('\n');
frameQArray.pop(); // Get rid of empty element at end

// Figure out the required disclosure indices as needed for VC proof config
let disclosed = [];
docQArray.forEach(function(quad, i){
    if (frameQArray.includes(quad)) {
      disclosed.push(i);
    }
});
console.log(`required disclosure indices: ${disclosed}`);
