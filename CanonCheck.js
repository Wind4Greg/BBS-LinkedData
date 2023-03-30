// Simple example of preparing a document for a BBS **signature**.

import jsonld from "jsonld";
import { blake2b } from '@noble/hashes/blake2b';

const context = {
    "firstName": "http://schema.org/firstName",
    "email": "http://schema.org/email",
    "jobTitle": "http://schema.org/jobTitle",
    "lastName": "http://schema.org/lastName",
    "telephone": "http://schema.org/telephone"
};

const context2 = [
    "http://schema.org/",
    "https://w3id.org/security/v2",
    "https://w3id.org/security/bbs/v1"
  ];

let doc = {
    "@context": context,
    "@id": "urn:bnid:_:c14n0",
    "firstName": "Jane",
    "lastName": "Does",
    "jobTitle": "Professor",
    "email": "jane.doe@example.com",
    "telephone": "(425) 123-4567"
  };

console.log("Full document with context:");
console.log(JSON.stringify(doc, null, 2), "\n");

let canon = await jsonld.canonize(doc);
let quadArray = canon.split('\n');
quadArray.pop(); // get rid of empty string at the end
console.log("Canonized quad array (note order):");
console.log(quadArray, "\n");

// Recreate document in the order of the canonical document -- Hopefully
const from_canon_doc = await jsonld.fromRDF(canon, {format: 'application/n-quads'});
const from_canon_compact = await jsonld.compact(from_canon_doc, context);
console.log("Compact Document from Quads:");
console.log(JSON.stringify(from_canon_compact, null, 2));
// Now we hash and get the "list of messages" that are input to the 
// signature algorithm
// let sigInput = quadArray.map(function(quad){
//     return blake2b(quad);
// });
// console.log(sigInput);

