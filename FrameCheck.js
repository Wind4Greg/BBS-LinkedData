// Simple example of selective disclosure and preparation of inputs 
// for BBS derived proof algorithms, i.e., getting disclosed indices.

import jsonld from "jsonld";

// Have local context so no document loading or network stuff
const context = {
  "firstName": "http://schema.org/firstName",
  "email": "http://schema.org/email",
  "jobTitle": "http://schema.org/jobTitle",
  "lastName": "http://schema.org/lastName",
  "telephone": "http://schema.org/telephone"
};

let doc = {
    "@context": context,
    "@id": "urn:bnid:_:c14n0", // Is this where they stabilize the blank node?
    "firstName": "Jane",
    "lastName": "Does",
    "jobTitle": "Professor",
    "email": "jane.doe@example.com",
    "telephone": "(425) 123-4567"
  };

// Don't reveal a bunch of stuff
let frame = {
  "@context": context,
  "@explicit": true,
  "firstName": {},
  "lastName": {}
};

// Selecting stuff via frame
let framed = await jsonld.frame(doc, frame);
console.log("Framed document:")
console.log(framed, "\n");

// Canonize framed and original document
let canonFramed = await jsonld.canonize(framed);
let canonDoc = await jsonld.canonize(doc);
console.log("Canonical Framed:")
console.log(canonFramed, "\n");
console.log("Canonical Document:");
console.log(canonDoc, "\n");

// Put quads into arrays
let docQArray = canonDoc.split('\n');
docQArray.pop(); // Get rid of empty element at end
let frameQArray = canonFramed.split('\n');
frameQArray.pop(); // Get rid of empty element at end

// Figure out the disclosed indices as needed to generate derived proof.
let disclosed = [];
docQArray.forEach(function(quad, i){
    if (frameQArray.includes(quad)) {
      disclosed.push(i);
    }
});
console.log(`disclosed indices: ${disclosed}`);

