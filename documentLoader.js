import jsonld from 'jsonld';
import { vcv2 } from './contexts/credv2.js';



// Set up a document loader so we don't have to go to the net
const CONTEXTS = {
    "https://www.w3.org/ns/credentials/v2": { "@context": vcv2 }
};
// Only needed if you want remote loading, see comments below
const nodeDocumentLoader = jsonld.documentLoaders.node();

// change the default document loader
export const localLoader = async (url, options) => {
    if (url in CONTEXTS) {
        return {
            contextUrl: null, // this is for a context via a link header
            document: CONTEXTS[url], // this is the actual document that was loaded
            documentUrl: url // this is the actual context URL after redirects
        };
    }
    // uncomment if you want to load resources from remote sites
    // return nodeDocumentLoader(url);
    // comment out if your want to load resources from remote sites
    throw Error("Only local loading currently enabled");
};