/* Demonstrating the encoding of public keys for BBS
   based on multiformats and base58-btc
*/
/*global console*/
import {publicFromPrivate} from '@grottonetworking/bbs-signatures';
import {bytesToHex, concatBytes, hexToBytes} from '@noble/hashes/utils';
import {base58btc} from 'multiformats/bases/base58';
import varint from 'varint';

// Multicodec information from https://github.com/multiformats/multicodec/
/*
name                  tag     code  status     description
bls12_381-g2-pub	    key     0xeb	draft	     BLS12-381 public key in the G2 field
*/

console.log('Multicodec leading bytes in hex for BLS12-381 G2 public key:');
const myBytes = new Uint8Array(varint.encode(0xeb));
console.log(`leading bytes: ${bytesToHex(myBytes)}`);

// Example keys from BBS draft

console.log('BBS key example:');
// From https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-key-pair
const privateKey = hexToBytes('4a39afffd624d69e81808b2e84385cc80bf86adadf764e030caa46c231f2a8d7');
const publicKey = publicFromPrivate(privateKey);
console.log(`BBS private key length: ${privateKey.length}`);
console.log('BBS private key hex:');
console.log(bytesToHex(privateKey));
console.log(`BBS Pubic key length ${publicKey.length}`);
console.log('BBS public key in hex:');
console.log(bytesToHex(publicKey));
const BBSG2Prefix = new Uint8Array(varint.encode(0xeb)); // Need to use varint on the multicodecs code
const pubBBSEncoded = base58btc.encode(concatBytes(BBSG2Prefix, publicKey));
console.log('BBS G2 encoded multikey:');
console.log(pubBBSEncoded, '\n'); // Should start with characters zUC7

