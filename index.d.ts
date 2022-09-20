
declare type Hex = string | symbol;
declare type Base64 = string | symbol;
declare type TVerifierFunction = (publicKey: Hex, hash: Hex, sig: Base64) => boolean
declare type TSignerFunction = (hash: Hex) => Base64
declare const createSigner: (privateKey: Hex) => TSignerFunction
declare const createVerifier: () => TVerifierFunction

declare const createHash: (data: Buffer|string) => Hex
declare const createObjHash: (data: Object) => Hex

export {createVerifier, createSigner, createHash, createObjHash}