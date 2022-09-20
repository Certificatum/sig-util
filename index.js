const strToInt = c => c.charCodeAt(0)
const keccak256 = require('keccak256')
const u8tob64 = (u8) =>
  btoa(String.fromCharCode.apply(null, u8))
const b64tou8 = (b64) =>
  new Uint8Array(
    atob(b64)
      .split("")
      .map(strToInt)
  )

module.exports.createObjHash = (data) =>
  keccak256(JSON.stringify(data)).toString('hex')

module.exports.createHash = (data) =>
  keccak256(data).toString('hex')

module.exports.createSigner = (privateKey) => {
  const { signSync, utils } = require("@noble/secp256k1")
  setHmacSha256Sync(utils)
  const decoder = new TextDecoder()
  return (hash) =>
    u8tob64(signSync(hash, privateKey))
}
module.exports.createVerifier = () => {
  const { recoverPublicKey, utils } = require("@noble/secp256k1")
  setHmacSha256Sync(utils)
  const decoder = new TextDecoder()

  return (public_key, hash, sig) =>
    Buffer.from(recoverPublicKey(
      hash,
      b64tou8(sig), 0, true
    )).toString("hex") === public_key
    ||
    // TODO: find way to calculate recovery bit to increase performance
    Buffer.from(recoverPublicKey(
      hash,
      b64tou8(sig), 1, true
    )).toString("hex") === public_key

}

const setHmacSha256Sync = (utils) => {
  if (!utils.hmacSha256Sync) {
    const { hmac } = require("@noble/hashes/hmac")
    const { sha256 } = require("@noble/hashes/sha256")

    utils.hmacSha256Sync = (key, ...messages) => {
      const h = hmac.create(sha256, key)
      messages.forEach(msg => h.update(msg))
      return h.digest()
    }
  }
}
