crypto_secretbox_NONCEBYTES = 24
{prng} = require('crypto')
uint64be = require('uint64be')

exports.nonceForSenderKeySecretBox = () -> return Buffer.from('saltpack_sender_key_sbox')

exports.nonceForPayloadKeyBox = () -> return Buffer.from('saltpack_payload_key_box')

exports.nonceForMACKeyBox = (headerHash) ->
  if headerHash.length isnt 64 then throw new Error('Header hash shorter than expected')
  return Buffer.from(headerHash[0...crypto_secretbox_NONCEBYTES])

exports.nonceForChunkSecretBox = (encryptionBlockNumber) ->
  nonce = Buffer.from('saltpack_ploadsb')
  return Buffer.concat([nonce, uint64be.encode(encryptionBlockNumber)])
