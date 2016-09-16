crypto_secretbox_NONCEBYTES = 24
{prng} = require('crypto')
uint64be = require('uint64be')

exports.nonceForSenderKeySecretBox = () -> new Buffer('saltpack_sender_key_sbox')

exports.nonceForPayloadKeyBox = () -> new Buffer('saltpack_payload_key_box')

exports.nonceForMACKeyBox = (headerHash) ->
  if headerHash.length isnt 64 then throw new Error('Header hash shorter than expected')
  new Buffer(headerHash[0...crypto_secretbox_NONCEBYTES])

exports.nonceForChunkSecretBox = (encryptionBlockNumber) ->
  nonce = new Buffer('saltpack_ploadsb')
  Buffer.concat([nonce, uint64be.encode(encryptionBlockNumber)])
