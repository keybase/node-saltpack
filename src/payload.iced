crypto = require('crypto')
{make_esc} = require('iced-error')
nonce = require('./nonce')
util = require('./util')

# HMAC-SHA512-256(step1 hash, mac_key)
compute_authenticator = ({hash, key}, cb) ->
  try
    hmac = crypto.createHmac('sha512', key)
    hmac.update(hash)
    authenticator = hmac.digest()[0...32]
  catch
    return cb(new Error("compute_authenticator"), null)
  cb(null, authenticator)

# sha512(header_hash + payload secretbox nonce + payload secretbox)
step1 = ({header_hash, block_num, payload_secretbox}, cb) ->
  try
    step1_cat = Buffer.concat([header_hash, nonce.nonceForChunkSecretBox(block_num), payload_secretbox])
    crypto_hash = crypto.createHash('sha512')
    crypto_hash.update(step1_cat)
    step1_hash = crypto_hash.digest()
  catch err
    console.log(err.message)
    return cb(new Error("step1"), null)
  cb(null, step1_hash)

exports.generate_encryption_payload_packet = ({payload_encryptor, plaintext, block_num, header_hash, mac_keys}, cb) ->
  esc = make_esc(cb, "generate_encryption_payload_packet")
  # perform nacl encryption of payload
  payload_secretbox = payload_encryptor.secretbox({plaintext, nonce : nonce.nonceForChunkSecretBox(block_num)})
  # compute the authenticators
  await step1({header_hash, block_num, payload_secretbox}, esc(defer(step1_hash)))
  authenticators = []
  for i in [0...mac_keys.length]
    await compute_authenticator({hash : step1_hash, key : mac_keys[i]}, esc(defer(authenticators[i])))
  cb(null, [authenticators, payload_secretbox])

exports.parse_encryption_payload_packet = ({payload_decryptor, payload_list, block_num, header_hash, mac_key, recipient_index}, cb) ->
  esc = make_esc(cb, "parse_encryption_payload_packet")
  # verify that we are an authenticator
  await step1({header_hash, block_num, payload_secretbox : payload_list[1]}, esc(defer(step1_hash)))
  await compute_authenticator({hash : step1_hash, key : mac_key}, esc(defer(computed_authenticator)))
  unless util.bufeq_secure(computed_authenticator, payload_list[0][recipient_index])
    return cb(new Error('Integrity check failed!'), null)

  # if we make it here, we are an authenticator, so decrypt
  payload = payload_decryptor.secretbox_open({ciphertext : payload_list[1], nonce : nonce.nonceForChunkSecretBox(block_num)})
  cb(null, payload)
