{prng} = require('crypto')
{createHash} = require('crypto')
{createHmac} = require('crypto')
msgpack = require('purepack')
crypto = require('keybase-nacl')
nonce = require('./nonce.iced')
util = require('./util.iced')

# HMAC-SHA512-256(step1 hash, mac_key)
compute_authenticator = (hash, key) ->
  hmac = createHmac('sha512', key)
  hmac.update(hash)
  return hmac.digest()[0...32]

# sha512(header_hash + payload secretbox nonce + payload secretbox)
step1 = (header_hash, block_num, payload_secretbox) ->
  step1_cat = Buffer.concat([header_hash, nonce.nonceForChunkSecretBox(block_num), payload_secretbox])
  crypto_hash = createHash('sha512')
  crypto_hash.update(step1_cat)
  step1_hash = crypto_hash.digest()
  return step1_hash

exports.generate_encryption_payload_packet = (encryptor, plaintext, block_num, header_hash, mac_keys) ->
  # perform nacl encryption of payload
  payload_secretbox = encryptor.secretbox({plaintext, nonce : nonce.nonceForChunkSecretBox(block_num)})

  # compute the authenticators
  step1_hash = step1(header_hash, block_num, payload_secretbox)
  authenticators = []
  for mac_key in mac_keys
    authenticator = compute_authenticator(step1_hash, mac_key)
    authenticators.push(authenticator)

  return [authenticators, payload_secretbox]

exports.parse_encryption_payload_packet = (decryptor, payload_list, block_num, header_hash, mac_key, recipient_index) ->
  # verify that we are an authenticator
  step1_hash = step1(header_hash, block_num, payload_list[1])
  computed_authenticator = compute_authenticator(step1_hash, mac_key)
  unless util.bufeq_secure(computed_authenticator, payload_list[0][recipient_index]) then throw new Error('You are not an authenticator!')

  # if we make it here, we are an authenticator, so decrypt
  payload = decryptor.secretbox_open({ciphertext : payload_list[1], nonce : nonce.nonceForChunkSecretBox(block_num)})

  return payload
