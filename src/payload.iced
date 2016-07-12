{prng} = require('crypto')
{createHash} = require('crypto')
{createHmac} = require('crypto')
msgpack = require('purepack')
crypto = require('keybase-nacl')
nonce = require('./nonce.iced')
util = require('./util.iced')

compute_authenticator = (hash, key) ->
  hmac = createHmac('sha512', key)
  hmac.update(hash)
  return hmac.digest()[0...32]

step1 = (header_hash, block_num, payload_secretbox) ->
  step1_cat = Buffer.concat([header_hash, nonce.nonceForChunkSecretBox(block_num), payload_secretbox])
  crypto_hash = createHash('sha512')
  crypto_hash.update(step1_cat)
  step1_hash = crypto_hash.digest()

exports.generate_encryption_payload_packet = (payload_secretbox, block_num, header_hash, mac_keys) ->
  step1_hash = step1(header_hash, block_num, payload_secretbox)

  authenticators = []
  for mac_key in mac_keys
    authenticator = compute_authenticator(step1_hash, mac_key)
    authenticators.push(authenticator)

  payload_list = [authenticators, payload_secretbox]
  return payload_list

exports.parse_encryption_payload_packet = (payload_list, block_num, header_hash, mac_key, auth_index) ->
  step1_hash = step1(header_hash, block_num, payload_list[1])

  computed_authenticator = compute_authenticator(step1_hash, mac_key)
  unless util.bufeq_secure(computed_authenticator, payload_list[0][auth_index]) then throw new Error('You are not an authenticator!')

  return payload_list[1]
