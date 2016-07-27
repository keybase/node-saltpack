crypto = require('crypto')
nacl = require('keybase-nacl')
saltpack = require('../..')
header = saltpack.lowlevel.header
payload = saltpack.lowlevel.payload
nonce = saltpack.lowlevel.nonce

gen_encryptors = () ->
  encryptor = nacl.alloc({force_js : false})
  decryptor = nacl.alloc({force_js : false})
  encryptor.genBoxPair()
  decryptor.genBoxPair()
  return {encryptor, decryptor}

gen_recipients = (pk) ->
  recipient_index = crypto.randomBytes(1)[0]
  recipients_list = []
  for i in [0...(recipient_index + crypto.randomBytes(1)[0])]
    recipients_list.push(crypto.randomBytes(32))
  recipients_list[recipient_index] = pk
  return {recipients_list, recipient_index}

gen_header = () ->
  {encryptor, decryptor} = gen_encryptors()
  {recipients_list, recipient_index} = gen_recipients(decryptor.publicKey)
  packed_header = header.generate_encryption_header_packet(encryptor, recipients_list)
  return {packed_header, recipient_index, encryptor, decryptor}

#===============================================================================

exports.test_header_pipeline = (T, cb) ->
  {packed_header, recipient_index, _, decryptor} = gen_header()
  {mac_key} = header.parse_encryption_header_packet(decryptor, packed_header.header_intermediate)

  T.equal(packed_header.mac_keys[recipient_index], mac_key, "MAC keys didn't match: packed key = #{packed_header.mac_keys[recipient_index]}, unpacked key = #{mac_key}")
  cb()

exports.test_payload_pipeline = (T, cb) ->
  {packed_header, _, encryptor, decryptor} = gen_header()
  {header_list, header_hash, payload_key, sender_pubkey, mac_key, recipient_index} = header.parse_encryption_header_packet(decryptor, packed_header.header_intermediate)

  block_num = 0
  plaintext = crypto.randomBytes(crypto.randomBytes(1)[0])

  encryptor.secretKey = payload_key
  payload_list = payload.generate_encryption_payload_packet(encryptor, plaintext, block_num, header_hash, packed_header.mac_keys)

  decryptor.secretKey = payload_key
  expected_payload = payload.parse_encryption_payload_packet(decryptor, payload_list, block_num, header_hash, mac_key, recipient_index)

  T.equal(plaintext, expected_payload, "Plaintexts didn't match")
  cb()
