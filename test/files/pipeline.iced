{prng} = require('crypto')
main = require('keybase-nacl')
header = require('../../src/header.iced')
payload = require('../../src/payload.iced')
nonce = require('../../src/nonce.iced')

gen_encryptors = () ->
  encryptor = main.alloc({force_js : false})
  decryptor = main.alloc({force_js : false})
  encryptor.genBoxPair()
  decryptor.genBoxPair()
  return {encryptor, decryptor}

gen_recipients = (pk) ->
  recipient_index = prng(1)[0]
  recipients_list = []
  for i in [0...(recipient_index + prng(1)[0])]
    recipients_list.push(prng(32))
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

exports.test_packet_pipeline = (T, cb) ->
  {packed_header, _, encryptor, decryptor} = gen_header()
  {header_list, header_hash, payload_key, sender_pubkey, mac_key, recipient_index} = header.parse_encryption_header_packet(decryptor, packed_header.header_intermediate)

  block_num = 0
  plaintext = prng(prng(1)[0])

  encryptor.secretKey = payload_key
  payload_list = payload.generate_encryption_payload_packet(encryptor, plaintext, block_num, header_hash, packed_header.mac_keys)

  decryptor.secretKey = payload_key
  expected_payload = payload.parse_encryption_payload_packet(decryptor, payload_list, block_num, header_hash, mac_key, recipient_index)

  T.equal(plaintext, expected_payload, "Plaintexts didn't match")
  cb()
