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

gen_header = () ->
  {encryptor, decryptor} = gen_encryptors()
  random_index = prng(1)[0]
  recipients_list = []

  for i in [0...(random_index + prng(1)[0])]
    recipients_list.push(prng(32))

  recipients_list[random_index] = decryptor.publicKey
  packed_header = header.generate_encryption_header_packet(encryptor, recipients_list)
  return {packed_header, random_index, encryptor, decryptor}

#===============================================================================

exports.test_header_pipeline = (T, cb) ->
  {packed_header, random_index, _, decryptor} = gen_header()
  {mac_key} = header.parse_encryption_header_packet(decryptor, packed_header.header_intermediate)

  T.equal(packed_header.mac_keys[random_index], mac_key, "MAC keys didn't match: packed key = #{packed_header.mac_keys[random_index]}, unpacked key = #{mac_key}")
  cb()

exports.test_packet_pipeline = (T, cb) ->
  {packed_header, _, encryptor, decryptor} = gen_header()
  {header_list, header_hash, payload_key, sender_pubkey, mac_key, auth_index} = header.parse_encryption_header_packet(decryptor, packed_header.header_intermediate)

  block_num = 0
  plaintext = prng(prng(1)[0])
  payload_secretbox = encryptor.secretbox({plaintext, nonce : nonce.nonceForChunkSecretBox(block_num)})

  payload_list = payload.generate_encryption_payload_packet(payload_secretbox, block_num, header_hash, packed_header.mac_keys)

  expected_payload_secretbox = payload.parse_encryption_payload_packet(payload_list, block_num, header_hash, mac_key, auth_index)
  expected_plaintext = encryptor.secretbox_open({ciphertext : expected_payload_secretbox, nonce : nonce.nonceForChunkSecretBox(block_num)})

  T.equal(plaintext, expected_plaintext, "Plaintexts didn't match")
  cb()
