crypto = require('crypto')
msgpack = require('keybase-msgpack-lite')
saltpack = require('../..')
header = saltpack.lowlevel.header
payload = saltpack.lowlevel.payload
nonce = saltpack.lowlevel.nonce
util = saltpack.lowlevel.util

gen_header = (opts) ->
  {alice, bob} = util.alice_and_bob(opts)
  if opts?.keep_alice_anonymous then alice.publicKey = null
  recipients_list = util.gen_recipients(bob.publicKey)

  if opts?.anonymize_recipients
    anonymized_recipients = []
    anonymized_recipients.push(null) for i in [0...recipients_list.length]

  packed_header = header.generate_encryption_header_packet({encryptor : alice, recipients : recipients_list, anonymized_recipients})
  return {packed_header, alice, bob}

_test_header_pipeline = (T, opts) ->
  {packed_header, _, bob} = gen_header(opts)
  {mac_key, recipient_index} = header.parse_encryption_header_packet({decryptor : bob, header_intermediate : packed_header.header_intermediate})

  T.equal(packed_header.mac_keys[recipient_index], mac_key, "MAC keys didn't match: packed key = #{packed_header.mac_keys[recipient_index]}, unpacked key = #{mac_key}")

#===============================================================================

exports.test_anonymous_sender = (T, cb) ->
  {packed_header, _, bob} = gen_header({keep_alice_anonymous : true})
  {_, _, _, sender_pubkey, _, _} = header.parse_encryption_header_packet({decryptor : bob, header_intermediate : packed_header.header_intermediate})
  header_list = msgpack.decode(packed_header.header_intermediate)
  T.equal(header_list[3], sender_pubkey, "Ephemeral key wasn't supplied as sender key")
  cb()

exports.test_payload_pipeline = (T, cb) ->
  {packed_header, alice, bob} = gen_header()
  {header_list, header_hash, payload_key, sender_pubkey, mac_key, recipient_index} = header.parse_encryption_header_packet({decryptor : bob, header_intermediate : packed_header.header_intermediate})

  block_num = 0
  plaintext = crypto.randomBytes(crypto.randomBytes(1)[0])

  alice.secretKey = payload_key
  payload_list = payload.generate_encryption_payload_packet({payload_encryptor : alice, plaintext, block_num, header_hash, mac_keys : packed_header.mac_keys})

  bob.secretKey = payload_key
  expected_payload = payload.parse_encryption_payload_packet({payload_decryptor : bob, payload_list, block_num, header_hash, mac_key, recipient_index})

  T.equal(plaintext, expected_payload, "Plaintexts didn't match")
  cb()

exports.test_sodium_anonymous_recipients = (T, cb) ->
  _test_header_pipeline(T, {force_js : false, keep_alice_anonymous : true, anonymize_recipients : true})
  cb()

exports.test_tweetnacl_anonymous_recipients = (T, cb) ->
  _test_header_pipeline(T, {force_js : true, keep_alice_anonymous : true, anonymize_recipients : true})
  cb()
