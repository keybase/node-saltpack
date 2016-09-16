crypto = require('crypto')
msgpack = require('keybase-msgpack-lite')
{make_esc} = require('iced-error')
saltpack = require('../..')
header = saltpack.lowlevel.header
payload = saltpack.lowlevel.payload
nonce = saltpack.lowlevel.nonce
util = saltpack.lowlevel.util

gen_header = ({keep_alice_anonymous, anonymize_recipients}, cb) ->
  esc = make_esc(cb, "gen_header")
  {alice, bob} = util.alice_and_bob()
  if keep_alice_anonymous then alice.publicKey = null
  recipients_list = util.gen_recipients(bob.publicKey)

  if anonymize_recipients? and anonymize_recipients
    anonymized_recipients = []
    anonymized_recipients.push(null) for i in [0...recipients_list.length]

  await header.generate_encryption_header_packet({encryptor : alice, recipients : recipients_list, anonymized_recipients}, esc(defer(packed_header)))
  return cb(null, {packed_header, alice, bob})

_test_header_pipeline = (T, opts, cb) ->
  esc = make_esc(cb, "_test_header_pipeline")
  await gen_header(opts, esc(defer({packed_header, bob})))
  await header.parse_encryption_header_packet({decryptor : bob, header_intermediate : packed_header.header_intermediate}, esc(defer({mac_key, recipient_index})))

  T.equal(packed_header.mac_keys[recipient_index], mac_key, "MAC keys didn't match: packed key = #{packed_header.mac_keys[recipient_index]}, unpacked key = #{mac_key}")

#===============================================================================

exports.test_anonymous_sender = (T, cb) ->
  esc = make_esc(cb, "test_anonymous_sender")
  await gen_header({keep_alice_anonymous : true}, esc(defer({packed_header, bob})))
  await header.parse_encryption_header_packet({decryptor : bob, header_intermediate : packed_header.header_intermediate}, esc(defer({sender_pubkey})))
  header_list = msgpack.decode(packed_header.header_intermediate)
  T.equal(header_list[3], sender_pubkey, "Ephemeral key wasn't supplied as sender key")
  cb()

exports.test_payload_pipeline = (T, cb) ->
  esc = make_esc(cb, "test_payload_pipeline")
  await gen_header({keep_alice_anonymous : false, anonymize_recipients : false}, esc(defer({packed_header, alice, bob})))
  await header.parse_encryption_header_packet({decryptor : bob, header_intermediate : packed_header.header_intermediate}, esc(defer({header_list, header_hash, payload_key, sender_pubkey, mac_key, recipient_index})))

  block_num = 0
  plaintext = crypto.randomBytes(crypto.randomBytes(1)[0])

  alice.secretKey = payload_key
  await payload.generate_encryption_payload_packet({payload_encryptor : alice, plaintext, block_num, header_hash, mac_keys : packed_header.mac_keys}, esc(defer(payload_list)))

  bob.secretKey = payload_key
  await payload.parse_encryption_payload_packet({payload_decryptor : bob, payload_list, block_num, header_hash, mac_key, recipient_index}, esc(defer(expected_payload)))

  T.equal(plaintext, expected_payload, "Plaintexts didn't match")
  cb()

exports.test_sodium_anonymous_recipients = (T, cb) ->
  _test_header_pipeline(T, {force_js : false, keep_alice_anonymous : true, anonymize_recipients : true})
  cb()

exports.test_tweetnacl_anonymous_recipients = (T, cb) ->
  _test_header_pipeline(T, {force_js : true, keep_alice_anonymous : true, anonymize_recipients : true})
  cb()
