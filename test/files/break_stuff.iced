crypto = require('crypto')
msgpack = require('keybase-msgpack-lite')
saltpack = require('../..')
util = saltpack.lowlevel.util
header = saltpack.lowlevel.header
payload = saltpack.lowlevel.payload

generate_anonymous_header = (alice, pk) ->
  recipients = util.gen_recipients(pk)
  anonymized_recipients = []
  for i in [0...recipients.length]
    anonymized_recipients.push(null)
  header.generate_encryption_header_packet({encryptor : alice, recipients, anonymized_recipients})

#===============================================================================

exports.break_encryption_header_packet = (T, cb) ->
  {alice, bob} = util.alice_and_bob()
  {header_intermediate, header_hash, mac_keys, payload_key} = generate_anonymous_header(alice, bob.publicKey)

  # break the format string
  header_list_format_broken = msgpack.decode(header_intermediate)
  header_list_format_broken[0] = 'satlpack'
  header_format_broken = msgpack.encode(header_list_format_broken)
  try
    header.parse_encryption_header_packet({decryptor : bob, header_intermediate : header_format_broken})
  catch error
    T.equal(error.message, "wrong format satlpack")

  # break the version number
  header_list_version_broken = msgpack.decode(header_intermediate)
  header_list_version_broken[1][0] = 0
  header_version_broken = msgpack.encode(header_list_version_broken)
  try
    header.parse_encryption_header_packet({decryptor : bob, header_intermediate : header_version_broken})
  catch error
    T.equal(error.message, "wrong version number 0.0")

  # break the mode number
  header_list_mode_broken = msgpack.decode(header_intermediate)
  header_list_mode_broken[2] = 1
  header_mode_broken = msgpack.encode(header_list_mode_broken)
  try
    header.parse_encryption_header_packet({decryptor : bob, header_intermediate : header_mode_broken})
  catch error
    T.equal(error.message, "packet wasn't meant for decryption, found mode 1")

  cb()

exports.break_recipients_list = (T, cb) ->
  {alice, bob} = util.alice_and_bob()
  {header_intermediate, header_hash, mac_keys, payload_key} = generate_anonymous_header(alice, crypto.randomBytes(32))

  try
    header.parse_encryption_header_packet({decryptor : bob, header_intermediate})
  catch error
    T.equal(error.message, "You are not a recipient!")

  cb()

#===============================================================================

exports.break_mac_key_in_payload_packet = (T, cb) ->
  {alice, bob} = util.alice_and_bob()
  {header_intermediate, header_hash, mac_keys, payload_key} = generate_anonymous_header(alice, bob.publicKey)
  alice.secretKey = payload_key

  {recipient_index} = header.parse_encryption_header_packet({decryptor : bob, header_intermediate})

  plaintext = crypto.randomBytes(crypto.randomBytes(1)[0]**2)
  payload_list = payload.generate_encryption_payload_packet({payload_encryptor : alice, plaintext, block_num : 0, header_hash, mac_keys})

  # break the MAC key
  {_, _, _, _, mac_key, _} = header.parse_encryption_header_packet({decryptor : bob, header_intermediate})
  mac_key[0] = ~mac_key[0]

  try
    payload.parse_encryption_payload_packet({decryptor : bob, payload_list, block_num : 0, header_hash, mac_key, recipient_index})
  catch error
    T.equal(error.message, "Integrity check failed!")

  cb()
