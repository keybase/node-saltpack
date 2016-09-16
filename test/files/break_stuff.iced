crypto = require('crypto')
msgpack = require('keybase-msgpack-lite')
{make_esc} = require('iced-error')
saltpack = require('../..')
util = saltpack.lowlevel.util
header = saltpack.lowlevel.header
payload = saltpack.lowlevel.payload

generate_anonymous_header = (alice, pk, cb) ->
  esc = make_esc(cb, "generate_anonymous_header")
  recipients = util.gen_recipients(pk)
  anonymized_recipients = []
  for i in [0...recipients.length]
    anonymized_recipients.push(null)
  await header.generate_encryption_header_packet({encryptor : alice, recipients, anonymized_recipients}, esc(defer(packet)))
  return cb(null, packet)

#===============================================================================

exports.break_encryption_header_packet = (T, cb) ->
  esc = make_esc(cb, "break_encryption_header_packet")
  {alice, bob} = util.alice_and_bob()
  await generate_anonymous_header(alice, bob.publicKey, esc(defer({header_intermediate, header_hash, mac_keys, payload_key})))

  # break the format string
  header_list_format_broken = msgpack.decode(header_intermediate)
  header_list_format_broken[0] = 'satlpack'
  header_format_broken = msgpack.encode(header_list_format_broken)
  try
    await header.parse_encryption_header_packet({decryptor : bob, header_intermediate : header_format_broken}, defer())
  catch error
    T.equal(error.message, "wrong format satlpack")

  # break the version number
  header_list_version_broken = msgpack.decode(header_intermediate)
  header_list_version_broken[1][0] = 0
  header_version_broken = msgpack.encode(header_list_version_broken)
  try
    await header.parse_encryption_header_packet({decryptor : bob, header_intermediate : header_version_broken}, defer())
  catch error
    T.equal(error.message, "wrong version number 0.0")

  # break the mode number
  header_list_mode_broken = msgpack.decode(header_intermediate)
  header_list_mode_broken[2] = 1
  header_mode_broken = msgpack.encode(header_list_mode_broken)
  try
    await header.parse_encryption_header_packet({decryptor : bob, header_intermediate : header_mode_broken}, defer())
  catch error
    T.equal(error.message, "packet wasn't meant for decryption, found mode 1")

  cb()

exports.break_recipients_list = (T, cb) ->
  esc = make_esc(cb, "break_recipients_list")
  {alice, bob} = util.alice_and_bob()
  await generate_anonymous_header(alice, crypto.randomBytes(32), esc(defer({header_intermediate, header_hash, mac_keys, payload_key})))

  try
    await header.parse_encryption_header_packet({decryptor : bob, header_intermediate}, defer())
  catch error
    T.equal(error.message, "You are not a recipient!")

  cb()

#===============================================================================

exports.break_mac_key_in_payload_packet = (T, cb) ->
  esc = make_esc(cb, "break_mac_key_in_payload_packet")
  {alice, bob} = util.alice_and_bob()
  await generate_anonymous_header(alice, bob.publicKey, esc(defer({header_intermediate, header_hash, mac_keys, payload_key})))
  alice.secretKey = payload_key

  await header.parse_encryption_header_packet({decryptor : bob, header_intermediate}, esc(defer({recipient_index})))

  plaintext = crypto.randomBytes(crypto.randomBytes(1)[0]**2)
  await payload.generate_encryption_payload_packet({payload_encryptor : alice, plaintext, block_num : 0, header_hash, mac_keys}, esc(defer(payload_list)))

  # break the MAC key
  await header.parse_encryption_header_packet({decryptor : bob, header_intermediate}, esc(defer({mac_key})))
  mac_key[0] = ~mac_key[0]

  await payload.parse_encryption_payload_packet({decryptor : bob, payload_list, block_num : 0, header_hash, mac_key, recipient_index}, defer(err, _))
  T.equal(err?.message, "Integrity check failed!")

  cb()
