{prng} = require('crypto')
main = require('keybase-nacl')
header = require('../../src/header.iced')

exports.test_header_pipeline = (T, cb) ->
  encryptor = main.alloc({force_js : false})
  decryptor = main.alloc({force_js : false})
  encryptor.genBoxPair()
  decryptor.genBoxPair()

  random_index = prng(1)[0]
  recipients_list = []
  for i in [0...random_index*2]
    recipients_list.push(prng(32))
  recipients_list[random_index] = decryptor.publicKey

  packed_obj = header.generate_encryption_header_packet(encryptor, recipients_list)
  unpacked_obj = header.parse_encryption_header_packet(decryptor, packed_obj.header_packet)

  T.equal(packed_obj.mac_keys[random_index], unpacked_obj.mac_key, "MAC keys didn't match: packed key = #{packed_obj.mac_keys[random_index]}, unpacked key = #{unpacked_obj.mac_key}")
  cb()
