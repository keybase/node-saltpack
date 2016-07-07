{prng} = require('crypto')
main = require('keybase-nacl')
header = require('../../src/header.iced')

exports.test_header_pipeline = (T, cb) ->
  encryptor = main.alloc({force_js : false})
  decryptor = main.alloc({force_js : false})
  encryptor.genBoxPair()
  decryptor.genBoxPair()

  packed_obj = header.generate_encryption_header_packet(encryptor, [prng(32), decryptor.publicKey, prng(32)])
  unpacked_obj = header.parse_encryption_header_packet(decryptor, packed_obj.header_packet)
  T.equal(packed_obj.mac_keys[1], unpacked_obj.mac_key, "MAC keys didn't match: packed key = #{packed_obj.mac_keys[1]}, unpacked key = #{unpacked_obj.mac_key}")
  cb()
