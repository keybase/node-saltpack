stream = require('keybase-chunk-stream')
nacl = require('keybase-nacl')
payload = require('./payload.iced')
header = require('./header.iced')
nonce = require('./nonce.iced')

saltpack_block_len = (1024**2)
noop = () ->

exports.EncryptStream = class EncryptStream extends stream.ChunkStream
  encrypt = (chunk) ->
    payload_secretbox = @encryptor.secretbox({plaintext : chunk, nonce : nonce.nonceForChunkSecretBox(@block_num)})
    {_, payload_packet} = payload.generate_encryption_payload_packet(@header_hash, @mac_keys, payload_secretbox, @block_num)
    ++@block_num
    return payload_packet

  constructor : (pk, sk, @recipients) ->
    @encryptor = nacl.alloc({force_js : false})
    @encryptor.publicKey = pk
    @encryptor.secretKey = sk

    @header_written = false
    @header_hash = null
    @mac_keys = null
    @block_num = 0
    super(encrypt, saltpack_block_len, true)

  _transform : (chunk, encoding, cb) ->
    if not @header_written
      {_, @header_hash, header_packet, @mac_keys} = header.generate_encryption_header_packet(@encryptor, @recipients)
      @push(header_packet)
      @header_written = true
      cb()
    else
      super(chunk, encoding, cb)

  _flush : (cb) ->
    super(noop)
    @push(encrypt(new Buffer('')))
    cb()

#===============================================================================

exports.DecryptStream = class DecryptStream extends stream.ChunkStream
  decrypt = (chunk) ->
    ciphertext = parse_payload_packet(chunk, @header_hash, @mac_key, 'foo', @block_num)
    payload = @decryptor.secretbox_open({ciphertext, nonce : nonce.nonceForChunkSecretBox(@block_num)})
    ++@block_num
    return payload

  constructor : (pk, sk) ->
    @decryptor = nacl.alloc({force_js : false})

    @header_read = false
    @header_hash = null
    @mac_key = null
    @auth_index = null
    @block_num = 0
    super(decrypt, saltpack_block_len, true)

  _transform : (chunk, encoding, cb) ->
    if not @header_read
      {@header_hash, _, seckey, @mac_key} = header.parse_encryption_header_packet(@decryptor, msgpack.encode(chunk))
      @decryptor.secretKey = seckey
      @header_read = true
      cb()
    else
      super(chunk, encoding, cb)
