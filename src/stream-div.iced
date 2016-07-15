stream = require('keybase-chunk-stream')
nacl = require('keybase-nacl')
armor = require('node-armor-x')
payload = require('./payload.iced')
header = require('./header.iced')
nonce = require('./nonce.iced')

saltpack_block_len = (1024**2)
noop = () ->

exports.NaClEncryptStream = class NaClEncryptStream extends stream.ChunkStream
  _encrypt : (chunk) =>
    payload_list = payload.generate_encryption_payload_packet(@_encryptor, chunk, @_block_num, @_header_hash, @_mac_keys)
    ++@_block_num
    return payload_list

  _transform : (chunk, encoding, cb) ->
    if not @_header_written
      {header_intermediate, @_header_hash, @_mac_keys, payload_key} = header.generate_encryption_header_packet(@_encryptor, @_recipients)
      @_encryptor.secretKey = payload_key
      @push(header_intermediate)
      @_header_written = true
    super(chunk, encoding, cb)

  _flush : (chunk, encoding, cb) ->
    super(noop)
    @push(@_encrypt(new Buffer('')))
    cb()

  constructor : (@_encryptor, @_recipients) ->
    @header_written = false
    @block_num = 0
    @mac_keys = null
    @header_hash = null
    super(@_encrypt, saltpack_block_len, true, {writableObjectMode : false, readableObjectMode : true})
