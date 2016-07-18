stream = require('keybase-chunk-stream')
nacl = require('keybase-nacl')
armor = require('node-armor-x')
msgpack = require('msgpack-lite')
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
      {header_intermediate, header_hash, mac_keys, payload_key} = header.generate_encryption_header_packet(@_encryptor, @_recipients)
      @_header_hash = header_hash
      @_mac_keys = mac_keys
      @_encryptor.secretKey = payload_key
      @push(header_intermediate)
      @_header_written = true
    super(chunk, encoding, cb)

  _flush : (cb) ->
    super(noop)
    @push(@_encrypt(new Buffer('')))
    cb()

  constructor : (@_encryptor, @_recipients) ->
    @_header_written = false
    @_block_num = 0
    @_mac_keys = null
    @_header_hash = null
    super(@_encrypt, saltpack_block_len, true, {writableObjectMode : false, readableObjectMode : true})

exports.NaClDecryptStream = class NaClDecryptStream extends stream.ChunkStream
  _decrypt : (chunk) =>
    payload_text = payload.parse_encryption_payload_packet(@_decryptor, chunk, @_block_num, @_header_hash, @_mac_key, @_recipient_index)
    ++@_block_num
    return payload_text

  _transform : (chunk, encoding, cb) ->
    if @_header_read
      super(chunk, encoding, cb)
    else
      {_, header_hash, payload_key, _, mac_key, recipient_index} = header.parse_encryption_header_packet(@_decryptor, chunk)
      @_header_hash = header_hash
      @_decryptor.secretKey = payload_key
      @_mac_key = mac_key
      @_recipient_index = recipient_index
      @_header_read = true
      cb()

  constructor : (@_decryptor) ->
    @_header_read = false
    @_header_hash = null
    @_mac_key = null
    @_recipient_index = -1
    @_block_num = 0
    super(@_decrypt, saltpack_block_len, true, {writableObjectMode : true, readableObjectMode : false})
