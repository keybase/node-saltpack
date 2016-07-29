stream = require('keybase-chunk-stream')
nacl = require('keybase-nacl')
armor = require('node-armor-x')
msgpack = require('msgpack-lite')
payload = require('./payload')
header = require('./header')
nonce = require('./nonce')
format = require('./format')

saltpack_block_len = (1024**2)
noop = () ->

class NaClEncryptStream extends stream.ChunkStream
  _encrypt : (chunk) =>
    payload_list = payload.generate_encryption_payload_packet(@_encryptor, chunk, @_block_num, @_header_hash, @_mac_keys)
    ++@_block_num
    return payload_list

  _transform : (chunk, encoding, cb) ->
    if not @_header_written
      {header_intermediate, header_hash, mac_keys, payload_key} = header.generate_encryption_header_packet(@_encryptor, @_recipients, {anonymized_recipients : @_anonymized_recipients})
      @_header_hash = header_hash
      @_mac_keys = mac_keys
      @_encryptor.secretKey = payload_key
      @push(header_intermediate)
      @_header_written = true
    super(chunk, encoding, cb)

  _flush : (cb) ->
    super(noop)
    @push(@_encrypt(Buffer.from('')))
    cb()

  constructor : (@_encryptor, @_recipients, @_anonymized_recipients) ->
    @_header_written = false
    @_block_num = 0
    @_mac_keys = null
    @_header_hash = null
    super(@_encrypt, {block_size : saltpack_block_len, exact_chunking : true, writableObjectMode : false, readableObjectMode : true})

class NaClDecryptStream extends stream.ChunkStream
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
    super(@_decrypt, {block_size : saltpack_block_len, exact_chunking : true, writableObjectMode : true, readableObjectMode : false})

#===========================================================

exports.EncryptStream = class EncryptStream
  constructor : ({encryptor, do_armoring, recipients, anonymized_recipients}) ->
    @nacl_stream = new NaClEncryptStream(encryptor, recipients, anonymized_recipients)
    @pack_stream = msgpack.createEncodeStream()
    @nacl_stream.pipe(@pack_stream)
    @last_stream = @pack_stream
    if do_armoring
      @armor_stream = new armor.stream.StreamEncoder(armor.encoding.b62.encoding)
      @format_stream = new format.FormatStream()
      @pack_stream.pipe(@armor_stream).pipe(@format_stream)
      @last_stream = @format_stream

  write : (plaintext, cb) ->
    @nacl_stream.write(plaintext)
    cb()

  end : (cb) ->
    # attaches an end listener to the last stream, and closes the first stream. the callback is executed when all streams close
    @last_stream.on('finish', cb)
    @nacl_stream.end()

  pipe : (dest) ->
    @last_stream.pipe(dest)

exports.DecryptStream = class DecryptStream
  constructor : ({decryptor, do_armoring}) ->
    @unpack_stream = msgpack.createDecodeStream()
    @nacl_stream = new NaClDecryptStream(decryptor)
    @unpack_stream.pipe(@nacl_stream)
    @first_stream = @unpack_stream
    if do_armoring
      @deformat_stream = new format.DeformatStream()
      @dearmor_stream = new armor.stream.StreamDecoder(armor.encoding.b62.encoding)
      @deformat_stream.pipe(@dearmor_stream).pipe(@unpack_stream)
      @first_stream = @deformat_stream

  write : (plaintext, cb) ->
    @first_stream.write(plaintext)
    cb()

  end : (cb) ->
    @nacl_stream.on('finish', cb)
    @first_stream.end()

  pipe : (dest) ->
    @nacl_stream.pipe(dest)
