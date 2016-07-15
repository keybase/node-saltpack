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
    payload_list = payload.generate_encryption_payload_packet(@encryptor, chunk, @block_num, @header_hash, @mac_keys)
    ++@block_num
    return payload_list

  constructor : (pk, sk, @recipients) ->
    @encryptor = nacl.alloc({force_js : false})
    @encryptor.publicKey = pk
    @encryptor.secretKey = sk

    @header_written = false
    @header_hash = null
    @mac_keys = null
    @block_num = 0
    super(@_encrypt, saltpack_block_len, true, {writableObjectMode : false, readableObjectMode : true})

  _transform : (chunk, encoding, cb) ->
    if @header_written
      super(chunk, encoding, cb)
    else
      {header_intermediate, @header_hash, @mac_keys, payload_key} = header.generate_encryption_header_packet(@encryptor, @recipients)
      @encryptor.secretKey = payload_key
      @push(msgpack.encode(header_intermediate))
      @header_written = true
      cb()

  _flush : (cb) ->
    super(noop)
    @push(@_encrypt(new Buffer('')))
    cb()

class NaClDecryptStream extends stream.ChunkStream
  decrypt = (chunk) ->
    ciphertext = parse_payload_packet(chunk, @header_hash, @mac_key, 'foo', @block_num)
    payload = @decryptor.secretbox_open({ciphertext, nonce : nonce.nonceForChunkSecretBox(@block_num)})
    ++@block_num
    return payload

  constructor : (pk, sk) ->
    @decryptor = nacl.alloc({force_js : false})
    @decryptor.publicKey = pk
    @decryptor.secretKey = sk

    @header_read = false
    @header_hash = null
    @mac_key = null
    @auth_index = null
    @block_num = 0
    super(decrypt, saltpack_block_len, true, {writableObjectMode : false, readableObjectMode : true})

  _transform : (chunk, encoding, cb) ->
    if @header_read
      super(chunk, encoding, cb)
    else
      {_, @header_hash, payload_key, _, @mac_key, @auth_index} = header.parse_encryption_header_packet(@decryptor, chunk)
      # now we can switch to using the payload key, no need for the real secret key
      @decryptor.secretKey = payload_key
      @header_read = true
      cb()

#===============================================================================

exports.EncryptStream = class EncryptStream
  constructor : (pk, sk, recipients, do_armoring) ->
    @nacl_stream = new NaClEncryptStream(pk, sk, recipients)
    @pack_stream = msgpack.createEncodeStream()
    @last_stream = @pack_stream
    @nacl_stream.pipe(@pack_stream)
    if do_armoring
      @armor_stream = new armor.stream.StreamEncoder(armor.encoding.b62.encoding)
      @pack_stream.pipe(@armor_stream)
      @last_stream = @armor_stream

  pipe : (dest) -> @last_stream.pipe(dest)
  read : (size) -> @last_stream.read(size)
  write : (chunk) -> @nacl_stream.write(chunk)
  end : () -> @nacl_stream.end()

exports.DecryptStream = class DecryptStream
  constructor : (pk, sk, do_armoring) ->
    @unpack_stream = msgpack.createDecodeStream()
    @first_stream = @unpack_stream
    if do_armoring
      @armor_stream = new armor.stream.StreamDecoder(armor.encoding.b62.encoding)
      @armor_stream.pipe(@unpack_stream)
      @first_stream = @armor_stream
    @nacl_stream = new NaClDecryptStream(pk, sk)
    @unpack_stream.pipe(@nacl_stream)

  pipe : (dest) -> @nacl_stream.pipe(dest)
  read : (size) -> @nacl_stream.read(size)
  write : (chunk) -> @first_stream.write(chunk)
  end : () -> @first_stream.end()
