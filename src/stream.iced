stream = require('keybase-chunk-stream')
nacl = require('keybase-nacl')
armor = require('node-armor-x')
msgpack = require('keybase-msgpack-lite')
payload = require('./payload')
header = require('./header')
nonce = require('./nonce')
format = require('./format')

SALTPACK_BLOCK_LEN = (1024**2)
noop = () ->

# This is a raw NaCl stream - it doesn't implement msgpack, armoring, or anything like that. This should only ever be called inside the exposed EncryptStream class
class NaClEncryptStream extends stream.ChunkStream

  # this function encrypts for a specific key, outputting a list object for msgpack. it gets passed in as the transform function to `node-chunk-stream`
  _encrypt : (chunk) =>
    payload_list = payload.generate_encryption_payload_packet({payload_encryptor : @_encryptor, plaintext : chunk, block_num : @_block_num, header_hash : @_header_hash, mac_keys : @_mac_keys})
    ++@_block_num
    return payload_list

  # very simple wrapper over `node-chunk-stream` - on the first call, it writes a header before writing the first packet, and on all subsequent calls simply defers to `node-chunk-stream`
  _transform : (chunk, encoding, cb) ->
    if not @_header_written
      {header_intermediate, header_hash, mac_keys, payload_key} = header.generate_encryption_header_packet({encryptor : @_encryptor, recipients : @_recipients, anonymized_recipients : @_anonymized_recipients})
      @_header_hash = header_hash
      @_mac_keys = mac_keys
      unless @_encryptor?
        @_encryptor = nacl.alloc({force_js : false})
      @_encryptor.secretKey = payload_key
      @push(header_intermediate)
      @_header_written = true
    super(chunk, encoding, cb)

  # have `node-chunk-stream` flush without exiting (hence the no-op), then write the empty payload packet
  _flush : (cb) ->
    super(noop)
    @push(@_encrypt(new Buffer('')))
    cb()

  constructor : (@_encryptor, @_recipients, @_anonymized_recipients) ->
    @_header_written = false
    @_block_num = 0
    @_mac_keys = null
    @_header_hash = null
    super({transform_func : @_encrypt, block_size : SALTPACK_BLOCK_LEN, exact_chunking : true, writableObjectMode : false, readableObjectMode : true})



# This is a raw NaCl stream - it doesn't implement msgpack, armoring, or anything like that. This should only ever be called inside the exposed EncryptStream class
class NaClDecryptStream extends stream.ChunkStream

  # as above, this function encrypts for a specific key and is passed to `node-chunk-stream`
  _decrypt : (chunk) =>
    payload_text = payload.parse_encryption_payload_packet({payload_decryptor : @_decryptor, payload_list : chunk, block_num : @_block_num, header_hash : @_header_hash, mac_key : @_mac_key, recipient_index : @_recipient_index})
    ++@_block_num
    return payload_text

  # as above, this function parses the header on the first call and defers to `node-chunk-stream` on subsequent calls
  _transform : (chunk, encoding, cb) ->
    if @_header_read
      super(chunk, encoding, cb)
    else
      {_, header_hash, payload_key, _, mac_key, recipient_index} = header.parse_encryption_header_packet({decryptor : @_decryptor, header_intermediate : chunk})
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
    super({transform_func : @_decrypt, block_size : SALTPACK_BLOCK_LEN, exact_chunking : true, writableObjectMode : true, readableObjectMode : false})

#===========================================================

# The two classes below are the meat and potatoes of this repo: they snap several streams together in a modular fashion to give a full saltpack pipeline
# Each of the two classes contain the following components:
#   - a nacl_stream which does the raw crypto
#   - an (un)pack_stream which does the msgpack {en,de}coding
# When run in armoring mode, each class also contains the following components:
#   - an armor stream which base62's the output
#   - a format stream which frames the payload and inserts spaces/line breaks where appropriate
# Both classes try to mimic stream-like interfaces:
#   - calling `stream.write(chunk, cb)` will write to the first stream in the pipeline
#   - calling `stream.end(cb)` will attach an end listener to the last stream in the pipeline and end the first stream - the callback will fire when all streams have ended
#   - calling `stream.pipe(dest)` will pipe the last stream in the pipeline to the given destination
#   - notably missing: it's not possible to do `other_stream.pipe(stream)`, instead use `other_stream.pipe(stream.first_stream)`

#===========================================================

exports.EncryptStream = class EncryptStream
  constructor : ({encryptor, do_armoring, recipients, anonymized_recipients}) ->
    @_internals = {}
    @_internals.nacl_stream = new NaClEncryptStream(encryptor, recipients, anonymized_recipients)
    @first_stream = @_internals.nacl_stream
    @_internals.pack_stream = msgpack.createEncodeStream()
    @_internals.nacl_stream.pipe(@_internals.pack_stream)
    @last_stream = @_internals.pack_stream
    if do_armoring
      @_internals.armor_stream = new armor.stream.StreamEncoder(armor.encoding.b62.encoding)
      @_internals.format_stream = new format.FormatStream({})
      @_internals.pack_stream.pipe(@_internals.armor_stream).pipe(@_internals.format_stream)
      @last_stream = @_internals.format_stream

  write : (plaintext, cb) ->
    @first_stream.write(plaintext)
    cb()

  end : (cb) ->
    @last_stream.on('finish', cb)
    @first_stream.end()

  pipe : (dest) ->
    @last_stream.pipe(dest)

exports.DecryptStream = class DecryptStream
  constructor : ({decryptor, do_armoring}) ->
    @_internals = {}
    @_internals.unpack_stream = msgpack.createDecodeStream()
    @_internals.nacl_stream = new NaClDecryptStream(decryptor)
    @last_stream = @_internals.nacl_stream
    @_internals.unpack_stream.pipe(@_internals.nacl_stream)
    @first_stream = @_internals.unpack_stream
    if do_armoring
      @_internals.deformat_stream = new format.DeformatStream({})
      @_internals.dearmor_stream = new armor.stream.StreamDecoder(armor.encoding.b62.encoding)
      @_internals.deformat_stream.pipe(@_internals.dearmor_stream).pipe(@_internals.unpack_stream)
      @first_stream = @_internals.deformat_stream

  write : (plaintext, cb) ->
    @first_stream.write(plaintext)
    cb()

  end : (cb) ->
    @last_stream.on('finish', cb)
    @first_stream.end()

  pipe : (dest) ->
    @last_stream.pipe(dest)
