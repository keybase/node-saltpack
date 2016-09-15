EventEmitter = require('events')
stream = require('keybase-chunk-stream')
nacl = require('keybase-nacl')
armor = require('node-armor-x')
msgpack = require('keybase-msgpack-lite')
{make_esc} = require('iced-error')
payload = require('./payload')
header = require('./header')
nonce = require('./nonce')
format = require('./format')

SALTPACK_BLOCK_LEN = (1024**2)
noop = () ->

# This is a raw NaCl stream - it doesn't implement msgpack, armoring, or anything like that. This should only ever be called inside the exposed EncryptStream class
class NaClEncryptStream extends stream.ChunkStream

  # this function encrypts for a specific key, outputting a list object for msgpack. it gets passed in as the transform function to `node-chunk-stream`
  _encrypt : (chunk, cb) =>
    esc = make_esc(cb, "NaClEncryptStream::_encrypt")
    # on the first call, spit out a header packet before writing payload
    if not @_header_written
      args = {
        encryptor: @_encryptor,
        recipients: @_recipients,
        anonymized_recipients: @_anonymized_recipients
      }
      await header.generate_encryption_header_packet(args, esc(defer({header_intermediate, header_hash, mac_keys, payload_key})))
      @_header_hash = header_hash
      @_mac_keys = mac_keys
      unless @_encryptor?
        @_encryptor = nacl.alloc({force_js : false})
      @_encryptor.secretKey = payload_key
      @push(header_intermediate)
      @_header_written = true
    # either way, we want to encrypt the received payload
    args = {
      payload_encryptor: @_encryptor,
      plaintext: chunk,
      block_num: @_block_num,
      header_hash: @_header_hash,
      mac_keys: @_mac_keys
    }
    await payload.generate_encryption_payload_packet(args, esc(defer(payload_list)))
    ++@_block_num
    return cb(null, payload_list)

  # write the empty payload packet
  flush_append : (cb) ->
    esc = make_esc(cb, "NaClEncryptStream::_flush_append")
    await @_encrypt(new Buffer(''), esc(defer(payload_list)))
    return cb(null, payload_list)

  constructor : (@_encryptor, @_recipients, @_anonymized_recipients) ->
    @_header_written = false
    @_block_num = 0
    @_mac_keys = null
    @_header_hash = null
    super({transform_func : @_encrypt, block_size : SALTPACK_BLOCK_LEN, readableObjectMode : true})

# This is a raw NaCl stream - it doesn't implement msgpack, armoring, or anything like that. This should only ever be called inside the exposed EncryptStream class
class NaClDecryptStream extends require('stream').Transform

  # as above, this function encrypts for a specific key and is passed to `node-chunk-stream`
  _decrypt : (chunk, cb) =>
    esc = make_esc(cb, "NaClDecryptStream::_decrypt")
    args = {
      payload_decryptor: @_decryptor,
      payload_list: chunk,
      block_num: @_block_num,
      header_hash: @_header_hash,
      mac_key: @_mac_key,
      recipient_index: @_recipient_index
    }
    await payload.parse_encryption_payload_packet(args, esc(defer(payload_text)))
    ++@_block_num
    return cb(null, payload_text)

  _transform_chunk : (chunk, cb) =>
    esc = make_esc(cb, "NaClDecryptStream::_transform_chunk")

  # as above, this function parses the header on the first call and defers to `node-chunk-stream` on subsequent calls
  _transform : (chunk, encoding, cb) ->
    esc = make_esc(cb, "NaClDecryptStream::_transform")
    if chunk.length is 0
      return cb(null, null)
    if @_header_read
      await @_decrypt(chunk, esc(defer(out)))
      if out.length is 0
        @_found_empty_ending_packet = true
      return cb(null, out)
    else
      await header.parse_encryption_header_packet({decryptor : @_decryptor, header_intermediate : chunk}, esc(defer({header_hash, payload_key, mac_key, recipient_index})))
      @_header_hash = header_hash
      @_decryptor.secretKey = payload_key
      @_mac_key = mac_key
      @_recipient_index = recipient_index
      @_header_read = true
      return cb(null, null)

  _flush : (cb) ->
    # detect truncation attacks
    if not @_found_empty_ending_packet
      return cb(new Error("Message was truncated"), null)
    return cb(null, null)

  constructor : (@_decryptor) ->
    @_header_read = false
    @_header_hash = null
    @_found_empty_ending_packet = false
    @_mac_key = null
    @_recipient_index = -1
    @_block_num = 0
    super({writableObjectMode : true, readableObjectMode : false})

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

class StreamWrapper extends EventEmitter
  constructor : (streams) ->
    # pipe everything together
    len = streams.length
    for i in [0...len-1]
      streams[i].pipe(streams[i+1])

    # expose the first and last streams
    @first_stream = streams[0]
    @last_stream = streams[len-1]

    # attach error listeners to each stream
    for stream in streams
      stream.on('error', (err) => @emit('error', err))

    # attach end listener to last stream
    @last_stream.on('finish', () => @emit('finish'))

  write : (chunk) ->
    @first_stream.write(chunk)

  pipe : (dest) ->
    @last_stream.pipe(dest)
    return dest

  end : () ->
    @first_stream.end()

exports.EncryptStream = class EncryptStream extends StreamWrapper
  constructor : ({encryptor, do_armoring, recipients, anonymized_recipients}) ->
    # put each of the streams we need into an array
    internals = []
    internals.push(new NaClEncryptStream(encryptor, recipients, anonymized_recipients))
    internals.push(msgpack.createEncodeStream())

    # if we need to armor, we need to put streams onto the end of the array ('push')
    if do_armoring
      internals.push(new armor.stream.StreamEncoder(armor.encoding.b62.encoding))
      internals.push(new format.FormatStream({}))

    super(internals)

exports.DecryptStream = class DecryptStream extends StreamWrapper
  constructor : ({decryptor, do_armoring}) ->
    # put each of the streams we need into an array
    internals = []
    internals.push(msgpack.createDecodeStream())
    internals.push(new NaClDecryptStream(decryptor))

    # if we need to armor, we need to put streams onto the front of the array ('unshift')
    if do_armoring
      internals.unshift(new armor.stream.StreamDecoder(armor.encoding.b62.encoding))
      internals.unshift(new format.DeformatStream({}))

    super(internals)
