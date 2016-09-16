stream = require('stream')
crypto = require('crypto')
nacl = require('keybase-nacl')

# Constant-time buffer comparison
exports.bufeq_secure = (x,y) ->
  ret = if not x? and not y? then true
  else if not x? or not y? then false
  else if x.length isnt y.length then false
  else
    check = 0
    for i in [0...x.length]
      check |= (x.readUInt8(i) ^ y.readUInt8(i))
    (check is 0)
  ret

# generates two keypairs, named alice and bob
exports.alice_and_bob = (opts) ->
  if opts?.force_js? then force_js = opts.force_js else force_js = false
  alice = nacl.alloc({force_js})
  bob = nacl.alloc({force_js})
  alice.genBoxPair()
  bob.genBoxPair()
  {alice, bob}

# generates a random recipients list with the specified public key inserted somewhere and junk everywhere else
exports.gen_recipients = (pk) ->
  recipient_index = Math.ceil(Math.random()*20)
  recipients_list = []
  for i in [0...(recipient_index + 2)]
    recipients_list.push(crypto.randomBytes(32))
  recipients_list[recipient_index] = pk
  recipients_list

# writes random data in random chunk sizes to the given stream
exports.stream_random_data = (strm, len, cb) ->
  written = 0
  expected_results = []
  while written < len
    # generate random length
    await crypto.randomBytes(1, defer(err, index))
    if err then throw err
    amt = (index[0] + 1)*16

    # generate random bytes of length amt
    await crypto.randomBytes(amt, defer(err, buf))
    if err then throw err
    written += buf.length
    expected_results.push(buf)

    # write the buffer
    strm.write(buf)
  cb(Buffer.concat(expected_results))

exports.random_megabyte_to_ten = () -> Math.floor((1024**2)*(Math.random()*9)+1)

# A very simple transform stream that puts everything in a buffer for easy testing
exports.StreamToBuffer = class StreamToBuffer extends stream.Transform

  constructor : (options) ->
    @bufs = []
    super(options)

  _write : (chunk, encoding, cb) ->
    @bufs.push(chunk)
    cb()

  getBuffer : () ->
    Buffer.concat(@bufs)
