nacl = require('keybase-nacl')
msgpack = require('msgpack-lite')
stream = require('../../src/stream.iced')
to_buf = require('../../src/stream-to-buffer.iced')
crypto = require('crypto')

#==========================================================
#Helper functions
#==========================================================

# generates two keypairs, named alice and bob
alice_and_bob = () ->
  alice = nacl.alloc({force_js : false})
  bob = nacl.alloc({force_js : true})
  alice.genBoxPair()
  bob.genBoxPair()
  return {alice, bob}

# generates a random recipients list with the specified public key inserted somewhere and junk everywhere else
gen_recipients = (pk) ->
  recipient_index = Math.ceil(Math.random()*20)
  recipients_list = []
  for i in [0...(recipient_index + 2)]
    recipients_list.push(crypto.randomBytes(32))
  recipients_list[recipient_index] = pk
  return {recipients_list, recipient_index}

# writes random data in random chunk sizes to the given stream
stream_random_data = (strm, len, cb) ->
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
    await strm.write(buf, defer(err))
    if err then throw err

  cb(Buffer.concat(expected_results))

random_megabyte_to_ten = () -> Math.floor((1024**2)*(Math.random()*9)+1)

# Test NaCl
_test_saltpack_pipeline = (do_armor, T, cb) ->
  {alice, bob} = alice_and_bob()
  {recipients_list, recipient_index} = gen_recipients(bob.publicKey)
  es = new stream.EncryptStream(alice, recipients_list, do_armor)
  ds = new stream.DecryptStream(bob, do_armor)
  stb = new to_buf.StreamToBuffer()
  es.pipe(ds.first_stream)
  ds.pipe(stb)

  await stream_random_data(es, random_megabyte_to_ten(), defer(data))
  await
    stb.on('finish', defer())
    es.end(() ->)

  out = stb.getBuffer()
  T.equal(data.length, out.length, 'Truncation or garbage bytes')
  T.equal(data, out, 'Plaintext mismatch')
  cb()

#exports.test_saltpack_with_armor = (T, cb) ->
#  await _test_saltpack_pipeline(true, T, defer())
#  cb()

exports.test_saltpack_without_armor = (T, cb) ->
  await _test_saltpack_pipeline(false, T, defer())
  cb()

exports.test_real_saltpack = (T, cb) ->
  {alice, bob} = alice_and_bob()
  key = new Buffer('2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74', 'hex')
  bob.publicKey = key
  es = new stream.EncryptStream(alice, [key], true)
  stb = new to_buf.StreamToBuffer()
  es.pipe(stb)
  message = new Buffer('If you please--draw me a sheep!')
  await es.write(message, defer(err))
  if err then throw err
  await
    stb.on('finish', defer())
    es.end(() ->)
  console.log(stb.getBuffer().toString())
  cb()
