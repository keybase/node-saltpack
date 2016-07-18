nacl = require('keybase-nacl')
msgpack = require('msgpack-lite')
stream = require('../../src/stream.iced')
to_buf = require('../../src/stream-to-buffer.iced')
{prng} = require('crypto')

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
    recipients_list.push(prng(32))
  recipients_list[recipient_index] = pk
  return {recipients_list, recipient_index}

# writes random data in random chunk sizes to the given stream
stream_random_data = (strm, len) ->
  data = prng(len)
  i = 0
  j = 0
  while j < data.length
    j = i + prng(1)[0]**3
    strm.write(data[i...j])
    i = j
  strm.end()
  data

random_megabyte_to_ten = () -> Math.floor((1024**2)*(Math.random()*9)+1)

# Test NaCl
exports.test_nacl_pipeline = (T, cb) ->
  {alice, bob} = alice_and_bob()
  {recipients_list, recipient_index} = gen_recipients(bob.publicKey)
  encryptor = new stream.NaClEncryptStream(alice, recipients_list)
  packer = msgpack.createEncodeStream()
  unpacker = msgpack.createDecodeStream()
  decryptor = new stream.NaClDecryptStream(bob)
  stb = new to_buf.StreamToBuffer()

  encryptor.pipe(decryptor)
  decryptor.pipe(stb)
  data = stream_random_data(encryptor, random_megabyte_to_ten())
  out = stb.getBuffer()
  T.equal(data.length, out.length, 'Truncation or garbage bytes')
  T.equal(data, out, 'Plaintext mismatch')
  cb()
