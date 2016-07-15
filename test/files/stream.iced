armor = require('node-armor-x')
nacl = require('keybase-nacl')
stream = require('../../src/stream-div.iced')
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
  recipient_index = prng(1)[0]
  recipients_list = []
  for i in [0...(recipient_index + prng(1)[0])]
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

random_megabyte_to_ten = () -> (1024**2)*(Math.floor(Math.random()*9)+1)

# Test NaCl
exports.test_nacl_encrypt_stream = (T, cb) ->
  {alice, bob} = alice_and_bob()
  {recipients_list, recipient_index} = gen_recipients(bob.publicKey)
  enc = new stream.NaClEncryptStream(alice, recipients_list)
  stb = new to_buf.StreamToBuffer()
  enc.pipe(stb)
  data = stream_random_data(enc, random_megabyte_to_ten())
  console.log('BUFFER BELOW')
  console.log(stb.getBuffer())
  cb()

#==========================================================
#Tests an entire saltpack pipeline
#==========================================================

test_encrypt_pack_armor = (T, cb) ->
  {alice, _} = alice_and_bob()
  encryptor = new stream.EncryptStream(alice.publicKey, alice.secretKey, gen_recipients(prng(32)), true)
  stb = new to_buf.StreamToBuffer()
  encryptor.nacl_stream.pipe(stb)
  input = stream_random_data(encryptor.nacl_stream, random_megabyte_to_ten())
  output = stb.getBuffer()
  console.log(output)
  cb()

test_encrypt_pack_armor_dearmor_unpack_decrypt = (T, cb) ->
  {alice, bob} = alice_and_bob()
  
  encryptor = new stream.EncryptStream(alice.publicKey, alice.secretKey, gen_recipients(bob.publicKey), true)
  decryptor = new stream.DecryptStream(bob.publicKey, bob.secretKey, true)
  stb = new to_buf.StreamToBuffer()
  encryptor.pipe(decryptor.first_stream)
  decryptor.pipe(stb)
  input = stream_random_data(encryptor.nacl_stream, prng(1)[0]*2)
  output = stb.getBuffer()
  T.equal(input, output, "Pipeline failed")
  cb()
