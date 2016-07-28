crypto = require('crypto')
nacl = require('keybase-nacl')
saltpack = require('../..')

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
  return recipients_list

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

#===============================================================================

exports.break_encryption_payload_packet = (T, cb) ->
  header = saltpack.lowlevel.header
  payload = saltpack.lowlevel.payload
  {payload_encryptor, _} = alice_and_bob()
  plaintext = crypto.randomBytes(crypto.randomBytes(1)[0]**2)
  dummy_header = header.generate_encryption_header_packet(
  payload_packet = payload.generate_encryption_payload_packet(payload_encryptor, plaintext, 0, header_hash, 
