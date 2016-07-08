{prng} = require('crypto')
{createHash} = require('crypto')
msgpack = require('purepack')
crypto = require('keybase-nacl')
nonce = require('./nonce.iced')

compute_mac_key = (encryptor, header_hash, pubkey) ->
  zero_bytes = Buffer.alloc(32)
  mac_box = encryptor.encrypt({plaintext : zero_bytes, nonce : nonce.nonceForMACKeyBox(header_hash), pubkey})
  return mac_box.slice(-32)

exports.generate_encryption_header_packet = (encryptor, recipients) ->
  mode = 0
  header_list = []
  header_list.push('saltpack')
  header_list.push([1, 0])
  header_list.push(mode)

  payload_encryptor = crypto.alloc({force_js : true})
  payload_key = prng(32)
  payload_encryptor.secretKey = payload_key
  ephemeral_encryptor = crypto.alloc({force_js : true})
  ephemeral_encryptor.genBoxPair()
  header_list.push(ephemeral_encryptor.publicKey)

  sender_sbox = payload_encryptor.secretbox({plaintext : encryptor.publicKey, nonce : nonce.nonceForSenderKeySecretBox()})
  header_list.push(sender_sbox)

  recipients_list = []
  for rec_pubkey in recipients
    rec_pair = []
    rec_pair.push(rec_pubkey)
    rec_payload = ephemeral_encryptor.encrypt({plaintext : payload_key, nonce : nonce.nonceForPayloadKeyBox(), pubkey : rec_pubkey})
    rec_pair.push(rec_payload)
    recipients_list.push(rec_pair)
  header_list.push(recipients_list)

  crypto_hash = createHash('sha512')
  header_intermediate = msgpack.pack(header_list)
  crypto_hash.update(header_intermediate)
  header_hash = crypto_hash.digest()
  header_packet = msgpack.pack(header_intermediate)

  mac_keys = []
  for rec_pubkey in recipients
    mac_keys.push(compute_mac_key(encryptor, header_hash, rec_pubkey))

  return {header_packet, mac_keys}



exports.parse_encryption_header_packet = (decryptor, header_packet) ->
  #unpack header
  crypto_hash = createHash('sha512')
  header_intermediate = msgpack.unpack(header_packet)
  crypto_hash.update(header_intermediate)
  header_hash = crypto_hash.digest()
  header_list = msgpack.unpack(header_intermediate)

  #sanity checking
  if header_list[0] isnt 'saltpack' then throw new Error("wrong format #{header_list[0]}")
  if header_list[1][0] isnt 1 or header_list[1][1] isnt 0 then throw new Error("wrong version number #{header_list[1][0]}.#{header_list[1][1]}")
  if header_list[2] isnt 0 then throw new Error("packet wasn't meant for decryption, found mode #{header_list[2]}")

  #precompute ephemeral shared secret
  secret = decryptor.box_beforenm({pubkey : header_list[3], seckey : decryptor.secretKey})

  #find the payload key box
  found = false
  payload_key = new Buffer([])
  for rec_pair in header_list[5]
    if rec_pair[0] is decryptor.publicKey
      payload_key = decryptor.box_open_afternm({ciphertext : rec_pair[1], nonce : nonce.nonceForPayloadKeyBox(), secret})
      found = true

  if not found then for rec_pair in header_list[5]
    try
      payload_key = decryptor.box_open_afternm({ciphertext : rec_pair[1], nonce : nonce.nonceForPayloadKeyBox(), secret})
    catch error
      continue

  if payload_key.length is 0 then throw new Error('You are not a recipient!')

  #open the sender secretbox
  payload_decryptor = crypto.alloc({force_js : false})
  payload_decryptor.secretKey = payload_key
  sender_pubkey = payload_decryptor.secretbox_open({ciphertext : header_list[4], nonce : nonce.nonceForSenderKeySecretBox()})

  #compute the MAC key
  mac_key = compute_mac_key(decryptor, header_hash, sender_pubkey)

  return {header_packet, mac_key}
