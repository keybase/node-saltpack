{prng} = require('crypto')
{createHash} = require('crypto')
msgpack = require('msgpack-lite')
crypto = require('keybase-nacl')
nonce = require('./nonce.iced')
util = require('./util.iced')

encryption_mode = 0
attached_sign_mode = 1
detached_sign_mode = 2
current_major = 1
current_minor = 0
crypto_auth_KEYBYTES = 32
crypto_secretbox_KEYBYTES = 32

compute_mac_key = (encryptor, header_hash, pubkey) ->
  zero_bytes = Buffer.alloc(crypto_auth_KEYBYTES)
  mac_box = encryptor.encrypt({plaintext : zero_bytes, nonce : nonce.nonceForMACKeyBox(header_hash), pubkey})
  # take last crypto_auth_BYTES bytes of MAC box
  return mac_box.slice(-crypto_auth_KEYBYTES)

exports.generate_encryption_header_packet = (encryptor, recipients) ->
  header_list = []
  header_list.push('saltpack')
  header_list.push([current_major, current_minor])
  header_list.push(encryption_mode)

  payload_encryptor = crypto.alloc({force_js : true})
  payload_key = prng(crypto_secretbox_KEYBYTES)
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
  header_intermediate = msgpack.encode(header_list)
  crypto_hash.update(header_intermediate)
  header_hash = crypto_hash.digest()

  mac_keys = []
  for rec_pubkey in recipients
    mac_keys.push(compute_mac_key(encryptor, header_hash, rec_pubkey))

  return {header_intermediate, header_hash, mac_keys}

exports.parse_encryption_header_packet = (decryptor, header_intermediate) ->
  #unpack header
  crypto_hash = createHash('sha512')
  crypto_hash.update(header_intermediate)
  header_hash = crypto_hash.digest()
  header_list = msgpack.decode(header_intermediate)
  [format, [major, minor], mode, ephemeral, sender, recipients] = header_list

  #sanity checking
  if format isnt 'saltpack' then throw new Error("wrong format #{format}")
  if major isnt current_major then throw new Error("wrong version number #{major}.#{minor}")
  if mode isnt encryption_mode then throw new Error("packet wasn't meant for decryption, found mode #{mode}")

  #precompute ephemeral shared secret
  secret = decryptor.box_beforenm({pubkey : ephemeral, seckey : decryptor.secretKey})

  #find the payload key box
  found = false
  payload_key = null
  for recipient_index in [0...recipients.length]
    if util.bufeq_secure(recipients[recipient_index][0], decryptor.publicKey)
      payload_key = decryptor.box_open_afternm({ciphertext : recipients[recipient_index][1], nonce : nonce.nonceForPayloadKeyBox(), secret})
      found = true
      break

  #check for anonymous recipients
  if not found then for recipient_index in [0...recipients.length]
    try
      payload_key = decryptor.box_open_afternm({ciphertext : recipients[recipient_index], nonce : nonce.nonceForPayloadKeyBox(), secret})
    catch error
      if error.message is 'TweetNaCl box_open_afternm failed!' or error.message is 'Sodium box_open_afternm failed!' then continue
      else throw error

  unless payload_key? then throw new Error('You are not a recipient!')

  #open the sender secretbox
  payload_decryptor = crypto.alloc({force_js : false})
  payload_decryptor.secretKey = payload_key
  sender_pubkey = payload_decryptor.secretbox_open({ciphertext : header_list[4], nonce : nonce.nonceForSenderKeySecretBox()})

  #compute the MAC key
  mac_key = compute_mac_key(decryptor, header_hash, sender_pubkey)

  return {header_list, header_hash, payload_key, sender_pubkey, mac_key, recipient_index}
