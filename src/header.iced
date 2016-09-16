crypto = require('crypto')
msgpack = require('keybase-msgpack-lite')
nacl = require('keybase-nacl')
{make_esc} = require('iced-error')
nonce = require('./nonce')
util = require('./util')

encryption_mode = 0
attached_sign_mode = 1
detached_sign_mode = 2
current_major = 1
current_minor = 0
crypto_auth_KEYBYTES = 32
crypto_secretbox_KEYBYTES = 32

compute_mac_key = ({encryptor, header_hash, pubkey}, cb) ->
  zero_bytes = new Buffer(crypto_auth_KEYBYTES)
  zero_bytes.fill(0)
  try
    mac_box = encryptor.encrypt({plaintext : zero_bytes, nonce : nonce.nonceForMACKeyBox(header_hash), pubkey})
  catch
    return cb(new Error("Failed to generate MAC keys"), null)
  # take last crypto_auth_BYTES bytes of MAC box
  cb(null, mac_box.slice(-crypto_auth_KEYBYTES))

exports.generate_encryption_header_packet = ({encryptor, recipients, anonymized_recipients}, cb) ->
  esc = make_esc(cb, "generate_encryption_header_packet")
  # create the header list and populate the quick stuff
  header_list = []
  header_list.push('saltpack')
  header_list.push([current_major, current_minor])
  header_list.push(encryption_mode)

  # generate the payload and ephemeral keys
  payload_encryptor = nacl.alloc({force_js : false})
  payload_key = crypto.randomBytes(crypto_secretbox_KEYBYTES)
  payload_encryptor.secretKey = payload_key
  ephemeral_encryptor = nacl.alloc({force_js : false})
  ephemeral_encryptor.genBoxPair()
  header_list.push(ephemeral_encryptor.publicKey)

  # support anonymous senders
  sender_encryptor = if encryptor?.publicKey? then encryptor else ephemeral_encryptor
  # create the sender secretbox
  sender_sbox = payload_encryptor.secretbox({plaintext : sender_encryptor.publicKey, nonce : nonce.nonceForSenderKeySecretBox()})
  header_list.push(sender_sbox)

  # create the recipients list
  recipients_list = []
  unless recipients.length > 0
    return cb(new Error("Bogus empty recipients list"), null)
  exposed_recipients = if anonymized_recipients?.length is recipients.length then anonymized_recipients else recipients
  for i in [0...recipients.length]
    rec_pair = []
    rec_pair.push(exposed_recipients[i])
    rec_payload = ephemeral_encryptor.encrypt({plaintext : payload_key, nonce : nonce.nonceForPayloadKeyBox(), pubkey : recipients[i]})
    rec_pair.push(rec_payload)
    recipients_list.push(rec_pair)
  header_list.push(recipients_list)

  # compute the header hash
  crypto_hash = crypto.createHash('sha512')
  header_intermediate = msgpack.encode(header_list)
  crypto_hash.update(header_intermediate)
  header_hash = crypto_hash.digest()

  # compute the mac keys
  mac_keys = []
  for i in [0...recipients.length]
    await compute_mac_key({encryptor : sender_encryptor, header_hash, pubkey : recipients[i]}, esc(defer(mac_keys[i])))

  cb(null, {header_intermediate, header_hash, mac_keys, payload_key})

exports.parse_encryption_header_packet = ({decryptor, header_intermediate}, cb) ->
  esc = make_esc(cb, "parse_encryption_header_packet")
  #unpack header
  crypto_hash = crypto.createHash('sha512')
  crypto_hash.update(header_intermediate)
  header_hash = crypto_hash.digest()
  header_list = msgpack.decode(header_intermediate)
  [format, [major, minor], mode, ephemeral, sender, recipients] = header_list

  #sanity checking
  if format isnt 'saltpack'
    return cb(new Error("wrong format #{format}"), null)
  if major isnt current_major
    return cb(new Error("wrong version number #{major}.#{minor}"), null)
  if mode isnt encryption_mode
    return cb(new Error("packet wasn't meant for decryption, found mode #{mode}"), null)

  #precompute ephemeral shared secret
  secret = decryptor.box_beforenm({pubkey : ephemeral, seckey : decryptor.secretKey})

  #find the payload key box
  found = false
  payload_key = null
  for recipient_index in [0...recipients.length]
    if recipients[recipient_index][0] is null then continue
    else if util.bufeq_secure(recipients[recipient_index][0], decryptor.publicKey)
      payload_key = decryptor.box_open_afternm({ciphertext : recipients[recipient_index][1], nonce : nonce.nonceForPayloadKeyBox(), secret})
      found = true
      break

  #check for anonymous recipients
  if not found then for recipient_index in [0...recipients.length]
    try
      payload_key = decryptor.box_open_afternm({ciphertext : recipients[recipient_index][1], nonce : nonce.nonceForPayloadKeyBox(), secret})
      break if payload_key? or payload_key.length is 0
    catch error
      if error.message is 'TweetNaCl box_open_afternm failed!' or error.message is 'Sodium box_open_afternm failed!' then continue
      else throw error

  unless payload_key?
    return cb(new Error('You are not a recipient!'), null)

  #open the sender secretbox
  payload_decryptor = nacl.alloc({force_js : false})
  payload_decryptor.secretKey = payload_key
  sender_pubkey = payload_decryptor.secretbox_open({ciphertext : header_list[4], nonce : nonce.nonceForSenderKeySecretBox()})

  #compute the MAC key
  await compute_mac_key({encryptor : decryptor, header_hash, pubkey : sender_pubkey}, esc(defer(mac_key)))

  cb(null, {header_list, header_hash, payload_key, sender_pubkey, mac_key, recipient_index})
