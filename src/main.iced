enc = require('node-armor-x')
header = require('./header.iced')
payload = require('./payload.iced')
saltpack = require('./stream.iced')
stb = require('./stream_to_buffer.iced')

exports.encrypt = (plaintext, pk, sk, recipients) ->
  encryptor = new saltpack.EncryptStream(pk, sk, recipients)
  encoder = enc.encoding.b62.encoding
  armorer = new enc.stream.StreamEncoder(encoder)
  buf = new stb.StreamToBuffer()
  encryptor.pipe(armorer)
  armorer.pipe(buf)
  encryptor.write(plaintext)
  return buf.getBuffer()
