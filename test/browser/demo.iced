saltpack = require('../..')

prompt = Buffer.concat([new Buffer(window.prompt("Put all your secrets here", "")), new Buffer('\n')])
{alice, _} = saltpack.lowlevel.util.alice_and_bob()
patrick_jack_and_mark_keys = [new Buffer('28536f6cd88b94772fc82b248163c5c7da76f75099be9e4bb3c7937f375ab70f', 'hex'), new Buffer('12474e6642d963c63bd8171cea7ddaef1120555ccaa15b8835c253ff8f67783c', 'hex'), new Buffer('915a08512f4fba8fccb9a258998a3513679e457b6f444a6f4bfc613fe81b8b1c', 'hex'), new Buffer('83711fb9664c478e43c62cf21040726b10d2670b7dbb49d3a6fcd926a876ff1c', 'hex'), new Buffer('28536f6cd88b94772fc82b248163c5c7da76f75099be9e4bb3c7937f375ab70f', 'hex')]
es = new saltpack.stream.EncryptStream({encryptor : alice, do_armoring : true, recipients : patrick_jack_and_mark_keys})
stb = new saltpack.lowlevel.util.StreamToBuffer()
es.pipe(stb)
await es.write(prompt, defer(err))
if err then throw err
await
  stb.on('finish', defer())
  es.end(() ->)
ct = stb.getBuffer().toString()
document.getElementById("ciphertext").innerHTML = ct
