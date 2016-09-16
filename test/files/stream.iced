crypto = require('crypto')
saltpack = require('../..')
{make_esc} = require('iced-error')
format = saltpack.lowlevel.format
stream = saltpack.stream
util = saltpack.lowlevel.util
vectors = require('../vectors.iced')

msg_length = (1024**2)/2

#===============================================================================
# Workhorse functions
#===============================================================================

_test_stream = (T, {test_case, stream}, cb) ->
  input = test_case.input
  stb = new util.StreamToBuffer()
  stream.pipe(stb)
  # if the test case was invalid, then we'll get a callback with the error we want to test, before hitting the T.equal below
  err = null
  stream.on('error', (_err) ->
    err = _err
  )
  stream.write(new Buffer(input))
  await
    stream.on('finish', defer())
    stream.end()
  if err?
    cb(err, null)
  else
    cb(null, stb.getBuffer())

_test_saltpack_pipeline = (T, {do_armoring, anon_recips}, cb) ->
  {alice, bob} = util.alice_and_bob()
  recipients_list = util.gen_recipients(bob.publicKey)
  if anon_recips
    anonymized_recipients = []
    anonymized_recipients.push(null) for [0...recipients_list.length]
    es = new stream.EncryptStream({encryptor : alice, do_armoring, recipients : recipients_list, anonymized_recipients})
  else
    es = new stream.EncryptStream({encryptor : alice, do_armoring, recipients : recipients_list})
  ds = new stream.DecryptStream({decryptor : bob, do_armoring})
  stb = new util.StreamToBuffer()
  es.pipe(ds.first_stream)
  ds.pipe(stb)

  await util.stream_random_data(es, msg_length, defer(data))
  await
    stb.on('finish', defer())
    es.end()
  out = stb.getBuffer()
  T.equal(data.length, out.length, 'Truncation or garbage bytes')
  T.equal(data, out, 'Plaintext mismatch')
  cb()

#===============================================================================
# Unit tests
#===============================================================================

exports.test_format_stream = (T, cb) ->
  test_case = vectors.valid.format
  await _test_stream(T, {test_case, stream: new format.FormatStream({})}, defer(err, res))
  if err? then throw err
  T.equal(res, new Buffer(test_case.output), "Vector #{test_case.name} failed")
  cb()

exports.test_short_single_block = (T, cb) ->
  test_case = vectors.valid.short_single_block
  await _test_stream(T, {test_case, stream: new format.DeformatStream({})}, defer(err, res))
  if err? then throw err
  T.equal(res, new Buffer(test_case.output), "Vector #{test_case.name} failed")
  cb()

exports.test_dog_end = (T, cb) ->
  test_case = vectors.invalid.dog_footer
  await _test_stream(T, {test_case, stream: new format.DeformatStream({})}, defer(err, _))
  T.equal(err.message, test_case.error, "Vector #{test_case.name} failed")
  cb()

exports.test_truncation = (T, cb) ->
  test_case = vectors.invalid.truncated_ending_packet
  {alice} = util.alice_and_bob()
  alice.secretKey = new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
  await _test_stream(T, {test_case, stream: new stream.DecryptStream({decryptor: alice, do_armoring: true})}, defer(err, _))
  T.equal(err.message, test_case.error, "Vector #{test_case.name} failed")
  cb()

exports.test_saltpack_with_armor = (T, cb) ->
  start = new Date().getTime()
  await _test_saltpack_pipeline(T, {do_armoring: true, anon_recips: false}, defer())
  end = new Date().getTime()
  console.log("Time: #{end-start}")
  cb()

exports.test_saltpack_without_armor = (T, cb) ->
  start = new Date().getTime()
  await _test_saltpack_pipeline(T, {do_armoring: false, anon_recips: false}, defer())
  end = new Date().getTime()
  console.log("Time: #{end-start}")
  cb()

exports.test_anonymous_recipients = (T, cb) ->
  start = new Date().getTime()
  await _test_saltpack_pipeline(T, {do_armoring: false, anon_recips: false}, defer())
  end = new Date().getTime()
  console.log("Time: #{end-start}")
  cb()

exports.test_real_saltpack = (T, cb) ->
  test_case = vectors.valid.real_saltpack
  people_keys = [
    new Buffer('28536f6cd88b94772fc82b248163c5c7da76f75099be9e4bb3c7937f375ab70f', 'hex'),
    new Buffer('12474e6642d963c63bd8171cea7ddaef1120555ccaa15b8835c253ff8f67783c', 'hex'),
    new Buffer('915a08512f4fba8fccb9a258998a3513679e457b6f444a6f4bfc613fe81b8b1c', 'hex'),
    new Buffer('83711fb9664c478e43c62cf21040726b10d2670b7dbb49d3a6fcd926a876ff1c', 'hex'),
    new Buffer('28536f6cd88b94772fc82b248163c5c7da76f75099be9e4bb3c7937f375ab70f', 'hex'),
    new Buffer('7e1454c201e72d7f22ded1fe359d5817a4c969ad7f2b742450d4e5606372c87e', 'hex'),
    new Buffer('9322c883599f4440eda5c2d40b0e1590b569db171d6fec2a92fbe7e12f90b414', 'hex'),
    new Buffer('d8507ab27528c6118f525f2e4d0d99cfbebf1f399758f596057b573f6e01ed48', 'hex'),
    new Buffer('c51589346c15414cf18ab7c23fed27dc8055f69770d2f34f6ca141607cc34d63', 'hex'),
    new Buffer('720b0ce2a6f7a3aff279702d157aa78b1bd774273be18938f4c006c9aadac90d', 'hex'),
    new Buffer('196bcc720c24d0b9937e3d78b966d27ab3679eb23330d7d0ca39b57bb3bac256', 'hex'),
    new Buffer('5da375c0018da143c001fe426e39dde28f85d99d16a7d30b46dd235f4f6f5b59', 'hex'),
    new Buffer('ddc0f890b224bc698e4f843b046b1eeaf3455504b434837424bcb63132bec40c', 'hex'),
    new Buffer('d65361e0d119422d7fa2d461b1eb460fcf9e3d0ed864b5b06639526b787e3c3b', 'hex')]
  es = new stream.EncryptStream({encryptor: null, do_armoring: true, recipients: people_keys})
  stb = new util.StreamToBuffer()
  es.pipe(stb)
  es.write(test_case.input)
  await
    stb.on('finish', defer())
    es.end()
  console.log('Send the following to Patrick, Jack, Mark, Max Krohn, Chris Coyne, or Chris Ball:')
  console.log(stb.getBuffer().toString())
  cb()
