crypto = require('crypto')
saltpack = require('../..')
vectors = require('../vectors')
format = saltpack.lowlevel.format
stream = saltpack.stream
util = saltpack.lowlevel.util

msg_length = (1024**2)*2

_test_saltpack_pipeline = (do_armoring, anon_recips, T, cb) ->
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
    es.end(() ->)
  out = stb.getBuffer()
  T.equal(data.length, out.length, 'Truncation or garbage bytes')
  T.equal(data, out, 'Plaintext mismatch')
  cb()

_test_deformatter = (T, test_case) ->
  str = test_case.input
  ds = new format.DeformatStream({})
  stb = new util.StreamToBuffer()
  ds.pipe(stb)
  await ds.write(new Buffer(str), defer())
  await
    stb.on('finish', defer())
    ds.end()
  T.equal(stb.getBuffer().toString(), test_case.output, "Vector #{test_case.name} failed")

exports.test_format_stream = (T, cb) ->
  str = new Buffer('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')
  expected = new Buffer('BEGIN KEYBASE SALTPACK ENCRYPTED MESSAGE. kiZ8aa8yNOPC2nP QD3QM6XxeDhqkAl a8L62n0LCUdD09k W0OD4LbFMb7i26Y GYIaGDOpZaWvOqE ZRcweQTdTmTZlgD wkRICgu5i61hXKp aZR2S33yInCIzWf hk4MTSmfkXqoXEc 0tNoFOuGJuN9cLm Bl7l6DjAPsuZEfD oiDw6OsHwywZtxE sdCToPhvLSCLLvJ 7vb5yeF20g8EfuW Ul8QQtfW5n93drh z2XcHThZzhRsqV9 FfEjWxUsF1ZRFf8 4gE1jjMdhU93bh1 rus3a5IAwxma1Mc Bhv49YTqIEWeMwb 2fRjHaqbPnc90cB ZGcYFeuW0ntAO8F qJe247yrTciVAW6 0Red2sk8hQIroLT MFHhYBb4Ll3kO3R ci3WTJXt8BayZdT KmUozJ1h6BTkd7j xRgtUWykZSOlxX2 Ujr1UlHJsxnB9X0 qUa5jKg9MxQwh9u 4Kf6h7VCgze5C5X N7ZMPQot9OFE8ee MiEBOSePBUtRPoU 7kAVZwfZ07MtyxP RzgdYUQz5pQiU2U UQqPLmaHRzFTb6B bj8059QXuA4rSqr vi7e0MWaCvRSnsh ZWJE9K07hrFz3D5 vNl6RoQ6gyhFlW5 ybDiNyX0bYRch3P ZikQFMyqWF7MlOI cMOtWjD6SU1cVBp dvJMYERSPbWLEC5 tEFRt5A5XxwL9Xi JNcs4wgBXaZIUlX L5HLmwsqc2TkfZJ ejs03nWXcgMWHrK N1O1bbQeU26djEx fwSOeqO4ArDWvhl qlJy354pjC8e0nU hd3xcNpws8lHYh4 tNQ04ZOBDtdxVwS tnE207oRDI7Kbrs rQNriLImESLyH3v iCT3ZW1I0scmuGv DwUxIA3yiVryXJ6 4vf7vRnSIjtLzAl QAjWZcoCWuVwcXj p4auqPSuQwgXQ5S K9UU8KkEmmsXuix UJzkz5SsLWjUAy5 UHCwmtddO26F8Sk 5P8GH3mFKU1w47w 4jrHkJ6KIINE4Xu DnrkU3uhY9sOHXm UgQ1euYYaSpOn2b FUsy07vAHTFAPzG GNkPVGRSc91OMG0 xhaU1x3hnCYSjc8 eJzuqeI9R9ABRw0 x0tuoftAeksztI0 6kKmqVJoncjv0nP nYkoMCuvwlY8IOx zbW4oWNqYGED908 DcaygUbNezF9E7i Eu77VoXNF5j0v52 wR7XBhsrsdno3Rz VQ3w91ovggkMyaj fSdu4lbTyrftRsH oyhOOAkSDWWwT0t RfcuQAjEIVsOh5m AulcfkjAZNbpGNE YxwtAGQqqDEtDQ5 njL7oPCYiIlry0N uy0orz86FGjReU0 fAebHxlaRwgQ1Rc kpUn8Q8fSQGmHBD M4lCTZX7lrNk5J6 KA8raprFzBOBgs7 ZK648zLE7paJp3G i7xe1TvsFBIXAlJ pY5baFvXnqTJolr yuEdW1pcZyqIQlB LRjN2tZIemdqsW2 33CKwc9sb4Mu8VK l4woUo6gN2vgRco 5Kd9QzjFbUtPdmy yVxuFaTgqrAfSIg XXCLjdgGUxmkI6o pi8FXuwpr5uyfD0 UqKQFXU8UCUf9JJ Axce2kCuK1V5NOC UWxwh8P4ySi9pn1 d74XS4iAhEcPjQI vKCJfub1APeaEc2 CT3yJEkcpcqdzmO kwjAiqN43fZYHDM 3tfZXaddEdw3I3B x8YUgVDzDhyMwqf WJhyz2mADrVuDe4 GwSi7M48U43OtKd 7sNjinliXbW2lqR 4A79rOFdjaoWHcd T6uRCoIVxHKAvLB Coq1WrXC1KrDz1g mL2mBY8jJonRHLL pGE5VUGqQRRuZdT exwnKXWMYTUCmfT osFkuL5wJSWgNLn oOfOI1UVtcMOEyP tLSbc0rq0ehZcCM 581pU4VwaXMO8KY 45bUbQTpaSIzJrt 5zel3NQ1kP7Dayo yIkpxv2MqCJxfTn kWOQMSRvcfUltFG PLjP47p9Z6y6Uhv h6Vkop9HthEeyrB 3AClDoj1B7tTXvK RRV9YkoXmLKrpyH ungcp5wfpyvOMoi vMoBXBHvSpkG1Zb BdMqBvEgnVDFCQe UMp7D20eVEe5rqe PLIY7I0ZUKz8sbR AfJDI6hvJxkJjp0 KUEz3Vz1XrlpUth GjG4icGDoPnGlI0 tqyUIwnMzTGtEn3 gE9jGWIL3aGIPEn UzaHtC9EWhPYgoT HzuhU7K968mL3hv Ncmm0OK2SsIXzqw HyXxXyIBlhyygZq AaxgvnZf9nTQTrF qtKyCKhtPf0xleg qSG44dsciXBORne G42WJaM8E6ud39D OCHOdGCljoT4sZM lsOnQi7vs46HKgs hWiAKJirtzw1uK7 lBxfk4mY88XNgGo vKvCBk7A6KHHKKd TiDkUy3gxmfAeov oo4o6VIzTJoACF8 1mUEpbKIF3HiE59 KtMIOl0wKukVUq5 9KcoaBUcudL0OZX s232glM0mXro8l0 7g9ywPLOtWrbNkb J8UTQOP4Y50ZW3e QdxF3njZQlKWpXb vS9NjwyKB2dUIC9 kYePp8aYuaqpzVV RBrTKJfkd88u7Z1 jfaXZIADVVWGq9S cl1764v4Onh0jzp i7T7jSKfV4OD2ax U9giKjQMudK2YLm IUdqXVgpQB5nNZi Q13AvNJGiEvExif BtEjrRyWHOmeQxG ej2qAfpSX69Gs2r XKetqqCKG5f5V21 hQ4NlhqEicLo2IT zkxS7uLVgbeKSHE 4VUXOIULo. END KEYBASE SALTPACK ENCRYPTED MESSAGE.')
  fs = new format.FormatStream({})
  ds = new format.DeformatStream({})
  stb = new util.StreamToBuffer()
  fs.pipe(ds).pipe(stb)
  await fs.write(str, defer())
  await
    stb.on('finish', defer())
    fs.end()
  T.equal(str, stb.getBuffer(), "Incorrect formatting or deformatting: #{stb.getBuffer()}")
  cb()

exports.test_short_single_block = (T, cb) ->
  test_case = vectors.valid.short_single_block
  _test_deformatter(T, test_case)
  cb()

# TODO: After error refactoring, fix this
exports.test_dog_end = (T, cb) ->
  test_case = vectors.invalid.footer_without_end
  _test_deformatter(T, test_case)
  cb()

exports.test_saltpack_with_armor = (T, cb) ->
  start = new Date().getTime()
  await _test_saltpack_pipeline(true, false, T, defer())
  end = new Date().getTime()
  console.log(end - start)
  cb()

exports.test_saltpack_without_armor = (T, cb) ->
  start = new Date().getTime()
  await _test_saltpack_pipeline(false, false, T, defer())
  end = new Date().getTime()
  console.log(end - start)
  cb()

exports.test_anonymous_recipients = (T, cb) ->
  await _test_saltpack_pipeline(false, true, T, defer())
  cb()

exports.test_real_saltpack = (T, cb) ->
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
  es = new stream.EncryptStream({encryptor : null, do_armoring : true, recipients : people_keys})
  stb = new util.StreamToBuffer()
  es.pipe(stb)
  message = new Buffer("For millions of years flowers have been producing thorns. For millions of years sheep have been eating them all the same. And it's not serious, trying to understand why flowers go to such trouble to produce thorns that are good for nothing? It's not important, the war between the sheep and the flowers? It's no more serious and more important than the numbers that fat red gentleman is adding up? Suppose I happen to know a unique flower, one that exists nowhere in the world except on my planet, one that a little sheep can wipe out in a single bite one morning, just like that, without even realizing what he'd doing - that isn't important? If someone loves a flower of which just one example exists among all the millions and millions of stars, that's enough to make him happy when he looks at the stars. He tells himself 'My flower's up there somewhere...' But if the sheep eats the flower, then for him it's as if, suddenly, all the stars went out. And that isn't important?\n")
  await es.write(message, defer(err))
  if err then throw err
  await
    stb.on('finish', defer())
    es.end(() ->)
  console.log('Send the following to Patrick, Jack, Mark, Max Krohn, Chris Coyne, or Chris Ball:')
  console.log(stb.getBuffer().toString())
  cb()
