# This class prettifies the output of our armoring stream, according to the saltpack spec.
# At the moment, per the spec, it simply frames the message, and inserts a space every 15 characters
# and a newline every 200 words.

stream = require('keybase-chunk-stream')
util = require('./util')

# Punctuation - this is modular
space = new Buffer(' ')
newline = new Buffer('\n')
punctuation = new Buffer('.')

words_per_line = 200
chars_per_word = 15

# For working with the chunk streams
noop = () ->

# This stream takes basex'd input and writes framed output, as per https://saltpack.org/armoring#framing-the-basex-payload
exports.FormatStream = class FormatStream extends stream.ChunkStream

  # _format is the transform function passed to the chunk stream constructor
  _format : (chunk, cb) ->
    # this is only ever called during flush()
    if chunk.length < @block_size
      return cb(null, chunk)

    # write out the header if we haven't already
    res = new Buffer('')
    unless @_header_written
      res = Buffer.concat([@_header, punctuation, space])
      @_header_written = true

    @_word_count++
    if @_word_count isnt 200
      # res will be an empty buffer except when writing the header
      res = Buffer.concat([res, chunk, space])
    else
      # ditto
      res = Buffer.concat([res, chunk, newline])
      @_word_count = 0

    cb(null, res)

  flush_append : (cb) ->
    cb(null, Buffer.concat([punctuation, space, @_footer, punctuation]))

  constructor : ({brand}) ->
    if brand? then _brand = brand else _brand = 'KEYBASE'
    @_header = new Buffer("BEGIN#{space}#{_brand}#{space}SALTPACK#{space}ENCRYPTED#{space}MESSAGE")
    @_footer = new Buffer("END#{space}#{_brand}#{space}SALTPACK#{space}ENCRYPTED#{space}MESSAGE")
    @_header_written = false
    @_word_count = 0
    super({transform_func : @_format, block_size : chars_per_word, readableObjectMode : false})

exports.DeformatStream = class DeformatStream extends stream.ChunkStream

  _header_mode = 0
  _body_mode = 1
  _footer_mode = 2
  _strip_re = /[>\n\r\t ]/g

  _strip = (chunk) -> chunk = new Buffer(chunk.toString().replace(_strip_re, ""))

  _deformat : (chunk, cb) ->
    chunk = Buffer.concat([@_partial, chunk])
    @_partial = new Buffer('')
    if @_mode is _header_mode
      index = chunk.indexOf(punctuation[0])
      if index isnt -1
        # then we have a full header, verify it
        re = /[>\n\r\t ]*BEGIN[>\n\r\t ]+([a-zA-Z0-9]+)?[>\n\r\t ]+SALTPACK[>\n\r\t ]+(ENCRYPTED[>\n\r\t ]+MESSAGE)|(SIGNED[>\n\r\t ]+MESSAGE)|(DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*/
        @_header = chunk[...index]
        unless re.test(@_header) then return cb(new Error("Header failed to verify!"), null)
        chunk = chunk[index + punctuation.length...]
        @_mode = _body_mode
      else
        # then we have a partial header, store it and wait for the next write
        @_partial = chunk
        return cb(null, null)

    if @_mode is _body_mode
      index = chunk.indexOf(punctuation[0])
      if index is -1
        # chunk is only body bytes
        return cb(null, _strip(chunk))
      else
        # chunk has some footer bytes
        @push(_strip(chunk[...index]))
        chunk = chunk[index + punctuation.length...]
        @_mode = _footer_mode

    if @_mode is _footer_mode
      index = chunk.indexOf(punctuation[0])
      if index isnt -1
        # we have a full footer, verify it
        footer = chunk[...index]
        re = /[>\n\r\t ]*END[>\n\r\t ]+([a-zA-Z0-9]+)?[>\n\r\t ]+SALTPACK[>\n\r\t ]+(ENCRYPTED[>\n\r\t ]+MESSAGE)|(SIGNED[>\n\r\t ]+MESSAGE)|(DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*/
        expected_footer = Buffer.concat([new Buffer('END'), _strip(@_header)[5...]])
        unless re.test(footer) and util.bufeq_secure(_strip(footer), expected_footer)
          return cb(new Error("Footer failed to verify! #{_strip(footer)} != #{expected_footer}"), null)
        @_mode = -1
        return cb(null, null)
      else
        # we only have a partial footer
        @_partial = chunk

    if @_mode is -1
      return cb(null, null)

  constructor : ({brand}) ->
    @_header = null
    @_mode = _header_mode
    @_partial = new Buffer('')
    super({transform_func : @_deformat, block_size : 2048, readableObjectMode : false})
