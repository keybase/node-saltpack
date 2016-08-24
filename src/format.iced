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
  _format : (chunk) ->
    # this is only ever called during flush()
    if chunk.length < @block_size
      return chunk

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
    return res

  _flush : (cb) ->
    super(noop)
    @push(Buffer.concat([punctuation, space, @_footer, punctuation]))
    cb()

  constructor : ({brand}) ->
    if brand? then _brand = brand else _brand = 'KEYBASE'
    @_header = new Buffer("BEGIN#{space}#{_brand}#{space}SALTPACK#{space}ENCRYPTED#{space}MESSAGE")
    @_footer = new Buffer("END#{space}#{_brand}#{space}SALTPACK#{space}ENCRYPTED#{space}MESSAGE")
    @_header_written = false
    @_word_count = 0
    super({transform_func : @_format, block_size : 15, exact_chunking : true, writableObjectMode : false, readableObjectMode : false})

exports.DeformatStream = class DeformatStream extends stream.ChunkStream

  _header_mode = 0
  _body_mode = 1
  _footer_mode = 2
  _strip_re = /[>\n\r\t ]/g

  _strip = (chunk) -> chunk = new Buffer(chunk.toString().replace(_strip_re, ""))

  _deformat : (chunk) ->
   switch @_mode
      # verify the header, and print out any body that we may have gotten with it
      when _header_mode
        index = chunk.indexOf(punctuation[0])
        if index > 0
          after_period = chunk[index+1...]
          header = Buffer.concat([@_partial, chunk[0...index]])
          # clear this buffer out to be reused by the footer
          @_partial = new Buffer('')
          re = /[>\n\r\t ]*BEGIN[>\n\r\t ]+([a-zA-Z0-9]+)?[>\n\r\t ]+SALTPACK[>\n\r\t ]+(ENCRYPTED[>\n\r\t ]+MESSAGE)|(SIGNED[>\n\r\t ]+MESSAGE)|(DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*/
          unless re.test(header) then throw new Error("Header failed to verify!")
          @_header = _strip(header)
          @_mode = _body_mode
          return _strip(after_period)
        else
          @_partial = Buffer.concat([@_partial, chunk])
          return new Buffer('')

      # strip the body and print it out
      when _body_mode
        index = chunk.indexOf(punctuation[0])
        if index is -1
          # we're just in a normal body chunk
          # everything is fine
          return _strip(chunk)
        else
          # we found the end!
          ret = _strip(chunk[...index])
          # store any partial footer
          @_partial = chunk[index+punctuation.length+space.length...]
          @_mode = _footer_mode
          return ret

      when _footer_mode
        index = chunk.indexOf(punctuation[0])
        if index > 0
          footer = Buffer.concat([@_partial, _strip(chunk)])
          unless _strip(footer) is @_header[6...] then throw new Error("Footer failed to verify!")
          return new Buffer('')
        else
          @_partial = Buffer.concat([@_partial, chunk])
          return new Buffer('')

  constructor : ({brand}) ->
    if brand? then _brand = brand else _brand = 'KEYBASE'
    @_header = new Buffer('')
    @_mode = _header_mode
    @_partial = new Buffer('')
    super({transform_func : @_deformat, block_size : 1, exact_chunking : false, writableObjectMode : false, readableObjectMode : false})
