# This class prettifies the output of our armoring stream, according to the saltpack spec.
# At the moment, per the spec, it simply frames the message, and inserts a space every 15 characters
# and a newline every 200 words.

stream = require('keybase-chunk-stream')
util = require('./util')

space = new Buffer(' ')
newline = new Buffer('\n')
punctuation = new Buffer('.')

words_per_line = 200
chars_per_word = 15

noop = () ->

exports.FormatStream = class FormatStream extends stream.ChunkStream

  _format : (chunk) ->
    if chunk.length < chars_per_word
      return chunk
    else
      results = []
      for i in [0...chunk.length] by chars_per_word
        word = chunk[i...i+chars_per_word]
        if i+chars_per_word >= chunk.length
          results.push(word)
        else
          if @_word_count % 200 is 0 and @_word_count isnt 0
            word = Buffer.concat([word, newline])
          else
            word = Buffer.concat([word, space])
          ++@_word_count
          results.push(word)
      return Buffer.concat(results)

  _transform : (chunk, encoding, cb) ->
    if not @_header_written
      @push(Buffer.concat([@_header, punctuation, space]))
      @_header_written = true
    super(chunk, encoding, cb)

  _flush : (cb) ->
    super(noop)
    @push(Buffer.concat([punctuation, space, @_footer, punctuation]))
    cb()

  constructor : (opts) ->
    if opts?.brand? then _brand = opts.brand else _brand = 'KEYBASE'
    @_header = new Buffer("BEGIN#{space}#{_brand}#{space}SALTPACK#{space}ENCRYPTED#{space}MESSAGE")
    @_footer = new Buffer("END#{space}#{_brand}#{space}SALTPACK#{space}ENCRYPTED#{space}MESSAGE")
    @_header_written = false
    @_word_count = 0
    super(@_format, {block_size : 1, exact_chunking : false, writableObjectMode : false, readableObjectMode : false})

exports.DeformatStream = class DeformatStream extends stream.ChunkStream

  _header_mode = 0
  _body_mode = 1
  _footer_mode = 2
  _strip_chars = new Buffer('>\n\r\t ')

  _strip = (chunk) ->
    indicies = []
    ret = []
    for i in [0...chunk.length]
      if _strip_chars.indexOf(chunk[i]) is -1 then ret.push(chunk[i])
    return new Buffer(ret)

  _deformat : (chunk) ->
   if @_mode is _header_mode
      index = chunk.indexOf(punctuation[0])
      if index isnt -1
        # we found the period
        read_header = chunk[0...index]
        read_header = _strip(read_header)
        unless util.bufeq_secure(read_header, _strip(@_header)) then throw new Error("Header failed to verify!")
        @_mode = _body_mode
        @block_size = 1
        @exact_chunking = false
        @extra = chunk[index+punctuation.length+space.length...]
        # so that we can't enter this if statement more than once
        _header_mode = null
        return new Buffer('')
      else
        # something horrible happened
        throw new Error('Somehow didn\'t get a full header packet')

    else if @_mode is _body_mode
      index = chunk.indexOf(punctuation[0])
      if index is -1
        # we're just in a normal body chunk
        # everything is fine
        return _strip(chunk)
      else
        # we found the end!
        ret = _strip(chunk[...index])
        # put any partial footer into extra
        @extra = chunk[index+punctuation.length+space.length...]
        @block_size = @_footer.length
        @exact_chunking = true
        @_mode = _footer_mode
        # so that we can't come back to body mode
        body_mode = null
        return ret

    else if @_mode is _footer_mode
      read_footer = _strip(chunk)
      unless util.bufeq_secure(read_footer, _strip(@_footer)) then throw new Error("Footer failed to verify!")
      # so that we can't enter this if statement more than once
      _footer_mode = null
      return new Buffer('')

    else
      # something very bad happened
      throw new Error("Modes were off, somehow. SAD!")

  # we should never have anything to flush
  _flush : (cb) ->
    cb()

  constructor : (opts) ->
    if opts?.brand? then _brand = opts.brand else _brand = 'KEYBASE'
    @_header = new Buffer("BEGIN#{space}#{_brand}#{space}SALTPACK#{space}ENCRYPTED#{space}MESSAGE")
    @_footer = new Buffer("END#{space}#{_brand}#{space}SALTPACK#{space}ENCRYPTED#{space}MESSAGE")
    @_mode = _header_mode
    super(@_deformat, {block_size : (@_header.length + punctuation.length + space.length), exact_chunking : true, writableObjectMode : false, readableObjectMode : false})
