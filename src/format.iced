stream = require('keybase-chunk-stream')
util = require('./util.iced')

space = new Buffer(' ')
newline = new Buffer('\n')
punctuation = new Buffer('.')
_appname = 'KEYBASE'
header = new Buffer("BEGIN#{space}#{_appname}#{space}SALTPACK#{space}ENCRYPTED#{space}MESSAGE")
footer = new Buffer("END#{space}#{_appname}#{space}SALTPACK#{space}ENCRYPTED#{space}MESSAGE")

words_per_line = 200
chars_per_word = 15

noop = () ->

exports.FormatStream = class FormatStream extends stream.ChunkStream

  __format : (chunk) ->
    return Buffer.concat([space, chunk])

  _format : (chunk) ->
    if chunk.length < chars_per_word then return chunk
    results = []
    for i in [0...chunk.length] by chars_per_word
      word = chunk[i...i+chars_per_word]
      if @_word_count % 200 is 0 and @_word_count isnt 0 then word = Buffer.concat([word, newline])
      else word = Buffer.concat([word, space])
      ++@_word_count
      results.push(word)
    return Buffer.concat(results)

  _transform : (chunk, encoding, cb) ->
    if not @_header_written
      @push(Buffer.concat([header, punctuation, space]))
      @_header_written = true
    super(chunk, encoding, cb)

  _flush : (cb) ->
    super(noop)
    @push(Buffer.concat([punctuation, space, footer, punctuation]))
    cb()

  constructor : () ->
    @_header_written = false
    @_word_count = 0
    super(@_format, {block_size : 15, exact_chunking : false, writableObjectMode : false, readableObjectMode : false})

exports.DeformatStream = class DeformatStream extends stream.ChunkStream

  _header_mode = 0
  _body_mode = 1
  _footer_mode = 2

  _strip = (chunk) ->
    indicies = []
    ret = []
    for i in [0...chunk.length]
      if chunk[i] isnt space[0] and chunk[i] isnt newline[0] then ret.push(chunk[i])
    return Buffer.from(ret)

  _deformat : (chunk) ->
   if @_mode is _header_mode
      index = chunk.indexOf(punctuation[0])
      if index isnt -1
        # we found the period
        read_header = chunk[0...index]
        read_header = _strip(read_header)
        unless util.bufeq_secure(read_header, _strip(header)) then throw new Error("Header failed to verify! Real header: #{_strip(header)} Header in question: #{read_header}")
        @_mode = _body_mode
        @block_size = 1
        @exact_chunking = false
        @extra = chunk[index+punctuation.length+space.length...]
      else
        # something horrible happened
        throw new Error('Somehow didn\'t get a full header packet')
      # so that we can't enter this if statement more than once
      _header_mode = null
      return new Buffer('')

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
        @block_size = footer.length
        @exact_chunking = true
        @_mode = _footer_mode
        # so that we can't come back to body mode
        body_mode = null
        return ret

    else if @_mode is _footer_mode
      read_footer = _strip(chunk)
      unless util.bufeq_secure(read_footer, _strip(footer)) then throw new Error("Footer failed to verify! Real footer: #{_strip(footer)} Footer in question: #{read_footer}")
      # so that we can't enter this if statement more than once
      _footer_mode = null
      return new Buffer('')

    else
      # something very bad happened
      throw new Error("Modes were off, somehow. SAD!")

  # we should never have anything to flush
  _flush : (cb) ->
    cb()

  constructor : () ->
    @_mode = _header_mode
    super(@_deformat, {block_size : (header.length + punctuation.length + space.length), exact_chunking : true, writableObjectMode : false, readableObjectMode : false})