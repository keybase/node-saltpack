stream = require('stream')

exports.StreamToBuffer = class StreamToBuffer extends stream.Transform

  constructor : (options) ->
    @buf = new Buffer([])
    super(options)

  _write : (chunk, encoding, cb) ->
    @buf = Buffer.concat([@buf, chunk])
    cb()

  getBuffer : () ->
    return @buf
