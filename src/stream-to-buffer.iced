stream = require('stream')

exports.StreamToBuffer = class StreamToBuffer extends stream.Transform

  constructor : (options) ->
    @bufs = []
    super(options)

  _write : (chunk, encoding, cb) ->
    @bufs.push(chunk)
    cb()

  getBuffer : () ->
    return Buffer.concat(@bufs)
