// Generated by IcedCoffeeScript 108.0.11
(function() {
  var DeformatStream, FormatStream, chars_per_word, newline, noop, punctuation, space, stream, util, words_per_line,
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  stream = require('keybase-chunk-stream');

  util = require('./util');

  space = new Buffer(' ');

  newline = new Buffer('\n');

  punctuation = new Buffer('.');

  words_per_line = 200;

  chars_per_word = 15;

  noop = function() {};

  exports.FormatStream = FormatStream = (function(_super) {
    __extends(FormatStream, _super);

    FormatStream.prototype.__format = function(chunk) {
      return Buffer.concat([space, chunk]);
    };

    FormatStream.prototype._format = function(chunk) {
      var i, results, word, _i, _ref;
      if (chunk.length < chars_per_word) {
        return chunk;
      }
      results = [];
      for (i = _i = 0, _ref = chunk.length; chars_per_word > 0 ? _i < _ref : _i > _ref; i = _i += chars_per_word) {
        word = chunk.slice(i, i + chars_per_word);
        if (this._word_count % 200 === 0 && this._word_count !== 0) {
          word = Buffer.concat([word, newline]);
        } else {
          word = Buffer.concat([word, space]);
        }
        ++this._word_count;
        results.push(word);
      }
      return Buffer.concat(results);
    };

    FormatStream.prototype._transform = function(chunk, encoding, cb) {
      if (!this._header_written) {
        this.push(Buffer.concat([this._header, punctuation, space]));
        this._header_written = true;
      }
      return FormatStream.__super__._transform.call(this, chunk, encoding, cb);
    };

    FormatStream.prototype._flush = function(cb) {
      FormatStream.__super__._flush.call(this, noop);
      this.push(Buffer.concat([punctuation, space, this._footer, punctuation]));
      return cb();
    };

    function FormatStream(opts) {
      var _brand;
      if ((opts != null ? opts.brand : void 0) != null) {
        _brand = opts.brand;
      } else {
        _brand = 'KEYBASE';
      }
      this._header = new Buffer("BEGIN" + space + _brand + space + "SALTPACK" + space + "ENCRYPTED" + space + "MESSAGE");
      this._footer = new Buffer("END" + space + _brand + space + "SALTPACK" + space + "ENCRYPTED" + space + "MESSAGE");
      this._header_written = false;
      this._word_count = 0;
      FormatStream.__super__.constructor.call(this, this._format, {
        block_size: 15,
        exact_chunking: false,
        writableObjectMode: false,
        readableObjectMode: false
      });
    }

    return FormatStream;

  })(stream.ChunkStream);

  exports.DeformatStream = DeformatStream = (function(_super) {
    var _body_mode, _footer_mode, _header_mode, _strip, _strip_chars;

    __extends(DeformatStream, _super);

    _header_mode = 0;

    _body_mode = 1;

    _footer_mode = 2;

    _strip_chars = Buffer.from('>\n\r\t ');

    _strip = function(chunk) {
      var i, indicies, ret, _i, _ref;
      indicies = [];
      ret = [];
      for (i = _i = 0, _ref = chunk.length; 0 <= _ref ? _i < _ref : _i > _ref; i = 0 <= _ref ? ++_i : --_i) {
        if (_strip_chars.indexOf(chunk[i]) === -1) {
          ret.push(chunk[i]);
        }
      }
      return Buffer.from(ret);
    };

    DeformatStream.prototype._deformat = function(chunk) {
      var body_mode, index, read_footer, read_header, ret;
      if (this._mode === _header_mode) {
        index = chunk.indexOf(punctuation[0]);
        if (index !== -1) {
          read_header = chunk.slice(0, index);
          read_header = _strip(read_header);
          if (!util.bufeq_secure(read_header, _strip(this._header))) {
            throw new Error("Header failed to verify! Real header: " + (_strip(this._header)) + " Header in question: " + read_header);
          }
          this._mode = _body_mode;
          this.block_size = 1;
          this.exact_chunking = false;
          this.extra = chunk.slice(index + punctuation.length + space.length);
          _header_mode = null;
          return new Buffer('');
        } else {
          throw new Error('Somehow didn\'t get a full header packet');
        }
      } else if (this._mode === _body_mode) {
        index = chunk.indexOf(punctuation[0]);
        if (index === -1) {
          return _strip(chunk);
        } else {
          ret = _strip(chunk.slice(0, index));
          this.extra = chunk.slice(index + punctuation.length + space.length);
          this.block_size = this._footer.length;
          this.exact_chunking = true;
          this._mode = _footer_mode;
          body_mode = null;
          return ret;
        }
      } else if (this._mode === _footer_mode) {
        read_footer = _strip(chunk);
        if (!util.bufeq_secure(read_footer, _strip(this._footer))) {
          throw new Error("Footer failed to verify! Real footer: " + (_strip(this._footer)) + " Footer in question: " + read_footer);
        }
        _footer_mode = null;
        return new Buffer('');
      } else {
        throw new Error("Modes were off, somehow. SAD!");
      }
    };

    DeformatStream.prototype._flush = function(cb) {
      return cb();
    };

    function DeformatStream(opts) {
      var _brand;
      if ((opts != null ? opts.brand : void 0) != null) {
        _brand = opts.brand;
      } else {
        _brand = 'KEYBASE';
      }
      this._header = new Buffer("BEGIN" + space + _brand + space + "SALTPACK" + space + "ENCRYPTED" + space + "MESSAGE");
      this._footer = new Buffer("END" + space + _brand + space + "SALTPACK" + space + "ENCRYPTED" + space + "MESSAGE");
      this._mode = _header_mode;
      DeformatStream.__super__.constructor.call(this, this._deformat, {
        block_size: this._header.length + punctuation.length + space.length,
        exact_chunking: true,
        writableObjectMode: false,
        readableObjectMode: false
      });
    }

    return DeformatStream;

  })(stream.ChunkStream);

}).call(this);