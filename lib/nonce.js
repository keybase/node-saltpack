// Generated by IcedCoffeeScript 108.0.11
(function() {
  var nonceBytes, prng, sigNonceBytes, uint64be;

  nonceBytes = 24;

  sigNonceBytes = 16;

  prng = require('crypto').prng;

  uint64be = require('uint64be');

  exports.nonceForSenderKeySecretBox = function() {
    return new Buffer('saltpack_sender_key_sbox');
  };

  exports.nonceForPayloadKeyBox = function() {
    return new Buffer('saltpack_payload_key_box');
  };

  exports.nonceForMACKeyBox = function(headerHash) {
    if (headerHash.length !== 64) {
      return new Error('Header hash shorter than expected');
    }
    return new Buffer(headerHash.slice(0, nonceBytes));
  };

  exports.nonceForChunkSecretBox = function(encryptionBlockNumber) {
    var nonce;
    nonce = new Buffer('saltpack_ploadsb');
    return Buffer.concat([nonce, uint64be.encode(encryptionBlockNumber)]);
  };

  exports.sigNonce = function() {
    return prng(sigNonceBytes);
  };

}).call(this);