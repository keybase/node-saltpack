# node-saltpack
our standard saltpack implementation in JS

### Features
- Full implementation of the saltpack spec (https://saltpack.org)
- Written for streaming (composable with standard node streams)
- Browser-ready

### Encrypting and decrypting
First, you'll need to obtain keys somehow. See our [NaCl](https://github.com/keybase/node-nacl) library for info on how to do that. If you just want random keys for testing, there's an `alice_and_bob` function that returns two keypairs in `lib/util.js`.

Once you have keys for the encryptor and the public keys of each recipient:

```js
var saltpack = require("saltpack");

//get some testing keys, create encrypt/decrypt streams
var alice, bob;
{alice, bob} = saltpack.lowlevel.util.alice_and_bob();

//to specify anonymous recipients, simply add an "anonymized_recipients" argument
//to the dict, with "null" in place of a public key for each recipient you want to hide.
var es = new saltpack.stream.EncryptStream({
    encryptor: alice,
    do_armoring: true,
    recipients: [bob.publicKey]
})
var ds = new saltpack.stream.DecryptStream({decryptor: bob, do_armoring: true})

//register error listeners
es.on('error', (err) -> throw err)
ds.on('error', (err) -> throw err)

//encrypt from stdin, write to a file
var fs = require("fs");
var file = fs.createWriteStream("/path/to/file");

//pipe the EncryptStream into the file
process.stdin.pipe(es);
//currently, it's not possible to chain pipe calls with {Encrypt,Decrypt}Streams, i.e.
//process.stdin.pipe(es).pipe(file) - this change may come down the line,
//but for now we just have to use the extra line.
es.pipe(file);
file.on('close', () -> es.end())

//decrypt from a file, write to stdout
file = fs.createReadStream("/path/to/file");
file.pipe(ds)
ds.pipe(process.stdin)
file.on('close', () -> ds.end())
```

### Stream interface
`EncryptStream` and `DecryptStream` mimic the NodeJS [stream API](https://nodejs.org/api/stream.html) as closely as possible. Accordingly, you can watch for the following events:
- Writable side (input):
    - `drain`
    - `pipe`
    - `unpipe`
- Readable side (output):
    - `close`
    - `data`
    - `end`
    - `finish`
    - `readable`
The events are propagated up to the caller by the wrapped stream classes. Additionally, 'error' events emitted by _any_ stream in the pipeline will propagate up to the caller.

`EncryptStream` and `DecryptStream` also provide three stream-interface methods:
- `.write(chunk)`
- `.pipe(dest)`
- `.end()`

Unfortunately, at this time it is not possibe to chain .pipe() calls, as explained above. Other than this you can treat `EncryptStream` and `DecryptStream` as standard NodeJS streams.
