### v0.0.1
- base implementation mimicing NodeJS stream interface

### planned changes
- make `DeformatStream` a regular `Transform` stream - no need for it to be a `ChunkStream`
- allow chained `.pipe` calls (i.e. `es.pipe(ds).pipe(file_stream)`)
