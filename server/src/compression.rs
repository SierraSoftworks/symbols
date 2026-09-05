use std::io::Write;
#[cfg(test)]
use std::io::Read;

use bytes::Bytes;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::errors::Error;

/// How a stored object's bytes are encoded at rest. Everything written since
/// the server learned to compress is `Gzip`; `None` covers objects stored
/// before that, and is what metadata carrying no `compression` reads back as.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    #[default]
    None,
    Gzip,
}

impl Compression {
    /// The suffix stored objects carry. Keeping the encoding in the key means
    /// the lookup path never has to read metadata to know how to serve an
    /// object.
    pub const fn suffix(self) -> &'static str {
        match self {
            Compression::None => "",
            Compression::Gzip => ".gz",
        }
    }
}

/// A stream of body bytes, as produced by object storage and consumed by
/// actix's `streaming` responses.
pub type ByteStream = BoxStream<'static, Result<Bytes, std::io::Error>>;

/// gzip's magic number. No symbol format we accept starts with these bytes
/// (ELF, Mach-O and PDB all have their own magic), so a body beginning with
/// them is unambiguously compressed even when nothing said so.
pub fn looks_gzipped(data: &[u8]) -> bool {
    data.starts_with(&[0x1f, 0x8b])
}

/// Compresses a whole symbol file. These run to hundreds of megabytes, so
/// call this from `web::block` rather than on a worker thread.
pub fn compress(data: &[u8]) -> Result<Bytes, Error> {
    let mut encoder = flate2::write::GzEncoder::new(
        Vec::with_capacity(data.len() / 4),
        flate2::Compression::default(),
    );
    encoder
        .write_all(data)
        .map_err(|e| Error::Internal(format!("compressing symbols: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| Error::Internal(format!("compressing symbols: {e}")))?;
    Ok(Bytes::from(compressed))
}

/// Decompresses a whole gzip body, refusing anything that expands past
/// `limit` — the result is held in memory to identify the file, so a
/// pathological ratio must not be allowed to exhaust the server.
#[cfg(test)]
pub fn decompress(data: &[u8], limit: usize) -> Result<Bytes, Error> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| Error::BadRequest(format!("decompressing the request body: {e}")))?;

    if out.len() > limit {
        return Err(Error::TooLarge(format!(
            "the body decompresses to more than the {limit} byte limit"
        )));
    }

    Ok(Bytes::from(out))
}

/// How much inflated output each chunk of a decoded stream carries. The
/// decoder fills the whole buffer before yielding, so this sets the size of
/// every body chunk the HTTP layer writes (and every allocation on the way).
/// `ReaderStream`'s default is 4KiB, which turned a 30MB symbol file into
/// ~7,500 chunked-transfer frames and per-frame writes — the inflate path ran
/// at a fraction of the pass-through path's throughput for no CPU reason.
/// 256KiB per in-flight response is a trivial amount of memory.
const INFLATE_CHUNK_SIZE: usize = 256 * 1024;

/// Inflates a stored gzip stream on the way out, for clients that can't take
/// `Content-Encoding: gzip`. Streaming (rather than buffering) keeps the
/// server's memory flat no matter how large the symbol file is: the decoder
/// holds one input chunk and one output buffer, however large the file.
///
/// Inflating is CPU work on the async runtime, but bounded per poll by the
/// output buffer (~a quarter of a millisecond of gzip per chunk), so it
/// doesn't need `spawn_blocking` — that would only add a channel hop per
/// chunk.
pub fn decode_stream(stream: ByteStream) -> ByteStream {
    let reader = tokio_util::io::StreamReader::new(stream);
    let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(reader);
    // Symbol files gzipped by `gzip`/`zlib` are a single member, but nothing
    // stops a client concatenating several; decode them all.
    decoder.multiple_members(true);
    Box::pin(tokio_util::io::ReaderStream::with_capacity(decoder, INFLATE_CHUNK_SIZE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::TryStreamExt;

    #[test]
    fn round_trips_through_gzip() {
        let plain = b"the quick brown fox".repeat(100);
        let compressed = compress(&plain).unwrap();
        assert!(looks_gzipped(&compressed));
        assert!(compressed.len() < plain.len());
        assert_eq!(&decompress(&compressed, 1 << 20).unwrap()[..], &plain[..]);
    }

    #[test]
    fn plain_bodies_are_not_mistaken_for_gzip() {
        assert!(!looks_gzipped(b"\x7fELF\x02\x01\x01"));
        assert!(!looks_gzipped(b""));
    }

    #[test]
    fn refuses_bodies_that_expand_past_the_limit() {
        // Zeroes compress ~1000:1, which is what a decompression bomb looks like.
        let compressed = compress(&vec![0u8; 512 * 1024]).unwrap();
        let err = decompress(&compressed, 1024).unwrap_err();
        assert!(matches!(err, Error::TooLarge(_)), "got {err:?}");
        // ...and the same body is fine when it fits.
        assert_eq!(decompress(&compressed, 1 << 20).unwrap().len(), 512 * 1024);
    }

    #[test]
    fn rejects_bodies_that_are_not_gzip() {
        assert!(matches!(
            decompress(b"\x7fELF not compressed", 1 << 20).unwrap_err(),
            Error::BadRequest(_)
        ));
    }

    #[actix_web::test]
    async fn decodes_a_stored_stream_in_chunks() {
        let plain = b"DWARF".repeat(10_000);
        let compressed = compress(&plain).unwrap();
        // Deliberately split across chunk boundaries the decoder must stitch.
        let chunks: Vec<Result<Bytes, std::io::Error>> = compressed
            .chunks(64)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();

        let decoded: Vec<Bytes> = decode_stream(Box::pin(futures::stream::iter(chunks)))
            .try_collect()
            .await
            .unwrap();

        assert_eq!(decoded.concat(), plain);
    }

    /// The inflated stream must come out in large chunks: each one is a body
    /// frame and a write on the wire, and 4KiB chunks were the bottleneck.
    #[actix_web::test]
    async fn decoded_streams_come_out_in_large_chunks() {
        // Highly compressible, so the whole thing is a handful of input
        // chunks but ~1MiB of output.
        let plain = vec![0u8; 1024 * 1024];
        let compressed = compress(&plain).unwrap();
        let chunks: Vec<Result<Bytes, std::io::Error>> = compressed
            .chunks(1024)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();

        let decoded: Vec<Bytes> = decode_stream(Box::pin(futures::stream::iter(chunks)))
            .try_collect()
            .await
            .unwrap();

        assert_eq!(decoded.concat(), plain);
        let full: Vec<_> = decoded.iter().take(decoded.len() - 1).collect();
        assert!(!full.is_empty());
        for chunk in full {
            assert_eq!(chunk.len(), INFLATE_CHUNK_SIZE, "every chunk but the last fills the buffer");
        }
    }
}
