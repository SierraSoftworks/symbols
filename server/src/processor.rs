//! The upload worker: turns a durably-staged upload body into stored symbols
//! without ever holding the body in memory.
//!
//! Ingest (the HTTP handlers) only streams bytes into `_staging/` — it never
//! looks at them. Once a body is durably staged, a job picks it up:
//!
//!  1. **Decode**: the staged chunks stream through a gzip decoder (or pass
//!     straight through when the upload was raw) into a spool file on disk.
//!     Memory stays at a few stream buffers regardless of body size, and the
//!     decompressed cap is enforced as bytes flow, so a pathological ratio is
//!     stopped mid-stream, not discovered after the fact.
//!  2. **Identify**: the spool file is memory-mapped and handed to the same
//!     `identify()` as ever — the page cache stands in for the heap, and the
//!     kernel reclaims it under pressure instead of OOM-killing the server.
//!  3. **Store**: the staged chunks stream again into the final object (via
//!     bounded multipart parts), gzip-encoded on the way if the upload was
//!     raw. Nothing is visible at the final path until the write completes.
//!
//! Jobs run under a small semaphore so concurrent uploads bound disk and CPU,
//! not just memory. Because staging is durable and jobs are recorded on the
//! session document, a server crash loses nothing: `recover()` re-runs any
//! job that was pending or in flight when the process died.

use std::io::Cursor;
use std::sync::Arc;

use bytes::Bytes;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_util::io::StreamReader;

use crate::api::AppState;
use crate::compression::{self, Compression};
use crate::errors::Error;
use crate::formats::identify;
use crate::storage::{Project, SymbolMeta, UploadSession, UploadStatus, Visibility};

/// How many uploads may be processed at once. Each job costs disk (the
/// decompressed spool) and a core (gzip); the rest queue on the semaphore.
pub const CONCURRENT_JOBS: usize = 2;

/// Largest symbol file we will spool once decoded. The whole file is needed
/// to derive its build ID; the spool lives on disk, so this bounds scratch
/// space rather than memory.
const MAX_SYMBOL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Spawns the background job for a session whose completion was requested.
/// The session must already be persisted as `Pending` — that record is what
/// `recover()` finds if the server dies before the job finishes.
pub fn spawn(state: Arc<AppState>, session: UploadSession) {
    tokio::spawn(run_job(state, session));
}

/// Re-runs jobs interrupted by a restart. Processing is idempotent — the
/// final object is written to a deterministic path and completion is
/// all-or-nothing — so re-running a job that half-finished is safe.
pub async fn recover(state: Arc<AppState>) {
    let sessions = match state.store.list_upload_sessions().await {
        Ok(sessions) => sessions,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to scan for interrupted upload jobs");
            return;
        }
    };

    for session in sessions {
        if matches!(session.status, UploadStatus::Pending | UploadStatus::Processing) {
            tracing::info!(
                upload_id = %session.id,
                project = %session.project,
                "Recovering interrupted upload job"
            );
            spawn(state.clone(), session);
        }
    }
}

async fn run_job(state: Arc<AppState>, mut session: UploadSession) {
    let _permit = match state.jobs.acquire().await {
        Ok(permit) => permit,
        Err(_) => return, // semaphore closed: shutting down
    };

    session.status = UploadStatus::Processing;
    if let Err(e) = state.store.create_upload(&session).await {
        // The job still runs; the record is only for recovery and polling.
        tracing::warn!(upload_id = %session.id, error = %e, "Failed to record job start");
    }

    match process(&state, &session).await {
        Ok(result) => {
            session.status = UploadStatus::Complete;
            session.result = Some(result);
            session.error = None;
            if let Err(e) = state.store.create_upload(&session).await {
                tracing::warn!(upload_id = %session.id, error = %e, "Failed to record job result");
            }
            // The chunks are spent; the session document stays behind for
            // status polling until the sweep clears it.
            if let Err(e) = state.store.delete_upload_chunks(&session.id).await {
                tracing::warn!(upload_id = %session.id, error = %e, "Failed to clear staged chunks");
            }
        }
        Err(e) => {
            tracing::warn!(upload_id = %session.id, error = %e, "Upload processing failed");
            session.status = UploadStatus::Failed;
            session.error = Some(e.to_string());
            if let Err(e) = state.store.create_upload(&session).await {
                tracing::warn!(upload_id = %session.id, error = %e, "Failed to record job failure");
            }
        }
    }
}

/// The streaming pipeline itself. Also called inline (awaited) by the
/// single-shot upload endpoint, which keeps its synchronous response contract
/// while sharing every byte of this path.
pub async fn process(state: &AppState, session: &UploadSession) -> Result<serde_json::Value, Error> {
    let chunks = session
        .chunks
        .ok_or_else(|| Error::Internal("session has no chunk count".to_string()))?;

    // --- Pass 1: decode the staged body into a spool file -------------------
    let stream = state.store.upload_body_stream(&session.id, chunks);
    let mut reader = StreamReader::new(stream);

    // Sniff the first two bytes to decide the encoding, then stitch them back
    // in front of the stream. No symbol format we accept can be mistaken for
    // gzip, and a client that sent a .gz without saying so still meant it.
    let mut header = Vec::with_capacity(2);
    (&mut reader).take(2).read_to_end(&mut header).await
        .map_err(|e| Error::Internal(format!("reading staged upload: {e}")))?;
    let gzipped = compression::looks_gzipped(&header);
    let reader = BufReader::new(Cursor::new(header).chain(reader));

    let spool = tempfile::tempfile()
        .map_err(|e| Error::Internal(format!("creating spool file: {e}")))?;
    let mut spool = tokio::fs::File::from_std(spool);

    let symbol_size = if gzipped {
        let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(reader);
        decoder.multiple_members(true);
        copy_limited(decoder, &mut spool, MAX_SYMBOL_BYTES).await?
    } else {
        copy_limited(reader, &mut spool, MAX_SYMBOL_BYTES).await?
    };
    if symbol_size == 0 {
        return Err(Error::BadRequest("empty upload".to_string()));
    }
    spool.flush().await
        .map_err(|e| Error::Internal(format!("flushing spool file: {e}")))?;

    // --- Pass 2: identify from the spool, via mmap ---------------------------
    // The map is backed by the page cache: identification touches whatever
    // pages it needs and the kernel reclaims them afterwards, so even a
    // gigabyte of DWARF never becomes server heap.
    let spool = spool.into_std().await;
    let info = tokio::task::spawn_blocking(move || {
        let map = unsafe { memmap2::Mmap::map(&spool) }
            .map_err(|e| Error::Internal(format!("mapping spool file: {e}")))?;
        identify(&map)
    })
    .await
    .map_err(|e| Error::Internal(format!("identification task failed: {e}")))??;

    // --- Resolve the project -------------------------------------------------
    let project = match state.store.get_project(&session.project).await? {
        Some(existing) => existing,
        None => {
            let visibility = match session.repository_visibility.as_deref() {
                Some("public") => Visibility::Public,
                // Private/internal repositories — and anything unexpected —
                // default to internal-plane-only symbols; widen via the API.
                _ => Visibility::Internal,
            };
            let project = Project {
                name: session.project.clone(),
                visibility,
                keep_versions: None,
                created_at: chrono::Utc::now(),
                created_by: "auto".to_string(),
            };
            state.store.put_project(&project).await?;
            tracing::info!(
                project = %project.name,
                visibility = ?project.visibility,
                "Auto-created project for trusted organization"
            );
            project
        }
    };

    // --- Pass 3: stream the staged body to its final object -----------------
    // A gzipped upload is stored exactly as it arrived; a raw one is encoded
    // as it streams past. Either way the final object only appears once the
    // write completes.
    let mut writer = state.store.symbol_writer(&project.name, &info.id).await?;
    let source = state.store.upload_body_stream(&session.id, chunks);
    let write_result: Result<(), Error> = async {
        if gzipped {
            let mut source = std::pin::pin!(source);
            while let Some(chunk) = source.next().await {
                let chunk = chunk.map_err(|e| Error::Internal(format!("reading staged upload: {e}")))?;
                writer.write(chunk).await?;
            }
        } else {
            let mut encoder =
                async_compression::tokio::bufread::GzipEncoder::new(BufReader::new(StreamReader::new(source)));
            let mut buffer = vec![0u8; 1024 * 1024];
            loop {
                let n = encoder.read(&mut buffer).await
                    .map_err(|e| Error::Internal(format!("compressing upload: {e}")))?;
                if n == 0 {
                    break;
                }
                writer.write(Bytes::copy_from_slice(&buffer[..n])).await?;
            }
        }
        Ok(())
    }
    .await;

    let stored_size = match write_result {
        Ok(()) => writer.finish().await?,
        Err(e) => {
            if let Err(abort) = writer.abort().await {
                tracing::warn!(error = %abort, "Failed to abort interrupted symbol write");
            }
            return Err(e);
        }
    };

    let meta = SymbolMeta {
        id: info.id.clone(),
        format: info.format,
        // The file's own architecture wins; the uploader's tag only fills the
        // gap for formats that don't declare one (PDBs).
        arch: info.arch.clone().or_else(|| session.arch.clone()),
        version: session.version.clone(),
        size: symbol_size,
        compression: Compression::Gzip,
        stored_size: Some(stored_size),
        uploaded_at: chrono::Utc::now(),
        uploaded_from: session.git_ref.clone(),
        os: session.os.as_deref().map(|os| os.to_ascii_lowercase()),
        commit: session.commit.as_deref().map(|c| c.to_ascii_lowercase()),
        build_url: session.build_url.clone(),
    };
    state.store.put_symbol_meta(&project.name, &info, &meta).await?;

    tracing::info!(
        project = %project.name,
        build_id = %info.id,
        format = ?info.format,
        arch = ?meta.arch,
        version = %meta.version,
        size = symbol_size,
        stored_size,
        "Stored symbols"
    );

    Ok(serde_json::json!({
        "build_id": info.id,
        "project": project.name,
        "format": info.format,
        "arch": meta.arch,
        "version": meta.version,
        "size": symbol_size,
        "stored_size": stored_size,
        "compression": meta.compression,
    }))
}

/// Copies `reader` into `out`, refusing to pass `limit` — enforced as the
/// bytes flow, so a decompression bomb is cut off rather than spooled.
async fn copy_limited<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    out: &mut tokio::fs::File,
    limit: u64,
) -> Result<u64, Error> {
    let mut limited = reader.take(limit + 1);
    let copied = tokio::io::copy(&mut limited, out).await.map_err(|e| match e.kind() {
        // Decoder errors (a corrupt gzip stream) are the client's fault;
        // anything else is ours.
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput | std::io::ErrorKind::UnexpectedEof => {
            Error::BadRequest(format!("decoding the upload: {e}"))
        }
        _ => Error::Internal(format!("spooling the upload: {e}")),
    })?;
    if copied > limit {
        return Err(Error::TooLarge(format!(
            "the upload decompresses to more than the {limit} byte limit"
        )));
    }
    Ok(copied)
}
