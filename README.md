# symbols

**A self-hosted debug-symbol server speaking the [debuginfod] protocol, with
push-to-publish from CI — plus the co-located GitHub Action that does the
publishing.**

Continuous profilers (Pyroscope's symbolizer, via the OTel eBPF profiler),
debuggers (gdb, elfutils via `DEBUGINFOD_URLS`) and pprof tooling all resolve
native stack frames by *build ID*. This server stores each released binary's
debug info keyed by that ID and serves it back over the standard lookup URL:

```
GET /buildid/{build-id}/debuginfo
```

Symbols are published by release pipelines with a plain `POST` — the build ID
is derived server-side from the uploaded file itself (ELF GNU build ID,
Mach-O `LC_UUID`, or PDB GUID+age), so uploads can never mislabel a lookup.
Symbols travel and are stored gzipped, end to end (see [Compression](#compression)).

## How publishing works

Release workflows use the co-located composite action:

```yaml
permissions:
  id-token: write

steps:
  - name: cargo build
    env:
      CARGO_PROFILE_RELEASE_STRIP: none   # keep debug info for the split
    run: cargo build --release --target ${{ matrix.target }}

  - uses: SierraSoftworks/symbols@v1
    if: github.event_name == 'release'
    with:
      binary: target/${{ matrix.target }}/release/my-app${{ matrix.extension }}
      version: ${{ github.event.release.tag_name }}
```

The action extracts the platform's symbol artifact (Linux: `objcopy
--only-keep-debug` with zlib-compressed sections, then re-strips the binary so
shipped artifacts keep their usual size; macOS: `dsymutil`; Windows: the MSVC
PDB), gzips it, and uploads it authenticated by the workflow's **GitHub OIDC
id-token** — no secrets are configured anywhere. Files too large for a single
request go up through the [chunked upload protocol](#chunked-uploads).

Symbol trouble never blocks a release: if extraction or publishing fails, the
action surfaces a workflow **warning** and the job carries on — symbols are a
debugging aid, and losing one build's symbols is not worth blocking its
release. Set `fail-on-error: true` to make failures fail the job instead.

On the server side, the token's `repository` claim names the project
(`org/repo`). Repositories in a **trusted organization** get their project
created automatically on first upload, seeded with the repository's own
visibility (public repo → publicly served symbols; private repo → symbols
served only on the internal plane).

## Serving planes

The server binds two listeners with different surfaces:

- **public** — fronted publicly (e.g. `https://symbols.sierrasoftworks.com`):
  debuginfod reads of `public` projects' symbols (internal projects are
  indistinguishable from absent) plus symbol uploads from CI.
- **internal** — bound to a cluster/tailnet-only address: unrestricted
  debuginfod reads, the management API, and the management UI. Point
  Pyroscope's `symbolizer.debuginfod_url` (and your own `DEBUGINFOD_URLS`)
  here.

Unknown build IDs are federated to an upstream debuginfod server (default:
`debuginfod.elfutils.org`, covering distro packages such as glibc) and cached
in object storage, so consumers only ever need this one URL.

## Compression

DWARF compresses several-fold, and the same gzip stream serves the upload, the
bucket and the download:

- **Uploading** — send the body with `Content-Encoding: gzip` (the action
  does; a body that is a gzip stream is recognised even without the header,
  since no symbol format we accept can be mistaken for one). This is what
  keeps large artifacts — a Rust dSYM passes 100MB easily — inside the request
  body limits imposed by CDNs in front of the server. A body sent raw is
  accepted and compressed server-side instead.
- **At rest** — stored objects are the compressed bytes, under a `.gz` key.
  A compressed upload is written through untouched.
- **Downloading** — a client that advertises `Accept-Encoding: gzip` gets
  those exact bytes back with `Content-Encoding: gzip`; no other client is
  handed anything it didn't ask for, so requests without the header are
  inflated as they stream out (in 256KiB chunks — the inflate path used to
  hand the HTTP layer 4KiB at a time, and ran at half the speed of the
  pass-through for it). Either way the server never holds a whole symbol
  file in memory to serve it.

Objects written before this all get served as they always were; the encoding
of each is part of its key.

### HTTP semantics

Every `/buildid/{id}/debuginfo` response — a published symbol or a cached
upstream one — behaves like a static file would:

- **HEAD** returns exactly the headers the GET would (status,
  `Content-Length`, `Content-Encoding`, ...) with no body, and is answered
  from object metadata alone; nothing is read from the bucket.
- **Byte ranges** (a single `Range: bytes=...`) are honoured on the bytes the
  server sends verbatim — the stored gzip stream for a client that accepts
  gzip, or a plain object for anyone — and read from storage as a range, so
  `Content-Range: bytes 0-1023/<stored size>` describes the gzip bytes,
  exactly as `Content-Encoding: gzip` says it does. An inflated response
  cannot be ranged without inflating from the start, so it carries
  `Accept-Ranges: none` and a `Range` on it is ignored (200, the whole
  file). A range lying past the end is a 416 with `Content-Range: bytes
  */<size>`; several ranges, other units and an `If-Range` all fall back to
  the whole representation (there is no validator yet for an `If-Range` to
  match). A HEAD describes the whole representation, range or no range.

## Chunked uploads

A single request can only be as large as the smallest hop in front of the
server allows — a CDN's request-body cap is typically ~100MB, and a large
project's DWARF passes that even gzipped. Files that would not fit go up in
parts:

```
POST /api/v1/uploads?version=...          -> { "upload_id": ... }
PUT  /api/v1/uploads/{id}/chunks/{index}     (raw slices of the file, from 0)
POST /api/v1/uploads/{id}/complete?chunks=N  -> { "state": "processing" }
GET  /api/v1/uploads/{id}                    -> { "state": ..., "result": ... }
```

Every request authenticates with the same OIDC id-token as a single-shot
upload, and a session only accepts requests from the repository that opened
it. Chunks are staged in object storage (so sessions survive server restarts),
and completion verifies every part arrived — a dropped chunk is an error, not
silently truncated symbols — then hands the body to a worker job and returns
immediately; the client polls the status endpoint for the outcome, which on
success carries the same payload the single-shot endpoint returns. Sessions
that are never completed (and finished ones nobody polled) are cleaned up by
the retention sweep (`upload_staging_max_age`, default 24h).

The publish action does all of this automatically: it uploads in one request
when the gzipped file fits, switches to 64MB chunks when it doesn't, and
polls completion until the symbols land.

### How uploads are processed

Ingest never holds a body: request bytes stream straight into staging as
bounded multipart parts, whatever their size. Once a body is durably staged,
a worker job (at most two at a time) streams it through a gzip decoder into a
spool file on disk, memory-maps that file to derive the build ID — the page
cache stands in for the heap, so even gigabyte DWARF never becomes server
memory — and then streams the staged bytes to their final object. Single-shot
uploads run the same job inline and keep their synchronous response; chunked
uploads are processed in the background behind the status endpoint. Because
staging is durable and jobs are recorded on the session, a server crash loses
nothing: interrupted jobs are re-run on startup.

## Storage

Everything lives in an S3-compatible bucket (Garage in production): symbol
data, per-symbol metadata, the build-id index, the upstream cache, **and the
project registry itself** — so projects are managed through the API rather
than through config rollouts. Symbols and cached upstream responses are held
compressed; each symbol's metadata records both its `size` (the symbol file
itself) and its `stored_size`. A retention sweep keeps the newest N versions
per project (default 10, per-project override) and ages out the upstream
cache, bounding growth.

## Management UI

The internal plane serves a server-rendered management UI (Yew SSR, no client
bundle — every interaction is a link or a plain HTML form, following the
structure of [grey]'s frontend):

- **Dashboard** — storage statistics (per project, plus the upstream
  federation cache), the project registry, and a button to run the retention
  sweep immediately.
- **Project pages** — visibility and retention settings, plus every stored
  release with per-target rows (OS icon, architecture, size, links back to
  the commit and CI run that produced the upload) and purge actions for a
  whole release or a single target.
- **Setup** — copy-pasteable snippets for `DEBUGINFOD_URLS`, gdb, Pyroscope's
  symbolizer, and the publishing workflow, rendered with this server's real
  URLs.

Users sign in through the configured OIDC issuer (authorization code + PKCE,
exchanged server-side; the session lives in an HttpOnly `SameSite=Lax`
cookie).

## Management access

Both the UI and the API authenticate against one OIDC client
(`management.oidc`): a browser id-token and an API access token are both
minted for it, so its `client_id` is the audience every management token
carries.

Who gets in is a [filt-rs] expression — `management.acl` — evaluated on every
request against the validated token claims (addressed under `claims.`) plus
the request's `method` and `path`, exactly as [grey]'s admin ACL is:

```yaml
management:
  acl: claims.email endswith "@sierrasoftworks.com"
  # or: method == "GET" || claims.groups contains "symbols-admins"
```

Because it runs per request rather than once at sign-in, it can distinguish
reads from writes, and tightening it applies immediately to sessions already
open. Omitted, it admits anyone the issuer vouches for — the right default
when the issuer already gates membership (tsidp mints tokens only for tailnet
members) and this plane is internal-only.

## Management API

The same surface is scriptable, bearer-authenticated against the same OIDC
client (internal plane only):

| Route | Purpose |
|---|---|
| `GET /api/v1/projects` | List projects |
| `GET /api/v1/projects/{org}/{repo}` | Project details |
| `PATCH /api/v1/projects/{org}/{repo}` | Change `visibility` / `keep_versions` |
| `GET /api/v1/projects/{org}/{repo}/symbols` | List stored symbols |
| `DELETE /api/v1/projects/{org}/{repo}/symbols/{id}` | Delete one symbol |
| `DELETE /api/v1/projects/{org}/{repo}/versions/{version}` | Purge a release (`?os=`/`?arch=` to narrow) |
| `GET /api/v1/stats` | Storage statistics by project + upstream cache |
| `POST /api/v1/sweep` | Run the retention sweep immediately |

## Running it

```sh
symbols --config config.yaml
```

See [config.example.yaml](config.example.yaml) for the full configuration
surface. In the SierraSoftworks cluster the server is deployed by the
`symbols` pack in [nomad-pack-registry], and observability flows through the
standard OTLP env vars (`tracing-batteries`).

[debuginfod]: https://sourceware.org/elfutils/Debuginfod.html
[nomad-pack-registry]: https://github.com/SierraSoftworks/nomad-pack-registry
[filt-rs]: https://github.com/SierraSoftworks/filters
[grey]: https://github.com/SierraSoftworks/grey
