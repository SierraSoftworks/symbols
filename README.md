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
id-token** — no secrets are configured anywhere.

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
  inflated as they stream out. Either way the server never holds a whole
  symbol file in memory to serve it.

Objects written before this all get served as they always were; the encoding
of each is part of its key.

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
cookie). Access can optionally be restricted to specific identities with
`management.allowed_users`.

## Management API

The same surface is scriptable, bearer-authenticated against the configured
OIDC issuer (internal plane only):

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
[grey]: https://github.com/SierraSoftworks/grey
