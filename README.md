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
PDB) and uploads it authenticated by the workflow's **GitHub OIDC id-token** —
no secrets are configured anywhere.

On the server side, the token's `repository` claim names the project
(`org/repo`). Repositories in a **trusted organization** get their project
created automatically on first upload, seeded with the repository's own
visibility (public repo → publicly served symbols; private repo → symbols
served only on the internal plane).

## Serving planes

The server binds two listeners with identical routes but different read
policies:

- **public** — fronted publicly (e.g. `https://symbols.sierrasoftworks.com`):
  serves only `public` projects' symbols; internal projects are
  indistinguishable from absent.
- **internal** — bound to a cluster/tailnet-only address: serves everything.
  Point Pyroscope's `symbolizer.debuginfod_url` (and your own
  `DEBUGINFOD_URLS`) here.

Unknown build IDs are federated to an upstream debuginfod server (default:
`debuginfod.elfutils.org`, covering distro packages such as glibc) and cached
in object storage, so consumers only ever need this one URL.

## Storage

Everything lives in an S3-compatible bucket (Garage in production): symbol
data, per-symbol metadata, the build-id index, the upstream cache, **and the
project registry itself** — so projects are managed through the API rather
than through config rollouts. A retention sweep keeps the newest N versions
per project (default 10, per-project override) and ages out the upstream
cache, bounding growth.

## Management API

Bearer-authenticated against the configured OIDC issuer:

| Route | Purpose |
|---|---|
| `GET /api/v1/projects` | List projects |
| `GET /api/v1/projects/{org}/{repo}` | Project details |
| `PATCH /api/v1/projects/{org}/{repo}` | Change `visibility` / `keep_versions` |
| `GET /api/v1/projects/{org}/{repo}/symbols` | List stored symbols |
| `DELETE /api/v1/projects/{org}/{repo}/symbols/{id}` | Delete one symbol |

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
