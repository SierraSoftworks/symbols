use yew::prelude::*;

use crate::components::Snippet;
use crate::models::SetupInfo;

#[derive(Properties, PartialEq)]
pub struct SetupProps {
    pub info: SetupInfo,
}

/// Copy-pasteable configuration snippets for the common consumers of this
/// server. Everything is rendered with the real server URLs so it can be
/// pasted verbatim.
#[function_component(SetupView)]
pub fn setup_view(props: &SetupProps) -> Html {
    let info = &props.info;

    let debuginfod = format!(
        "# Point elfutils, gdb, and anything else debuginfod-aware at this server.\n\
         export DEBUGINFOD_URLS=\"{}\"\n\n\
         # Or persist it system-wide:\n\
         echo \"{}\" | sudo tee /etc/debuginfod/symbols.urls",
        info.internal_url, info.internal_url
    );

    let gdb = "# gdb ≥ 10 picks up DEBUGINFOD_URLS automatically; enable without prompting:\n\
               set debuginfod enabled on"
        .to_string();

    let pyroscope = format!(
        "# Pyroscope (OTel eBPF profiler) symbolizer configuration — native\n\
         # frames are resolved by build ID against this server.\n\
         symbolizer:\n\
         \x20 debuginfod_url: {}",
        info.internal_url
    );

    let action = format!(
        "# Publish symbols from a release workflow. The build ID is derived\n\
         # server-side from the file itself; auth is the workflow's OIDC token.\n\
         permissions:\n\
         \x20 id-token: write\n\n\
         steps:\n\
         \x20 - name: cargo build\n\
         \x20   env:\n\
         \x20     CARGO_PROFILE_RELEASE_STRIP: none   # keep debug info for the split\n\
         \x20   run: cargo build --release --target ${{{{ matrix.target }}}}\n\n\
         \x20 - uses: SierraSoftworks/symbols@v1\n\
         \x20   if: github.event_name == 'release'\n\
         \x20   with:\n\
         \x20     binary: target/${{{{ matrix.target }}}}/release/my-app\n\
         \x20     version: ${{{{ github.event.release.tag_name }}}}\n\
         \x20     server: {}\n\
         \x20     audience: {}",
        info.public_url, info.github_audience
    );

    let curl = format!(
        "# Fetch the debug info for a build ID by hand:\n\
         curl -fLo my-app.debug {}/buildid/<build-id>/debuginfo",
        info.internal_url
    );

    html! {
        <div class="content">
            <div class="page-head">
                <h1 class="page-head__title">{"Setup"}</h1>
                <span class="page-head__meta">
                    {"How to publish symbols to this server and consume them from your tooling."}
                </span>
            </div>

            <section class="card">
                <h2 class="card__title">{"Debuggers and elfutils"}</h2>
                <p>
                    {"The internal plane serves every project's symbols (plus federated \
                      distro symbols) over the standard debuginfod protocol."}
                </p>
                <Snippet id="snippet-debuginfod" lang="bash" code={debuginfod} />
                <Snippet id="snippet-gdb" lang="gdb" code={gdb} />
            </section>

            <section class="card">
                <h2 class="card__title">{"Pyroscope / continuous profiling"}</h2>
                <p>
                    {"Point the profiler's symbolizer at the internal plane so native \
                      stack frames in profiles resolve to source lines."}
                </p>
                <Snippet id="snippet-pyroscope" lang="yaml" code={pyroscope} />
            </section>

            <section class="card">
                <h2 class="card__title">{"Publishing from GitHub Actions"}</h2>
                <p>
                    {"Repositories in a trusted organization publish with the co-located \
                      action — no secrets required. The project appears here automatically \
                      on first upload."}
                </p>
                <Snippet id="snippet-action" lang="yaml" code={action} />
            </section>

            <section class="card">
                <h2 class="card__title">{"Manual lookup"}</h2>
                <Snippet id="snippet-curl" lang="bash" code={curl} />
            </section>
        </div>
    }
}
