use std::collections::HashMap;
use std::sync::Arc;

use crate::api::AppState;
use crate::errors::Error;
use crate::storage::SymbolMeta;

/// Runs the retention sweep forever on the configured interval. The first
/// sweep runs shortly after startup (rather than immediately) so a
/// crash-looping task can't hammer the store.
pub async fn run(state: Arc<AppState>) {
    let interval = state.config.retention.sweep_interval;
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = sweep(&state).await {
            tracing::warn!(error = %e, "Retention sweep failed");
        }
    }
}

/// What a sweep did — surfaced in the management API/UI when a sweep is run
/// manually.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct SweepSummary {
    pub symbols_pruned: usize,
    pub upstream_dropped: usize,
    /// Abandoned upload sessions removed, chunks and all.
    pub staging_dropped: usize,
}

pub async fn sweep(state: &AppState) -> Result<SweepSummary, Error> {
    let default_keep = state.config.retention.default_keep_versions.max(1);
    let mut summary = SweepSummary::default();

    for project in state.store.list_projects().await? {
        let keep = project.keep_versions.unwrap_or(default_keep).max(1);
        let symbols = state.store.list_symbols(&project.name).await?;
        for stale in select_stale(&symbols, keep) {
            tracing::info!(
                project = %project.name,
                build_id = %stale.id,
                version = %stale.version,
                "Pruning symbols past the retention window"
            );
            state.store.delete_symbol(&project.name, &stale.id).await?;
            summary.symbols_pruned += 1;
        }
    }

    let cutoff = chrono::Utc::now()
        - chrono::Duration::from_std(state.config.retention.upstream_cache_max_age)
            .unwrap_or_else(|_| chrono::Duration::days(90));
    summary.upstream_dropped = state.store.prune_upstream(cutoff).await?;
    if summary.upstream_dropped > 0 {
        tracing::info!(dropped = summary.upstream_dropped, "Pruned upstream federation cache");
    }

    // Any session still staged after this long belongs to an uploader that
    // died mid-flight (or a result nobody polled); a healthy session lives
    // for minutes. Whole sessions go at once, so a trickling upload can
    // never decay into orphaned chunks.
    let staging_cutoff = chrono::Utc::now()
        - chrono::Duration::from_std(state.config.retention.upload_staging_max_age)
            .unwrap_or_else(|_| chrono::Duration::days(1));
    summary.staging_dropped = state.store.prune_staging(staging_cutoff).await?;
    if summary.staging_dropped > 0 {
        tracing::info!(dropped = summary.staging_dropped, "Pruned abandoned upload staging");
    }

    Ok(summary)
}

/// Groups symbols by version tag and returns those belonging to versions
/// beyond the newest `keep` (a version's age is its newest upload). Grouping
/// by version rather than by symbol keeps all architectures of a release
/// together — one release counts once against the retention budget.
fn select_stale(symbols: &[SymbolMeta], keep: usize) -> Vec<&SymbolMeta> {
    let mut versions: HashMap<&str, chrono::DateTime<chrono::Utc>> = HashMap::new();
    for symbol in symbols {
        let entry = versions.entry(symbol.version.as_str()).or_insert(symbol.uploaded_at);
        *entry = (*entry).max(symbol.uploaded_at);
    }

    let mut ordered: Vec<(&str, chrono::DateTime<chrono::Utc>)> = versions.into_iter().collect();
    ordered.sort_by_key(|(_, newest)| std::cmp::Reverse(*newest));
    let retained: std::collections::HashSet<&str> =
        ordered.iter().take(keep).map(|(v, _)| *v).collect();

    symbols
        .iter()
        .filter(|s| !retained.contains(s.version.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::SymbolFormat;
    use chrono::{Duration, Utc};

    fn symbol(id: &str, version: &str, age_days: i64) -> SymbolMeta {
        SymbolMeta {
            id: id.to_string(),
            format: SymbolFormat::Elf,
            arch: None,
            version: version.to_string(),
            size: 1,
            compression: crate::compression::Compression::Gzip,
            stored_size: Some(1),
            uploaded_at: Utc::now() - Duration::days(age_days),
            uploaded_from: None,
            os: None,
            commit: None,
            build_url: None,
        }
    }

    #[test]
    fn keeps_newest_versions_with_all_architectures() {
        let symbols = vec![
            symbol("a1", "v3", 1),
            symbol("a2", "v3", 1), // second arch of v3
            symbol("b1", "v2", 5),
            symbol("c1", "v1", 9),
            symbol("c2", "v1", 9),
        ];

        let stale: Vec<&str> = select_stale(&symbols, 2).iter().map(|s| s.id.as_str()).collect();
        assert_eq!(stale, vec!["c1", "c2"]);
    }

    #[test]
    fn untagged_uploads_form_one_group() {
        let symbols = vec![
            symbol("a", "", 1),
            symbol("b", "", 30),
            symbol("c", "v1", 2),
        ];
        // keep=2 keeps the "" group and "v1" — nothing stale.
        assert!(select_stale(&symbols, 2).is_empty());
    }

    #[test]
    fn keep_is_at_least_one() {
        let symbols = vec![symbol("a", "v1", 1)];
        assert!(select_stale(&symbols, 1).is_empty());
    }
}
