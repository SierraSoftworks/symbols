use chrono::{DateTime, Utc};

/// A coarse "3 days ago" for tables; the exact timestamp goes in the title
/// attribute (see [`timestamp`]) for anyone who hovers.
pub fn ago(when: DateTime<Utc>) -> String {
    let delta = Utc::now().signed_duration_since(when);
    let seconds = delta.num_seconds();
    if seconds < 0 {
        return "in the future".to_string();
    }
    match seconds {
        0..=59 => "just now".to_string(),
        60..=3599 => plural(delta.num_minutes(), "minute"),
        3600..=86_399 => plural(delta.num_hours(), "hour"),
        86_400..=2_591_999 => plural(delta.num_days(), "day"),
        _ => when.format("%Y-%m-%d").to_string(),
    }
}

pub fn timestamp(when: DateTime<Utc>) -> String {
    when.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn plural(count: i64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit} ago")
    } else {
        format!("{count} {unit}s ago")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn buckets_recent_times() {
        assert_eq!(ago(Utc::now()), "just now");
        assert_eq!(ago(Utc::now() - Duration::minutes(5)), "5 minutes ago");
        assert_eq!(ago(Utc::now() - Duration::hours(1)), "1 hour ago");
        assert_eq!(ago(Utc::now() - Duration::days(3)), "3 days ago");
    }

    #[test]
    fn old_times_become_dates() {
        let old = Utc::now() - Duration::days(60);
        assert_eq!(ago(old), old.format("%Y-%m-%d").to_string());
    }
}
