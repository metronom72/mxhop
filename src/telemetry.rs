use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

pub const DEFAULT_FILTER: &str = "info";

pub fn filter(spec: Option<&str>) -> EnvFilter {
    match spec {
        Some(spec) => EnvFilter::try_new(spec).unwrap_or_else(|_| {
            eprintln!("mxhop: log filter {spec:?} makes no sense, using {DEFAULT_FILTER:?}");
            EnvFilter::new(DEFAULT_FILTER)
        }),
        None => EnvFilter::new(DEFAULT_FILTER),
    }
}

pub fn init(spec: Option<&str>, json: bool) {
    let filter = filter(spec);
    if json {
        fmt().json().with_env_filter(filter).init();
    } else {
        fmt().with_env_filter(filter).init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_spec_it_logs_at_info() {
        assert_eq!(filter(None).to_string(), DEFAULT_FILTER);
    }

    #[test]
    fn a_valid_spec_is_kept() {
        let f = filter(Some("mxhop::routing=debug")).to_string();
        assert!(f.contains("mxhop::routing"), "{f}");
        assert!(f.contains("debug"), "{f}");
    }

    #[test]
    fn nonsense_falls_back_instead_of_failing() {
        assert_eq!(
            filter(Some("=,,,=")).to_string(),
            DEFAULT_FILTER,
            "a typo in a log level is not a reason to refuse to run"
        );
    }
}
