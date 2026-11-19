use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub struct Counter {
    name: &'static str,
    help: &'static str,
    value: AtomicU64,
}

impl Counter {
    const fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: AtomicU64::new(0),
        }
    }

    pub fn hit(&self) {
        self.add(1);
    }

    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

pub struct Gauge {
    name: &'static str,
    help: &'static str,
    value: AtomicU64,
}

impl Gauge {
    const fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: AtomicU64::new(0),
        }
    }

    pub fn set(&self, n: u64) {
        self.value.store(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

pub const BUCKETS: [f64; 9] = [0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

pub struct Histogram {
    name: &'static str,
    help: &'static str,
    buckets: [AtomicU64; BUCKETS.len()],
    count: AtomicU64,
    millis: AtomicU64,
}

impl Histogram {
    const fn new(name: &'static str, help: &'static str) -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            name,
            help,
            buckets: [ZERO; BUCKETS.len()],
            count: AtomicU64::new(0),
            millis: AtomicU64::new(0),
        }
    }

    pub fn took(&self, how_long: Duration) {
        let seconds = how_long.as_secs_f64();
        for (slot, edge) in self.buckets.iter().zip(BUCKETS) {
            if seconds <= edge {
                slot.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.millis
            .fetch_add(how_long.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

macro_rules! counters {
    ($($name:ident => $metric:literal, $help:literal;)*) => {
        $(pub static $name: Counter = Counter::new($metric, $help);)*
        static ALL_COUNTERS: &[&Counter] = &[$(&$name),*];
    };
}

macro_rules! gauges {
    ($($name:ident => $metric:literal, $help:literal;)*) => {
        $(pub static $name: Gauge = Gauge::new($metric, $help);)*
        static ALL_GAUGES: &[&Gauge] = &[$(&$name),*];
    };
}

macro_rules! histograms {
    ($($name:ident => $metric:literal, $help:literal;)*) => {
        $(pub static $name: Histogram = Histogram::new($metric, $help);)*
        static ALL_HISTOGRAMS: &[&Histogram] = &[$(&$name),*];
    };
}

counters! {
    SESSIONS => "mxhop_sessions_total", "Inbound SMTP connections served.";
    SESSIONS_TLS => "mxhop_sessions_tls_total", "Inbound connections that reached STARTTLS.";
    SESSIONS_FAILED => "mxhop_sessions_failed_total", "Inbound connections that ended in an error.";
    MESSAGES_ACCEPTED => "mxhop_messages_accepted_total", "Messages taken at end of DATA.";
    MESSAGES_REFUSED => "mxhop_messages_refused_total", "Messages refused at end of DATA.";
    RECIPIENTS_DELIVERED => "mxhop_recipients_delivered_total", "Recipient copies a destination took.";
    RECIPIENTS_DEFERRED => "mxhop_recipients_deferred_total", "Recipient copies a destination deferred.";
    RECIPIENTS_REFUSED => "mxhop_recipients_refused_total", "Recipient copies a destination refused for good.";
    QUEUE_SWEEPS => "mxhop_queue_sweeps_total", "Queue sweeps run.";
    QUEUE_RETRIES => "mxhop_queue_retries_total", "Delivery attempts made from the queue.";
    QUEUE_FROZEN => "mxhop_queue_frozen_total", "Messages given up on and moved to frozen/.";
    REPORTS_SENT => "mxhop_reports_queued_total", "Delivery reports written to the queue.";
    REPORTS_SUPPRESSED => "mxhop_reports_suppressed_total", "Failures no report was sent for.";
    AUTH_REFUSALS => "mxhop_auth_refusals_total", "Messages refused by the DMARC rule.";
}

gauges! {
    QUEUE_DEPTH => "mxhop_queue_depth", "Messages waiting in queue/ at the last sweep.";
    SESSIONS_OPEN => "mxhop_sessions_open", "Inbound connections being served right now.";
}

histograms! {
    SESSION_SECONDS => "mxhop_session_seconds", "How long an inbound session lasted.";
    DELIVERY_SECONDS => "mxhop_delivery_seconds", "How long one destination group took.";
}

pub fn render() -> String {
    let mut out = String::with_capacity(4096);

    for counter in ALL_COUNTERS {
        let _ = write!(
            out,
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n",
            name = counter.name,
            help = counter.help,
            value = counter.get(),
        );
    }

    for gauge in ALL_GAUGES {
        let _ = write!(
            out,
            "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n",
            name = gauge.name,
            help = gauge.help,
            value = gauge.get(),
        );
    }

    for histogram in ALL_HISTOGRAMS {
        let _ = write!(
            out,
            "# HELP {name} {help}\n# TYPE {name} histogram\n",
            name = histogram.name,
            help = histogram.help,
        );
        for (slot, edge) in histogram.buckets.iter().zip(BUCKETS) {
            let _ = writeln!(
                out,
                "{name}_bucket{{le=\"{edge}\"}} {count}",
                name = histogram.name,
                count = slot.load(Ordering::Relaxed),
            );
        }
        let count = histogram.count.load(Ordering::Relaxed);
        let _ = write!(
            out,
            "{name}_bucket{{le=\"+Inf\"}} {count}\n\
             {name}_sum {sum}\n\
             {name}_count {count}\n",
            name = histogram.name,
            sum = histogram.millis.load(Ordering::Relaxed) as f64 / 1_000.0,
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_metric_is_named_once_and_carries_help_and_type() {
        let text = render();
        let mut names: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("# TYPE "))
            .map(|l| l.split(' ').nth(2).unwrap())
            .collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();

        assert_eq!(before, names.len(), "a metric is declared twice: {names:?}");
        assert_eq!(
            text.matches("# HELP ").count(),
            before,
            "every metric needs help text, which is what a reader sees in Grafana"
        );
        assert!(names.iter().all(|n| n.starts_with("mxhop_")), "{names:?}");
    }

    #[test]
    fn nothing_in_the_output_could_be_an_address() {
        let text = render();

        assert!(
            !text.contains('@'),
            "metrics are counts, not a log: an address in a label would be \
             published to whoever can read /metrics and would blow the \
             cardinality up besides"
        );
    }

    #[test]
    fn a_histogram_counts_each_observation_once_in_every_bucket_it_fits() {
        let h = Histogram::new("test_seconds", "help");
        h.took(Duration::from_millis(80));

        let counts: Vec<u64> = h
            .buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect();

        assert_eq!(counts, vec![0, 1, 1, 1, 1, 1, 1, 1, 1], "{counts:?}");
        assert_eq!(h.count(), 1);
    }

    #[test]
    fn a_duration_past_the_last_bucket_is_still_counted_and_summed() {
        let h = Histogram::new("test_seconds", "help");
        h.took(Duration::from_secs(45));

        assert!(h.buckets.iter().all(|b| b.load(Ordering::Relaxed) == 0));
        assert_eq!(h.count(), 1);
        assert_eq!(h.millis.load(Ordering::Relaxed), 45_000);
    }

    #[test]
    fn a_counter_adds_up() {
        let c = Counter::new("test_total", "help");
        c.hit();
        c.add(4);

        assert_eq!(c.get(), 5);
    }
}
