//! Transfer progress for the sync status: what is queued in each direction,
//! how fast it is moving, and roughly when it will be done.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How far back the transfer rate looks.
const WINDOW: Duration = Duration::from_secs(10);

/// Bytes moved recently, for a transfer rate, plus what moved since the
/// current batch began (for a progress bar).
#[derive(Debug, Default)]
pub struct Meter {
    samples: VecDeque<(Instant, u64)>,
    batch_done: u64,
}

impl Meter {
    pub fn record(&mut self, bytes: u64) {
        self.record_at(Instant::now(), bytes);
    }

    pub fn record_at(&mut self, now: Instant, bytes: u64) {
        self.samples.push_back((now, bytes));
        self.batch_done += bytes;
        self.prune(now);
    }

    fn prune(&mut self, now: Instant) {
        while self.samples.front().is_some_and(|(t, _)| now.duration_since(*t) > WINDOW) {
            self.samples.pop_front();
        }
    }

    /// Bytes per second over the last few seconds; `None` when nothing moved
    /// recently or there is too little to tell.
    pub fn rate_at(&mut self, now: Instant) -> Option<f64> {
        self.prune(now);
        // A sample marks the end of a transfer, so the oldest one only
        // starts the clock; the bytes after it are what moved since.
        let (start, _) = *self.samples.front()?;
        let moved: u64 = self.samples.iter().skip(1).map(|(_, b)| b).sum();
        let secs = now.duration_since(start).as_secs_f64();
        (moved > 0 && secs >= 0.5).then(|| moved as f64 / secs)
    }

    pub fn rate(&mut self) -> Option<f64> {
        self.rate_at(Instant::now())
    }

    /// Whether anything moved within the window.
    pub fn active_at(&mut self, now: Instant) -> bool {
        self.prune(now);
        !self.samples.is_empty()
    }

    pub fn batch_done(&self) -> u64 {
        self.batch_done
    }

    /// The queue ran empty: the next transfer starts a new batch.
    pub fn end_batch(&mut self) {
        self.batch_done = 0;
    }
}

/// One direction of sync work.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Direction {
    /// Files with content still to move.
    pub files: usize,
    /// Other changes waiting (folders, renames, deletions); uploads only.
    pub changes: usize,
    /// Bytes still to move.
    pub bytes: u64,
    /// Bytes moved since this batch began.
    pub done: u64,
    /// Recent transfer rate in bytes per second.
    pub rate: Option<f64>,
    /// Data moved in the last seconds (also without a queue, e.g. files
    /// downloaded as they are opened).
    pub active: bool,
}

impl Direction {
    pub fn idle(&self) -> bool {
        self.files == 0 && self.changes == 0 && self.bytes == 0
    }

    /// Time left at the current rate.
    pub fn eta(&self) -> Option<Duration> {
        if self.bytes == 0 {
            return None;
        }
        let rate = self.rate.filter(|r| *r > 0.0)?;
        Some(Duration::from_secs_f64(self.bytes as f64 / rate))
    }

    /// Share of the batch done, 0..=1; `None` when there is no batch.
    pub fn fraction(&self) -> Option<f32> {
        let total = self.bytes + self.done;
        (self.bytes > 0).then(|| self.done as f32 / total as f32)
    }

    /// "12 files, 340 MB" (or "3 changes" when no content is left).
    pub fn what(&self) -> String {
        let mut parts = Vec::new();
        if self.files > 0 {
            parts.push(count(self.files, "file", "files"));
        }
        if self.bytes > 0 {
            parts.push(bytes(self.bytes));
        }
        if parts.is_empty() && self.changes > 0 {
            parts.push(count(self.changes, "change", "changes"));
        }
        parts.join(", ")
    }

    /// "4.2 MB/s, about 3 min left", or what is known of it.
    pub fn when(&self) -> Option<String> {
        match (self.rate, self.eta()) {
            (Some(r), Some(eta)) => Some(format!("{}, {} left", rate(r), duration(eta))),
            (Some(r), None) => Some(rate(r)),
            _ => None,
        }
    }

    /// One line for menus and tooltips: "12 files, 340 MB, about 3 min left".
    pub fn summary(&self) -> String {
        let what = self.what();
        match self.eta() {
            Some(eta) if !what.is_empty() => format!("{what}, {} left", duration(eta)),
            _ => what,
        }
    }
}

/// Sync work of one vault, both ways.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SyncProgress {
    pub up: Direction,
    pub down: Direction,
    /// Downloads happen as files are opened, so there is no download queue.
    pub on_demand: bool,
}

impl SyncProgress {
    pub fn idle(&self) -> bool {
        self.up.idle() && self.down.idle()
    }

    /// The work of several vaults as one; `None` for no vault. Queues and
    /// rates add up, so the time left covers all of them together.
    pub fn total(all: impl IntoIterator<Item = SyncProgress>) -> Option<SyncProgress> {
        all.into_iter().reduce(|mut sum, p| {
            sum.up.add(&p.up);
            sum.down.add(&p.down);
            sum.on_demand |= p.on_demand;
            sum
        })
    }
}

impl Direction {
    fn add(&mut self, o: &Direction) {
        self.files += o.files;
        self.changes += o.changes;
        self.bytes += o.bytes;
        self.done += o.done;
        self.rate = match (self.rate, o.rate) {
            (Some(a), Some(b)) => Some(a + b),
            (a, b) => a.or(b),
        };
        self.active |= o.active;
    }
}

fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// "340 MB", "1.2 GB", "12 KB".
pub fn bytes(n: u64) -> String {
    const K: f64 = 1024.0;
    let f = n as f64;
    if f < K * K {
        format!("{} KB", (f / K).ceil().max(1.0) as u64)
    } else if f < K * K * K {
        let mb = f / (K * K);
        if mb < 10.0 { format!("{mb:.1} MB") } else { format!("{mb:.0} MB") }
    } else {
        format!("{:.1} GB", f / (K * K * K))
    }
}

/// "4.2 MB/s".
pub fn rate(bytes_per_sec: f64) -> String {
    format!("{}/s", bytes(bytes_per_sec.max(0.0) as u64))
}

/// "less than a minute", "about 3 min", "about 1 h 20 min".
pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => "less than a minute".into(),
        60..3600 => format!("about {} min", s.div_ceil(60)),
        _ => {
            let m = s.div_ceil(60);
            match m % 60 {
                0 => format!("about {} h", m / 60),
                r => format!("about {} h {r} min", m / 60),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = 1024 * 1024;

    #[test]
    fn rate_counts_bytes_after_the_first_sample() {
        let t0 = Instant::now();
        let mut m = Meter::default();
        assert_eq!(m.rate_at(t0), None);
        m.record_at(t0, MB);
        assert_eq!(m.rate_at(t0 + Duration::from_secs(1)), None, "one sample only starts the clock");
        m.record_at(t0 + Duration::from_secs(1), MB);
        m.record_at(t0 + Duration::from_secs(2), MB);
        let r = m.rate_at(t0 + Duration::from_secs(2)).unwrap();
        assert!((r - MB as f64).abs() < 1.0, "{r}");
        assert_eq!(m.batch_done(), 3 * MB);
    }

    #[test]
    fn rate_fades_when_transfers_stop() {
        let t0 = Instant::now();
        let mut m = Meter::default();
        m.record_at(t0, MB);
        m.record_at(t0 + Duration::from_secs(1), MB);
        let fast = m.rate_at(t0 + Duration::from_secs(1)).unwrap();
        let slow = m.rate_at(t0 + Duration::from_secs(4)).unwrap();
        assert!(slow < fast);
        assert!(m.active_at(t0 + Duration::from_secs(4)));
        assert_eq!(m.rate_at(t0 + Duration::from_secs(30)), None);
        assert!(!m.active_at(t0 + Duration::from_secs(30)));
    }

    #[test]
    fn eta_and_fraction() {
        let d = Direction { files: 3, bytes: 30 * MB, done: 10 * MB, rate: Some(MB as f64), ..Default::default() };
        assert_eq!(d.eta(), Some(Duration::from_secs(30)));
        assert_eq!(d.fraction(), Some(0.25));
        assert_eq!(d.summary(), "3 files, 30 MB, less than a minute left");
        assert_eq!(d.when().unwrap(), "1.0 MB/s, less than a minute left");
        let stalled = Direction { rate: None, ..d.clone() };
        assert_eq!(stalled.eta(), None);
        assert_eq!(stalled.summary(), "3 files, 30 MB");
    }

    #[test]
    fn metadata_only_work_counts_changes() {
        let d = Direction { changes: 2, ..Default::default() };
        assert!(!d.idle());
        assert_eq!(d.what(), "2 changes");
        assert_eq!(d.fraction(), None);
        assert!(Direction::default().idle());
    }

    #[test]
    fn total_adds_vaults_up() {
        assert_eq!(SyncProgress::total([]), None);
        let a = SyncProgress {
            up: Direction { files: 2, bytes: 20 * MB, done: 10 * MB, rate: Some(MB as f64), active: true, ..Default::default() },
            ..Default::default()
        };
        let b = SyncProgress {
            up: Direction { files: 1, changes: 3, bytes: 10 * MB, ..Default::default() },
            down: Direction { files: 4, bytes: MB, rate: Some(2.0 * MB as f64), ..Default::default() },
            on_demand: true,
        };
        let t = SyncProgress::total([a, b]).unwrap();
        assert_eq!((t.up.files, t.up.changes, t.up.bytes, t.up.done), (3, 3, 30 * MB, 10 * MB));
        assert_eq!(t.up.rate, Some(MB as f64));
        assert!(t.up.active);
        assert_eq!(t.up.eta(), Some(Duration::from_secs(30)));
        assert_eq!((t.down.files, t.down.bytes), (4, MB));
        assert!(t.on_demand);
    }

    #[test]
    fn formatting() {
        assert_eq!(bytes(0), "1 KB");
        assert_eq!(bytes(1500), "2 KB");
        assert_eq!(bytes(5 * MB + MB / 2), "5.5 MB");
        assert_eq!(bytes(340 * MB), "340 MB");
        assert_eq!(bytes(3 * 1024 * MB / 2), "1.5 GB");
        assert_eq!(duration(Duration::from_secs(59)), "less than a minute");
        assert_eq!(duration(Duration::from_secs(61)), "about 2 min");
        assert_eq!(duration(Duration::from_secs(3600)), "about 1 h");
        assert_eq!(duration(Duration::from_secs(4800)), "about 1 h 20 min");
    }
}
