//! Deterministic file tree rebuilt by replaying the commit log.
//!
//! The server totally orders encrypted [`Commit`]s by sequence number. Every
//! client replays them with exactly the same rules, so all clients converge on
//! the same tree without the server understanding anything about it:
//!
//! * Each node has a random 128-bit id; renames/moves are a single `Put`.
//! * Every op carries `base` = the node version (seq) the author last saw.
//!   A `Put` on a file whose current version differs from `base` with
//!   different content is a concurrent edit: the older version is preserved as
//!   a derived "conflict copy" node and the newer one wins the name
//!   (Syncthing-style, but derived so no extra writes are needed).
//! * A `Delete` loses against a concurrent file modification; a directory
//!   delete is skipped while the directory still has children.
//! * Writing into a deleted directory resurrects it.
//! * Moves that would create a cycle are rejected.
//! * Two live siblings with the same (case-insensitive) name: the oldest keeps
//!   the name, the others are displayed as `name (dup-xxxxxxxx).ext`.

use crate::crypto::{self, ChunkId, KeyRing};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub type NodeId = u128;
pub const ROOT: NodeId = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Dir,
    File,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: NodeId,
    pub parent: NodeId,
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    pub chunks: Vec<ChunkId>,
    /// Windows file attributes (FILE_ATTRIBUTE_*), excluding DIRECTORY.
    pub attributes: u32,
    /// Windows FILETIME (100 ns ticks since 1601-01-01 UTC).
    pub created: u64,
    pub modified: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    Put { entry: Entry, base: u64 },
    Delete { id: NodeId, base: u64 },
}

/// One log record. The chain fields (`prev`, `head`) are inside the AEAD, so
/// the server, which only sees ciphertext, cannot change where in the history
/// a record claims to sit; see [`ChainState`] for how readers check them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    /// Random id; lets a client recognise its own commits in the log.
    pub id: [u8; 16],
    pub device_id: String,
    pub device_name: String,
    /// Unix seconds.
    pub time: u64,
    pub ops: Vec<Op>,
    /// [`record_hash`] of the record at `head` as the author saw it:
    /// [`GENESIS`] for the first record of a vault, and also when the author
    /// resumed from a snapshot written before chaining and could not learn
    /// the hash (see [`ChainState::advance`]).
    pub prev: ChainHash,
    /// Log position the author observed: this record expects to land at
    /// `head + 1`. The server refuses an append whose `head` is stale, so
    /// concurrent authors never produce two records for one position.
    pub head: u64,
}

/// Record layout before chaining; still readable, and what clients from
/// before this change read a chained record as (they ignore the trailing
/// chain fields).
#[derive(Serialize, Deserialize)]
struct LegacyCommit {
    id: [u8; 16],
    device_id: String,
    device_name: String,
    time: u64,
    ops: Vec<Op>,
}

/// A decrypted log record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub commit: Commit,
    /// Key epoch the record was sealed under (authenticated).
    pub epoch: u32,
    /// Whether the record carries chain fields. Records written before this
    /// change don't; they decrypt with `prev = GENESIS`, `head = 0`.
    pub chained: bool,
}

fn commit_aad(vault: &str) -> Vec<u8> {
    format!("kybersync-commit-v1:{vault}").into_bytes()
}

impl Commit {
    /// Encrypt under the ring's current key epoch (the epoch is visible in the
    /// record header so the server can refuse records under a retired key).
    pub fn encrypt(&self, ring: &KeyRing, vault: &str) -> Vec<u8> {
        let pt = postcard::to_allocvec(self).expect("commit serialization");
        ring.seal_with(|k| &k.meta, &commit_aad(vault), &pt)
    }

    /// Decrypt a record of any epoch the ring holds (legacy records are epoch 0).
    pub fn decrypt(ring: &KeyRing, vault: &str, data: &[u8]) -> Result<Self> {
        Self::decrypt_record(ring, vault, data).map(|r| r.commit)
    }

    /// Like [`Commit::decrypt`], also telling the epoch and whether the record
    /// is chained. A record from before this change lacks the chain fields, so
    /// parsing it as a [`Commit`] runs out of bytes; it is then parsed as a
    /// [`LegacyCommit`]. The other direction is impossible: a chained record
    /// always parses as a `Commit` first.
    pub fn decrypt_record(ring: &KeyRing, vault: &str, data: &[u8]) -> Result<Record> {
        let (epoch, pt) = ring.open_with(|k| &k.meta, &commit_aad(vault), data)?;
        if let Ok(commit) = postcard::from_bytes::<Commit>(&pt) {
            return Ok(Record { commit, epoch, chained: true });
        }
        let l: LegacyCommit = postcard::from_bytes(&pt).map_err(|e| Error::Malformed(e.to_string()))?;
        let commit = Commit { id: l.id, device_id: l.device_id, device_name: l.device_name, time: l.time, ops: l.ops, prev: GENESIS, head: 0 };
        Ok(Record { commit, epoch, chained: false })
    }
}

// ----- log chain -----------------------------------------------------------

pub type ChainHash = [u8; 32];
/// `prev` of the first record of a vault (and of a record whose author did
/// not know the hash of its predecessor).
pub const GENESIS: ChainHash = [0; 32];

/// Hash of a record's ciphertext that the next record's `prev` names.
pub fn record_hash(record: &[u8]) -> ChainHash {
    let mut h = blake3::Hasher::new_derive_key("kybersync 2026-10 log chain v1");
    h.update(record);
    *h.finalize().as_bytes()
}

/// A reader's position in the vault's commit chain: what the next record has
/// to connect to. Persisted implicitly: `head` and `last` are recomputed from
/// the local log copy (or taken from the snapshot it starts at), `epoch` from
/// the records replayed.
///
/// What this gives (fork consistency): a server can still withhold the tail
/// of the log from a device, and it can show two devices different histories
/// as long as they never see each other's records again. It cannot reorder,
/// drop, duplicate or renumber records inside a history a device has
/// accepted, nor splice two devices' histories together: every chained record
/// names the ciphertext hash and position of its predecessor, so the first
/// record from the other history fails [`ChainState::advance`] and the device
/// stops syncing.
///
/// Rules, in the order checked:
///
/// 1. Records are contiguous: the next record is `head + 1`.
/// 2. Key epochs never go back: a record sealed under an epoch older than one
///    already seen is refused (an honest server refuses such appends, so this
///    only blocks a revoked device colluding with the server).
/// 3. A record without chain fields (written by a client from before this
///    change) is accepted at the next position; its hash still enters the
///    chain, so the next chained record pins it. Until a chained record
///    follows, such records in the tail of the log are only protected by
///    rule 1 (the server could reorder them among themselves).
/// 4. A chained record's `head` must be the reader's `head`.
/// 5. Its `prev` must be the hash of the record at `head`, when both sides
///    know it. The reader doesn't after resuming from a snapshot that
///    predates chaining ([`Snapshot::last`] is `None`); an author in that
///    state writes `prev = GENESIS`, which is accepted at `head > 0` for that
///    reason only (the position is still bound by rule 4). Both cases exist
///    only until every device runs this version and the vault has been
///    compacted once since, after which every snapshot carries the hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainState {
    pub head: u64,
    /// Hash of the record at `head` (`GENESIS` at head 0); `None` when
    /// resumed from a snapshot written before chaining.
    pub last: Option<ChainHash>,
    /// Newest key epoch seen in the log.
    pub epoch: u32,
}

impl Default for ChainState {
    fn default() -> Self {
        Self::GENESIS
    }
}

impl ChainState {
    /// An empty vault.
    pub const GENESIS: ChainState = ChainState { head: 0, last: Some(GENESIS), epoch: 0 };

    /// The position right after `s`.
    pub fn from_snapshot(s: &Snapshot) -> Self {
        ChainState { head: s.seq, last: s.last, epoch: s.epoch }
    }

    /// `prev` for a record this reader would write next.
    pub fn prev(&self) -> ChainHash {
        self.last.unwrap_or(GENESIS)
    }

    /// Check that `rec` (decrypted from the ciphertext `data`, served at
    /// position `seq`) continues the chain, and move past it. On an error
    /// the state is unchanged.
    pub fn advance(&mut self, seq: u64, data: &[u8], rec: &Record) -> Result<()> {
        let diverged = |m: String| Error::Diverged(format!("log entry #{seq} {m}"));
        if seq != self.head + 1 {
            return Err(diverged(format!("follows #{}: the server dropped or renumbered entries", self.head)));
        }
        if rec.epoch < self.epoch {
            return Err(diverged(format!("was written under retired key epoch {} (the log is at {})", rec.epoch, self.epoch)));
        }
        if rec.chained {
            if rec.commit.head != self.head {
                return Err(diverged(format!("was written for position #{}: the server moved it", rec.commit.head + 1)));
            }
            if let Some(last) = self.last {
                if rec.commit.prev != last && !(rec.commit.prev == GENESIS && self.head > 0) {
                    return Err(diverged("does not continue the history this device has: the entry before it was altered, replaced or reordered".into()));
                }
            }
        }
        self.head = seq;
        self.last = Some(record_hash(data));
        self.epoch = self.epoch.max(rec.epoch);
        Ok(())
    }

    /// Decrypt and [`advance`](Self::advance) in one step; a record that fails
    /// authentication under a key the ring holds counts as divergence too (the
    /// server served something no device wrote).
    pub fn apply(&mut self, ring: &KeyRing, vault: &str, seq: u64, data: &[u8]) -> Result<Commit> {
        let rec = match Commit::decrypt_record(ring, vault, data) {
            Ok(r) => r,
            Err(Error::UnknownEpoch(e)) => return Err(Error::UnknownEpoch(e)),
            Err(e) => return Err(Error::Diverged(format!("log entry #{seq} fails authentication: {e}"))),
        };
        self.advance(seq, data, &rec)?;
        Ok(rec.commit)
    }
}

/// The complete replay state after applying the log up to `seq`.
///
/// Compaction: an authorized device uploads this (encrypted) and the server
/// may then drop log entries `<= seq`. A device that starts from a snapshot
/// and replays the rest of the log ends in exactly the same state as one that
/// replayed everything, because the snapshot keeps every input the replay
/// rules look at: node versions and `created_seq`s, tombstones (resurrection,
/// conflict-copy ids) and the ids of applied commits (retry de-duplication).
///
/// A device resuming from a snapshot continues the commit chain from it:
/// `last` is the hash of the record at `seq`, so the next record's `prev` can
/// be checked. The snapshot itself is trusted on the authority of the
/// authorized device that sealed it (its content cannot be checked against
/// the chain, only its position, which is in the AEAD associated data).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub seq: u64,
    pub nodes: Vec<Node>,
    pub tombstones: Vec<Node>,
    pub seen: Vec<[u8; 16]>,
    /// [`record_hash`] of the record at `seq`; `None` if the author didn't
    /// know it (it had itself resumed from a snapshot without one), and for
    /// snapshots written before chaining.
    pub last: Option<ChainHash>,
    /// Newest key epoch among the records covered (0 for legacy snapshots).
    pub epoch: u32,
}

/// Snapshot layout before chaining.
#[derive(Serialize, Deserialize)]
struct LegacySnapshot {
    seq: u64,
    nodes: Vec<Node>,
    tombstones: Vec<Node>,
    seen: Vec<[u8; 16]>,
}

fn snapshot_aad(vault: &str, seq: u64) -> Vec<u8> {
    format!("kybersync-snapshot-v1:{vault}:{seq}").into_bytes()
}

impl Snapshot {
    /// Encrypted under the current epoch and bound to `seq`, so a server can't
    /// present it as the state at a different log position.
    pub fn encrypt(&self, ring: &KeyRing, vault: &str) -> Vec<u8> {
        let pt = postcard::to_allocvec(self).expect("snapshot serialization");
        ring.seal_with(|k| &k.meta, &snapshot_aad(vault, self.seq), &pt)
    }

    /// Decrypts snapshots of either layout (see [`Commit::decrypt_record`]
    /// for why trying the current one first is unambiguous).
    pub fn decrypt(ring: &KeyRing, vault: &str, seq: u64, data: &[u8]) -> Result<Self> {
        let (_, pt) = ring.open_with(|k| &k.meta, &snapshot_aad(vault, seq), data)?;
        let s: Self = match postcard::from_bytes::<Self>(&pt) {
            Ok(s) => s,
            Err(_) => {
                let l: LegacySnapshot = postcard::from_bytes(&pt).map_err(|e| Error::Malformed(e.to_string()))?;
                Snapshot { seq: l.seq, nodes: l.nodes, tombstones: l.tombstones, seen: l.seen, last: None, epoch: 0 }
            }
        };
        if s.seq != seq {
            return Err(Error::Malformed("snapshot sequence mismatch".into()));
        }
        Ok(s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub entry: Entry,
    /// Seq of the commit that produced this version.
    pub seq: u64,
    /// Seq at which the node first appeared (decides name collisions).
    pub created_seq: u64,
    /// Device name of the last writer.
    pub author: String,
    /// Unix seconds of the last write.
    pub time: u64,
}

/// What [`Tree::restore_plan`] brings back.
#[derive(Clone, Debug, Default)]
pub struct RestorePlan {
    /// `Put`s recreating the deleted nodes, parents first.
    pub ops: Vec<Op>,
    /// Where each of `ops` puts its node.
    pub paths: Vec<String>,
    /// Paths of the files, sorted.
    pub files: Vec<String>,
    pub bytes: u64,
    pub dirs: usize,
    /// Deleted files left out because a file of the same name replaced them.
    pub replaced: usize,
}

/// Office lock files and the like, which apps delete all the time.
fn is_temp_file(e: &Entry) -> bool {
    const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
    let name = e.name.to_lowercase();
    e.attributes & FILE_ATTRIBUTE_TEMPORARY != 0 || name.starts_with("~$") || name.ends_with(".tmp")
}

#[derive(Clone, Debug)]
pub struct Tree {
    nodes: HashMap<NodeId, Node>,
    tombstones: HashMap<NodeId, Node>,
    /// parent -> lowercase name -> nodes with that name
    index: HashMap<NodeId, HashMap<String, Vec<NodeId>>>,
    /// Commit ids already applied; a retried upload can land twice in the log.
    seen: HashSet<[u8; 16]>,
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}

impl Tree {
    pub fn new() -> Self {
        let root = Node {
            entry: Entry {
                id: ROOT,
                parent: ROOT,
                name: String::new(),
                kind: Kind::Dir,
                size: 0,
                chunks: vec![],
                attributes: 0,
                created: 0,
                modified: 0,
            },
            seq: 0,
            created_seq: 0,
            author: String::new(),
            time: 0,
        };
        Self {
            nodes: HashMap::from([(ROOT, root)]),
            tombstones: HashMap::new(),
            index: HashMap::new(),
            seen: HashSet::new(),
        }
    }

    // ----- snapshots ------------------------------------------------------

    /// Capture the replay state (canonically ordered) as of log position `seq`,
    /// without chain information (comparisons, tests); devices use
    /// [`Tree::snapshot_at`].
    pub fn snapshot(&self, seq: u64) -> Snapshot {
        let mut nodes: Vec<Node> = self.nodes.values().cloned().collect();
        nodes.sort_by_key(|n| n.entry.id);
        let mut tombstones: Vec<Node> = self.tombstones.values().cloned().collect();
        tombstones.sort_by_key(|n| n.entry.id);
        let mut seen: Vec<[u8; 16]> = self.seen.iter().copied().collect();
        seen.sort();
        Snapshot { seq, nodes, tombstones, seen, last: None, epoch: 0 }
    }

    /// The replay state at `chain`, carrying its hash so that devices resuming
    /// from the snapshot continue the chain.
    pub fn snapshot_at(&self, chain: &ChainState) -> Snapshot {
        Snapshot { last: chain.last, epoch: chain.epoch, ..self.snapshot(chain.head) }
    }

    /// Rebuild a tree from a snapshot. The structure is validated (every live
    /// node hangs off a live directory, no cycles) so later replay can rely on
    /// the same invariants as a tree built from the log.
    pub fn from_snapshot(s: &Snapshot) -> Result<Self> {
        let bad = |m: &str| Error::Malformed(format!("snapshot: {m}"));
        let mut t = Tree::new();
        t.nodes.clear();
        for n in &s.nodes {
            if n.entry.kind == Kind::File && !chunks_match_size(&n.entry) {
                return Err(bad("file chunk list does not match its size"));
            }
            if t.nodes.insert(n.entry.id, n.clone()).is_some() {
                return Err(bad("duplicate node"));
            }
        }
        match t.nodes.get(&ROOT) {
            Some(r) if r.entry.kind == Kind::Dir && r.entry.parent == ROOT => {}
            _ => return Err(bad("missing root")),
        }
        for n in t.nodes.values() {
            if n.entry.id == ROOT {
                continue;
            }
            let mut cur = n.entry.parent;
            for depth in 0.. {
                match t.nodes.get(&cur) {
                    Some(p) if p.entry.kind == Kind::Dir => {}
                    _ => return Err(bad("node without a live parent directory")),
                }
                if cur == ROOT {
                    break;
                }
                if cur == n.entry.id || depth > 100_000 {
                    return Err(bad("cycle"));
                }
                cur = t.nodes[&cur].entry.parent;
            }
        }
        for n in &s.tombstones {
            if t.nodes.contains_key(&n.entry.id) || t.tombstones.insert(n.entry.id, n.clone()).is_some() {
                return Err(bad("tombstone overlaps a node"));
            }
        }
        t.seen = s.seen.iter().copied().collect();
        let ids: Vec<NodeId> = t.nodes.keys().copied().filter(|id| *id != ROOT).collect();
        for id in ids {
            t.index_insert(id);
        }
        Ok(t)
    }

    /// Every chunk a live file (conflict copies included) refers to.
    pub fn live_chunks(&self) -> HashSet<ChunkId> {
        self.nodes.values().filter(|n| n.entry.kind == Kind::File).flat_map(|n| n.entry.chunks.iter().copied()).collect()
    }

    // ----- trash ----------------------------------------------------------
    //
    // Deleted nodes stay as tombstones (with their chunk lists) and carry the
    // time of the delete, so recently deleted files can be brought back as
    // long as their chunks are still on the server.

    /// Chunks of files deleted at or after `since` (unix seconds).
    pub fn trash_chunks(&self, since: u64) -> HashSet<ChunkId> {
        self.tombstones
            .values()
            .filter(|n| n.entry.kind == Kind::File && n.time >= since)
            .flat_map(|n| n.entry.chunks.iter().copied())
            .collect()
    }

    /// Ops recreating what was deleted at or after `since` (unix seconds, by
    /// the deleting device's clock), parents before children. Temporary files
    /// are left out, and so are files whose name is taken again in the same
    /// folder (apps often save by writing a new file and deleting the old).
    /// A deleted folder whose name a live folder took is merged into it.
    pub fn restore_plan(&self, since: u64) -> RestorePlan {
        let mut deleted: Vec<&Node> = self
            .tombstones
            .values()
            .filter(|n| n.time >= since && !(n.entry.kind == Kind::File && is_temp_file(&n.entry)))
            .collect();
        // Parents first; of two deleted files with the same name the newer wins.
        deleted.sort_by_key(|n| (self.depth(n.entry.id), std::cmp::Reverse(n.time), n.entry.id));

        let mut into: HashMap<NodeId, NodeId> = HashMap::new();
        let mut placed: HashMap<(NodeId, String), (NodeId, Kind)> = HashMap::new();
        let mut plan = RestorePlan::default();
        for n in deleted {
            let mut e = n.entry.clone();
            e.parent = into.get(&e.parent).copied().unwrap_or(e.parent);
            let key = (e.parent, e.name.to_lowercase());
            let taken = self
                .index
                .get(&e.parent)
                .and_then(|m| m.get(&key.1))
                .and_then(|g| self.winner(g))
                .map(|id| (id, self.nodes[&id].entry.kind))
                .or_else(|| placed.get(&key).copied());
            match (taken, e.kind) {
                (Some((dir, Kind::Dir)), Kind::Dir) => {
                    into.insert(e.id, dir);
                    continue;
                }
                (Some(_), Kind::File) => {
                    plan.replaced += 1;
                    continue;
                }
                _ => {}
            }
            let dir = self.any_path(e.parent);
            let path = if dir == "\\" { format!("\\{}", e.name) } else { format!("{dir}\\{}", e.name) };
            match e.kind {
                Kind::Dir => plan.dirs += 1,
                Kind::File => {
                    plan.bytes += e.size;
                    plan.files.push(path.clone());
                }
            }
            plan.paths.push(path);
            placed.insert(key, (e.id, e.kind));
            plan.ops.push(Op::Put { entry: e, base: n.seq });
        }
        plan.files.sort();
        plan
    }

    /// Ancestors of a live or deleted node.
    fn depth(&self, mut id: NodeId) -> usize {
        for depth in 0..4096 {
            if id == ROOT {
                return depth;
            }
            match self.nodes.get(&id).or_else(|| self.tombstones.get(&id)) {
                Some(n) => id = n.entry.parent,
                None => return depth,
            }
        }
        4096
    }

    /// `\a\b` for a live or deleted node, by stored names.
    fn any_path(&self, mut id: NodeId) -> String {
        let mut parts = Vec::new();
        while id != ROOT && parts.len() < 4096 {
            let Some(n) = self.nodes.get(&id).or_else(|| self.tombstones.get(&id)) else { break };
            parts.push(n.entry.name.as_str());
            id = n.entry.parent;
        }
        parts.reverse();
        format!("\\{}", parts.join("\\"))
    }

    // ----- replay ---------------------------------------------------------

    pub fn apply_commit(&mut self, seq: u64, c: &Commit) {
        if !self.seen.insert(c.id) {
            return;
        }
        for op in &c.ops {
            match op {
                Op::Put { entry, base } => self.put(seq, c, entry.clone(), *base),
                Op::Delete { id, base } => self.delete(seq, c, *id, *base),
            }
        }
    }

    fn put(&mut self, seq: u64, c: &Commit, mut e: Entry, base: u64) {
        if e.id == ROOT {
            return;
        }
        e.name = sanitize_name(&e.name);
        if e.kind == Kind::Dir {
            e.size = 0;
            e.chunks.clear();
        } else if !chunks_match_size(&e) {
            // A peer (or a bug) produced a file whose chunk list doesn't cover
            // its size. Readers index chunks by offset, so applying it would
            // break every device that opens the file; drop the op instead.
            tracing::warn!(
                id = format!("{:x}", e.id),
                size = e.size,
                chunks = e.chunks.len(),
                "ignoring file entry whose chunk list does not match its size"
            );
            return;
        }
        let id = e.id;

        if let Some(n) = self.nodes.get(&id) {
            if n.entry.kind != e.kind {
                return;
            }
            // Ops inside one commit are sequential by construction, never concurrent.
            let concurrent = n.seq != base && n.seq != seq;
            if concurrent && e.kind == Kind::File && (n.entry.chunks != e.chunks || n.entry.size != e.size) {
                self.fork_conflict(id, seq);
            }
            let old = self.nodes[&id].entry.clone();
            if (e.parent != old.parent || e.name != old.name) && !self.valid_parent_for(id, e.parent) {
                e.parent = old.parent;
                e.name = old.name;
            }
            self.index_remove(id);
            let n = self.nodes.get_mut(&id).unwrap();
            n.entry = e;
            n.seq = seq;
            n.author = c.device_name.clone();
            n.time = c.time;
            self.index_insert(id);
        } else {
            let created_seq = self.tombstones.remove(&id).map(|t| t.created_seq).unwrap_or(seq);
            if !self.valid_parent_for(id, e.parent) {
                e.parent = ROOT;
            }
            self.nodes.insert(
                id,
                Node { entry: e, seq, created_seq, author: c.device_name.clone(), time: c.time },
            );
            self.index_insert(id);
        }
    }

    fn delete(&mut self, seq: u64, c: &Commit, id: NodeId, base: u64) {
        if id == ROOT {
            return;
        }
        let Some(n) = self.nodes.get(&id) else { return };
        match n.entry.kind {
            // A modification the deleter never saw wins over the delete.
            Kind::File if n.seq != base && n.seq != seq => return,
            Kind::Dir if self.index.get(&id).is_some_and(|m| !m.is_empty()) => return,
            _ => {}
        }
        self.index_remove(id);
        self.index.remove(&id);
        let mut n = self.nodes.remove(&id).unwrap();
        // A tombstone records who deleted it and when (the trash).
        n.author = c.device_name.clone();
        n.time = c.time;
        self.tombstones.insert(id, n);
    }

    fn fork_conflict(&mut self, id: NodeId, seq: u64) {
        let n = &self.nodes[&id];
        let cid = conflict_id(id, n.seq);
        if cid == ROOT || self.nodes.contains_key(&cid) || self.tombstones.contains_key(&cid) {
            return;
        }
        let mut entry = n.entry.clone();
        entry.id = cid;
        entry.name = conflict_name(&n.entry.name, &n.author, n.time);
        let node = Node { entry, seq, created_seq: seq, author: n.author.clone(), time: n.time };
        self.nodes.insert(cid, node);
        self.index_insert(cid);
    }

    /// Ensure `parent` is a live directory (resurrecting it if deleted) and
    /// that placing `id` under it would not create a cycle.
    fn valid_parent_for(&mut self, id: NodeId, parent: NodeId) -> bool {
        if parent == ROOT {
            return true;
        }
        if parent == id || !self.ensure_dir(parent, 0) {
            return false;
        }
        let mut cur = parent;
        for _ in 0..100_000 {
            if cur == ROOT {
                return true;
            }
            if cur == id {
                return false;
            }
            cur = self.nodes[&cur].entry.parent;
        }
        false
    }

    fn ensure_dir(&mut self, id: NodeId, depth: usize) -> bool {
        if id == ROOT {
            return true;
        }
        if let Some(n) = self.nodes.get(&id) {
            return n.entry.kind == Kind::Dir;
        }
        if depth > 4096 {
            return false;
        }
        match self.tombstones.get(&id) {
            Some(t) if t.entry.kind == Kind::Dir => {}
            _ => return false,
        }
        let mut t = self.tombstones.remove(&id).unwrap();
        if !self.ensure_dir(t.entry.parent, depth + 1) {
            t.entry.parent = ROOT;
        }
        self.nodes.insert(id, t);
        self.index_insert(id);
        true
    }

    fn index_insert(&mut self, id: NodeId) {
        let e = &self.nodes[&id].entry;
        self.index.entry(e.parent).or_default().entry(e.name.to_lowercase()).or_default().push(id);
    }

    fn index_remove(&mut self, id: NodeId) {
        let e = &self.nodes[&id].entry;
        let key = e.name.to_lowercase();
        if let Some(dir) = self.index.get_mut(&e.parent) {
            if let Some(v) = dir.get_mut(&key) {
                v.retain(|x| *x != id);
                if v.is_empty() {
                    dir.remove(&key);
                }
            }
        }
    }

    // ----- queries --------------------------------------------------------

    pub fn get(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    /// A deleted node, as it was when deleted.
    pub fn tombstone(&self, id: NodeId) -> Option<&Node> {
        self.tombstones.get(&id)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }

    pub fn has_children(&self, dir: NodeId) -> bool {
        self.index.get(&dir).is_some_and(|m| !m.is_empty())
    }

    fn winner<'a>(&'a self, group: &'a [NodeId]) -> Option<NodeId> {
        group.iter().copied().min_by_key(|id| (self.nodes[id].created_seq, *id))
    }

    /// Visible children of `dir` as `(display name, node)`.
    pub fn children(&self, dir: NodeId) -> Vec<(String, &Node)> {
        let mut out = Vec::new();
        if let Some(groups) = self.index.get(&dir) {
            for group in groups.values() {
                let win = self.winner(group);
                for id in group {
                    let n = &self.nodes[id];
                    let name = if Some(*id) == win { n.entry.name.clone() } else { dup_name(&n.entry.name, *id) };
                    out.push((name, n));
                }
            }
        }
        out
    }

    pub fn display_name(&self, id: NodeId) -> Option<String> {
        let n = self.nodes.get(&id)?;
        if id == ROOT {
            return Some(String::new());
        }
        let group = self.index.get(&n.entry.parent)?.get(&n.entry.name.to_lowercase())?;
        Some(if self.winner(group) == Some(id) { n.entry.name.clone() } else { dup_name(&n.entry.name, id) })
    }

    /// Case-insensitive child lookup by display name.
    pub fn lookup(&self, dir: NodeId, name: &str) -> Option<NodeId> {
        let groups = self.index.get(&dir)?;
        let lower = name.to_lowercase();
        if let Some(group) = groups.get(&lower) {
            return self.winner(group);
        }
        let (base, prefix) = parse_dup_name(&lower)?;
        let group = groups.get(&base)?;
        let win = self.winner(group);
        group.iter().copied().find(|id| Some(*id) != win && format!("{id:032x}").starts_with(&prefix))
    }

    /// Resolve a `\`- or `/`-separated path relative to the root.
    pub fn resolve(&self, path: &str) -> Option<NodeId> {
        let mut cur = ROOT;
        for comp in path.split(['\\', '/']).filter(|c| !c.is_empty()) {
            cur = self.lookup(cur, comp)?;
        }
        Some(cur)
    }

    pub fn path_of(&self, mut id: NodeId) -> Option<String> {
        let mut parts = Vec::new();
        for _ in 0..100_000 {
            if id == ROOT {
                parts.reverse();
                return Some(format!("\\{}", parts.join("\\")));
            }
            parts.push(self.display_name(id)?);
            id = self.nodes.get(&id)?.entry.parent;
        }
        None
    }

    /// All descendants of `dir`, children before parents (delete order).
    pub fn descendants_bottom_up(&self, dir: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack = vec![(dir, false)];
        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                if id != dir {
                    out.push(id);
                }
                continue;
            }
            stack.push((id, true));
            if let Some(groups) = self.index.get(&id) {
                for c in groups.values().flatten() {
                    stack.push((*c, false));
                }
            }
        }
        out
    }
}

// ----- naming helpers -------------------------------------------------------

pub fn new_node_id() -> NodeId {
    loop {
        let id = u128::from_le_bytes(crypto::random());
        if id != ROOT {
            return id;
        }
    }
}

fn conflict_id(id: NodeId, seq: u64) -> NodeId {
    let mut material = id.to_le_bytes().to_vec();
    material.extend_from_slice(&seq.to_le_bytes());
    let h = blake3::derive_key("kybersync 2026-10 conflict copy id v1", &material);
    u128::from_le_bytes(h[..16].try_into().unwrap())
}

/// Whether a file entry's chunk list covers exactly its size (one chunk per
/// started [`CHUNK_SIZE`](crate::CHUNK_SIZE) bytes).
pub fn chunks_match_size(e: &Entry) -> bool {
    e.chunks.len() as u64 == e.size.div_ceil(crate::CHUNK_SIZE as u64)
}

/// Replace characters Windows can't store so remote names always mount.
pub fn sanitize_name(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if c < ' ' || matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') { '_' } else { c })
        .collect();
    if s.is_empty() || s == "." || s == ".." {
        s = format!("_{s}");
    }
    if s.chars().count() > 255 {
        s = s.chars().take(255).collect();
    }
    s
}

pub fn valid_name(name: &str) -> bool {
    sanitize_name(name) == name
}

fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

fn dup_name(name: &str, id: NodeId) -> String {
    let (stem, ext) = split_ext(name);
    format!("{stem} (dup-{}){ext}", &format!("{id:032x}")[..8])
}

/// `"a (dup-0123abcd).txt"` -> `("a.txt", "0123abcd")`.
fn parse_dup_name(lower: &str) -> Option<(String, String)> {
    let i = lower.rfind(" (dup-")?;
    let rest = &lower[i + 6..];
    let prefix = rest.get(..8)?;
    if !prefix.bytes().all(|b| b.is_ascii_hexdigit()) || rest.as_bytes().get(8) != Some(&b')') {
        return None;
    }
    Some((format!("{}{}", &lower[..i], &rest[9..]), prefix.to_string()))
}

fn conflict_name(name: &str, author: &str, unix: u64) -> String {
    let (stem, ext) = split_ext(name);
    let author: String = author.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_').take(32).collect();
    let (y, m, d, hh, mm) = civil(unix);
    format!("{stem} (conflict {author} {y:04}-{m:02}-{d:02} {hh:02}{mm:02}){ext}")
}

/// Unix seconds -> (year, month, day, hour, minute) UTC.
fn civil(unix: u64) -> (i64, u32, u32, u32, u32) {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Howard Hinnant's days_from_civil inverse.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d, (secs / 3600) as u32, ((secs % 3600) / 60) as u32)
}

/// FILETIME offset of the Unix epoch.
pub const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

pub fn now_filetime() -> u64 {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    FILETIME_UNIX_EPOCH + (d.as_nanos() / 100) as u64
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(dev: &str, ops: Vec<Op>) -> Commit {
        Commit { id: crypto::random(), device_id: dev.into(), device_name: dev.into(), time: 1_760_000_000, ops, prev: GENESIS, head: 0 }
    }

    fn file(id: NodeId, parent: NodeId, name: &str, content: u8) -> Entry {
        Entry {
            id,
            parent,
            name: name.into(),
            kind: Kind::File,
            size: 1,
            chunks: vec![ChunkId([content; 32])],
            attributes: 0,
            created: 0,
            modified: 0,
        }
    }

    fn dir(id: NodeId, parent: NodeId, name: &str) -> Entry {
        Entry { kind: Kind::Dir, size: 0, chunks: vec![], ..file(id, parent, name, 0) }
    }

    fn put(e: Entry, base: u64) -> Op {
        Op::Put { entry: e, base }
    }

    #[test]
    fn concurrent_edit_creates_conflict_copy() {
        let mut t = Tree::new();
        t.apply_commit(1, &commit("a", vec![put(file(10, ROOT, "doc.txt", 1), 0)]));
        // Both devices edit based on seq 1.
        t.apply_commit(2, &commit("a", vec![put(file(10, ROOT, "doc.txt", 2), 1)]));
        t.apply_commit(3, &commit("b", vec![put(file(10, ROOT, "doc.txt", 3), 1)]));
        let kids = t.children(ROOT);
        assert_eq!(kids.len(), 2);
        let main = t.get(t.resolve("doc.txt").unwrap()).unwrap();
        assert_eq!(main.entry.chunks[0].0[0], 3);
        let copy = kids.iter().find(|(n, _)| n.contains("conflict a")).unwrap();
        assert_eq!(copy.1.entry.chunks[0].0[0], 2);
    }

    #[test]
    fn sequential_edits_no_conflict() {
        let mut t = Tree::new();
        t.apply_commit(1, &commit("a", vec![put(file(10, ROOT, "x", 1), 0)]));
        t.apply_commit(2, &commit("b", vec![put(file(10, ROOT, "x", 2), 1)]));
        t.apply_commit(3, &commit("a", vec![put(file(10, ROOT, "x", 3), 2)]));
        assert_eq!(t.children(ROOT).len(), 1);
    }

    #[test]
    fn modification_beats_delete() {
        let mut t = Tree::new();
        t.apply_commit(1, &commit("a", vec![put(file(10, ROOT, "x", 1), 0)]));
        t.apply_commit(2, &commit("a", vec![put(file(10, ROOT, "x", 2), 1)]));
        t.apply_commit(3, &commit("b", vec![Op::Delete { id: 10, base: 1 }]));
        assert!(t.resolve("x").is_some());
        t.apply_commit(4, &commit("b", vec![Op::Delete { id: 10, base: 2 }]));
        assert!(t.resolve("x").is_none());
    }

    #[test]
    fn write_into_deleted_dir_resurrects_it() {
        let mut t = Tree::new();
        t.apply_commit(1, &commit("a", vec![put(dir(5, ROOT, "d"), 0), put(file(6, 5, "f", 1), 0)]));
        t.apply_commit(2, &commit("a", vec![Op::Delete { id: 6, base: 1 }, Op::Delete { id: 5, base: 1 }]));
        assert!(t.resolve("d").is_none());
        t.apply_commit(3, &commit("b", vec![put(file(7, 5, "new", 1), 0)]));
        assert_eq!(t.resolve("d\\new"), Some(7));
    }

    #[test]
    fn dir_delete_skipped_when_not_empty() {
        let mut t = Tree::new();
        t.apply_commit(1, &commit("a", vec![put(dir(5, ROOT, "d"), 0)]));
        t.apply_commit(2, &commit("b", vec![put(file(6, 5, "f", 1), 0)]));
        t.apply_commit(3, &commit("a", vec![Op::Delete { id: 5, base: 1 }]));
        assert_eq!(t.resolve("d/f"), Some(6));
    }

    #[test]
    fn move_cycle_rejected() {
        let mut t = Tree::new();
        t.apply_commit(1, &commit("a", vec![put(dir(1, ROOT, "a"), 0), put(dir(2, 1, "b"), 0)]));
        t.apply_commit(2, &commit("x", vec![put(dir(1, 2, "a"), 1)]));
        assert_eq!(t.resolve("a\\b"), Some(2));
        assert_eq!(t.get(1).unwrap().entry.parent, ROOT);
    }

    #[test]
    fn duplicate_names_are_disambiguated() {
        let mut t = Tree::new();
        t.apply_commit(1, &commit("a", vec![put(file(0xaaaa_0000_0000_0000_0000_0000_0000_0000, ROOT, "Same.txt", 1), 0)]));
        t.apply_commit(2, &commit("b", vec![put(file(0xbbbb_0000_0000_0000_0000_0000_0000_0000, ROOT, "same.TXT", 2), 0)]));
        let mut names: Vec<_> = t.children(ROOT).into_iter().map(|(n, _)| n).collect();
        names.sort();
        assert_eq!(names, vec!["Same.txt".to_string(), "same (dup-bbbb0000).TXT".to_string()]);
        assert_eq!(t.lookup(ROOT, "SAME.txt"), Some(0xaaaa_0000_0000_0000_0000_0000_0000_0000));
        assert_eq!(t.lookup(ROOT, "same (dup-bbbb0000).txt"), Some(0xbbbb_0000_0000_0000_0000_0000_0000_0000));
    }

    #[test]
    fn replay_is_deterministic() {
        let commits = [
            commit("a", vec![put(dir(1, ROOT, "d"), 0), put(file(2, 1, "f", 1), 0)]),
            commit("b", vec![put(file(2, 1, "f", 2), 1)]),
            commit("a", vec![put(file(2, 1, "f", 3), 1)]),
            commit("b", vec![Op::Delete { id: 2, base: 1 }]),
        ];
        let build = || {
            let mut t = Tree::new();
            for (i, c) in commits.iter().enumerate() {
                t.apply_commit(i as u64 + 1, c);
            }
            let mut v: Vec<_> = t.children(1).into_iter().map(|(n, x)| (n, x.entry.id, x.entry.chunks.clone())).collect();
            v.sort();
            v
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn inconsistent_file_entries_are_ignored() {
        let mut t = Tree::new();
        t.apply_commit(1, &commit("a", vec![put(file(10, ROOT, "ok.txt", 1), 0)]));
        // Claims two chunks' worth of bytes but lists one chunk.
        let mut big = file(11, ROOT, "big.txt", 2);
        big.size = crate::CHUNK_SIZE as u64 + 1;
        // Claims one byte but lists no chunk.
        let mut empty = file(12, ROOT, "empty.txt", 3);
        empty.chunks.clear();
        // Overwrites an existing file with a short chunk list.
        let mut short = file(10, ROOT, "ok.txt", 4);
        short.size = 5 * crate::CHUNK_SIZE as u64;
        t.apply_commit(2, &commit("b", vec![put(big, 0), put(empty, 0), put(short, 1)]));
        assert!(t.get(11).is_none());
        assert!(t.get(12).is_none());
        assert_eq!(t.get(10).unwrap().entry.chunks, vec![ChunkId([1; 32])]);
        assert_eq!(t.get(10).unwrap().seq, 1);

        let mut snap = t.snapshot(2);
        snap.nodes.iter_mut().find(|n| n.entry.id == 10).unwrap().entry.size = 3 * crate::CHUNK_SIZE as u64;
        assert!(Tree::from_snapshot(&snap).is_err());
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_name("a/b:c"), "a_b_c");
        assert_eq!(sanitize_name(".."), "_..");
        assert!(valid_name("hello.txt"));
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1, 0, 0));
        assert_eq!(civil(1_760_659_200), (2025, 10, 17, 0, 0));
    }

    #[test]
    fn commit_encryption() {
        let ring = KeyRing::new(0, crypto::VaultKey::generate());
        let c = commit("a", vec![put(file(1, ROOT, "x", 1), 0)]);
        let enc = c.encrypt(&ring, "v");
        assert_eq!(Commit::decrypt(&ring, "v", &enc).unwrap(), c);
        assert!(Commit::decrypt(&ring, "other", &enc).is_err());
    }

    /// Seal `c` the way clients from before chaining did (no chain fields).
    fn legacy_record(ring: &KeyRing, c: &Commit) -> Vec<u8> {
        let l = LegacyCommit {
            id: c.id,
            device_id: c.device_id.clone(),
            device_name: c.device_name.clone(),
            time: c.time,
            ops: c.ops.clone(),
        };
        ring.seal_with(|k| &k.meta, &commit_aad("v"), &postcard::to_allocvec(&l).unwrap())
    }

    #[test]
    fn legacy_commit_records_are_epoch_zero() {
        let vk = crypto::VaultKey::generate();
        let c = commit("a", vec![put(file(1, ROOT, "x", 1), 0)]);
        let l = LegacyCommit { id: c.id, device_id: c.device_id.clone(), device_name: c.device_name.clone(), time: c.time, ops: c.ops.clone() };
        let legacy = crypto::seal(&vk.derive().meta, &commit_aad("v"), &postcard::to_allocvec(&l).unwrap());
        let (ring, _) = KeyRing::new(0, vk).rotate("v");
        let rec = Commit::decrypt_record(&ring, "v", &legacy).unwrap();
        assert_eq!(rec, Record { commit: c, epoch: 0, chained: false });
    }

    /// Clients from before chaining parse a chained record as a
    /// `LegacyCommit` (postcard ignores the trailing chain fields), so mixed
    /// versions keep reading each other's commits.
    #[test]
    fn old_clients_read_chained_records() {
        let ring = KeyRing::new(0, crypto::VaultKey::generate());
        let mut c = commit("a", vec![put(file(1, ROOT, "x", 1), 0)]);
        c.prev = [7; 32];
        c.head = 41;
        let enc = c.encrypt(&ring, "v");
        let (_, pt) = ring.open_with(|k| &k.meta, &commit_aad("v"), &enc).unwrap();
        let l: LegacyCommit = postcard::from_bytes(&pt).unwrap();
        assert_eq!((l.id, l.ops), (c.id, c.ops.clone()));
        let rec = Commit::decrypt_record(&ring, "v", &enc).unwrap();
        assert!(rec.chained && rec.commit == c);
    }

    // ----- log chain -------------------------------------------------------

    /// What an honest author does: seal `c` for the position after `chain`.
    fn chained(ring: &KeyRing, chain: &ChainState, mut c: Commit) -> Vec<u8> {
        c.prev = chain.prev();
        c.head = chain.head;
        c.encrypt(ring, "v")
    }

    /// An honest log of `n` chained records, as served by an honest server.
    fn honest_log(ring: &KeyRing, n: u64) -> Vec<(u64, Vec<u8>)> {
        let mut chain = ChainState::GENESIS;
        let mut log = Vec::new();
        for seq in 1..=n {
            let data = chained(ring, &chain, commit("a", vec![put(file(seq as u128, ROOT, &format!("f{seq}"), 1), 0)]));
            chain.apply(ring, "v", seq, &data).unwrap();
            log.push((seq, data));
        }
        log
    }

    fn replay(ring: &KeyRing, chain: &mut ChainState, log: &[(u64, Vec<u8>)]) -> Result<Vec<Commit>> {
        log.iter().map(|(seq, data)| chain.apply(ring, "v", *seq, data)).collect()
    }

    fn diverged(r: Result<Vec<Commit>>) -> String {
        match r {
            Err(Error::Diverged(m)) => m,
            other => panic!("expected divergence, got {other:?}"),
        }
    }

    #[test]
    fn chain_accepts_the_honest_log_and_resumes_from_snapshots() {
        let ring = KeyRing::new(0, crypto::VaultKey::generate());
        let log = honest_log(&ring, 5);
        let mut chain = ChainState::GENESIS;
        let commits = replay(&ring, &mut chain, &log).unwrap();
        assert_eq!(chain.head, 5);
        assert_eq!(chain.last, Some(record_hash(&log[4].1)));
        assert_eq!(commits[2].head, 2);
        assert_eq!(commits[2].prev, record_hash(&log[1].1));

        // A device replaying the first three records and snapshotting there
        // hands the chain to a device starting from that snapshot.
        let mut t = Tree::new();
        let mut at3 = ChainState::GENESIS;
        for (seq, c) in replay(&ring, &mut at3, &log[..3]).unwrap().iter().enumerate() {
            t.apply_commit(seq as u64 + 1, c);
        }
        let enc = t.snapshot_at(&at3).encrypt(&ring, "v");
        let snap = Snapshot::decrypt(&ring, "v", 3, &enc).unwrap();
        let mut resumed = ChainState::from_snapshot(&snap);
        assert_eq!(resumed, at3);
        replay(&ring, &mut resumed, &log[3..]).unwrap();
        assert_eq!(resumed, chain);
        // ...and refuses the server's attempt to skip record 4 after the snapshot.
        let mut resumed = ChainState::from_snapshot(&snap);
        assert!(diverged(replay(&ring, &mut resumed, &log[4..])).contains("#5 follows #3"));
    }

    #[test]
    fn chain_detects_reordered_records() {
        let ring = KeyRing::new(0, crypto::VaultKey::generate());
        let mut log = honest_log(&ring, 4);
        // Swap the contents of positions 2 and 3 (what a server does to pick
        // the winner of two concurrent edits).
        let (a, b) = (log[1].1.clone(), log[2].1.clone());
        log[1].1 = b;
        log[2].1 = a;
        let mut chain = ChainState::GENESIS;
        let m = diverged(replay(&ring, &mut chain, &log));
        assert!(m.starts_with("log entry #2 was written for position #3"), "{m}");
        assert_eq!(chain.head, 1, "state must not advance past the bad record");
    }

    #[test]
    fn chain_detects_dropped_records() {
        let ring = KeyRing::new(0, crypto::VaultKey::generate());
        let log = honest_log(&ring, 4);
        // Dropped outright: the sequence has a hole.
        let mut without_2: Vec<_> = log.clone();
        without_2.remove(1);
        let m = diverged(replay(&ring, &mut ChainState::default(), &without_2));
        assert!(m.starts_with("log entry #3 follows #1"), "{m}");
        // Dropped and the rest renumbered to hide the hole.
        let renumbered: Vec<_> = without_2.into_iter().enumerate().map(|(i, (_, d))| (i as u64 + 1, d)).collect();
        let m = diverged(replay(&ring, &mut ChainState::default(), &renumbered));
        assert!(m.starts_with("log entry #2 was written for position #3"), "{m}");
    }

    #[test]
    fn chain_detects_duplicated_records() {
        let ring = KeyRing::new(0, crypto::VaultKey::generate());
        let mut log = honest_log(&ring, 3);
        log.push((4, log[1].1.clone()));
        let m = diverged(replay(&ring, &mut ChainState::default(), &log));
        assert!(m.starts_with("log entry #4 was written for position #2"), "{m}");
    }

    #[test]
    fn chain_detects_a_substituted_record() {
        // Two devices write concurrently at head 1; an honest server keeps
        // exactly one of the records at position 2 (the other gets a 409 and
        // is re-sealed for position 3). A malicious server that stores both
        // and shows different devices different winners is caught as soon as
        // a device sees the other branch.
        let ring = KeyRing::new(0, crypto::VaultKey::generate());
        let log = honest_log(&ring, 1);
        let mut chain = ChainState::GENESIS;
        replay(&ring, &mut chain, &log).unwrap();
        let x = chained(&ring, &chain, commit("a", vec![put(file(10, ROOT, "x", 1), 0)]));
        let y = chained(&ring, &chain, commit("b", vec![put(file(11, ROOT, "y", 1), 0)]));
        // Device on the x branch: a's next record continues, b's (sealed on
        // the y branch) does not, and neither does y itself in place of x.
        let mut on_x = chain;
        on_x.apply(&ring, "v", 2, &x).unwrap();
        let mut on_y = chain;
        on_y.apply(&ring, "v", 2, &y).unwrap();
        let next_a = chained(&ring, &on_x, commit("a", vec![]));
        let next_b = chained(&ring, &on_y, commit("b", vec![]));
        let m = diverged(replay(&ring, &mut on_x.clone(), &[(3, next_b.clone())]));
        assert!(m.starts_with("log entry #3 does not continue"), "{m}");
        on_x.apply(&ring, "v", 3, &next_a).unwrap();
        assert!(diverged(replay(&ring, &mut on_y.clone(), &[(3, next_a)])).starts_with("log entry #3 does not continue"));
        on_y.apply(&ring, "v", 3, &next_b).unwrap();
        // A record the key holders never wrote fails authentication: divergence, not a skip.
        let mut forged = x.clone();
        let n = forged.len() - 1;
        forged[n] ^= 1;
        assert!(diverged(replay(&ring, &mut chain.clone(), &[(2, forged)])).contains("fails authentication"));
    }

    #[test]
    fn unchained_records_are_pinned_by_the_next_chained_one() {
        // A vault written by clients from before chaining, then upgraded.
        let ring = KeyRing::new(0, crypto::VaultKey::generate());
        let legacy: Vec<(u64, Vec<u8>)> = (1..=3u64)
            .map(|seq| (seq, legacy_record(&ring, &commit("a", vec![put(file(seq as u128, ROOT, &format!("f{seq}"), 1), 0)]))))
            .collect();
        let mut chain = ChainState::GENESIS;
        replay(&ring, &mut chain, &legacy).unwrap();
        assert_eq!(chain, ChainState { head: 3, last: Some(record_hash(&legacy[2].1)), epoch: 0 });
        // Still contiguous: a dropped legacy record is a hole.
        assert!(diverged(replay(&ring, &mut ChainState::default(), &[legacy[0].clone(), legacy[2].clone()])).contains("#3 follows #1"));
        // The first chained record names the last legacy one, so swapping
        // legacy records 2 and 3 underneath it is caught there.
        let first = chained(&ring, &chain, commit("a", vec![]));
        let mut swapped = legacy.clone();
        let (a, b) = (swapped[1].1.clone(), swapped[2].1.clone());
        swapped[1].1 = b;
        swapped[2].1 = a;
        swapped.push((4, first.clone()));
        assert!(diverged(replay(&ring, &mut ChainState::default(), &swapped)).starts_with("log entry #4 does not continue"));
        // An unchained record from a not-yet-upgraded client after chained
        // ones is accepted and pinned by the next chained record in turn.
        chain.apply(&ring, "v", 4, &first).unwrap();
        let late = legacy_record(&ring, &commit("b", vec![]));
        chain.apply(&ring, "v", 5, &late).unwrap();
        let after = chained(&ring, &chain, commit("a", vec![]));
        let mut other = ChainState::GENESIS;
        replay(&ring, &mut other, &legacy).unwrap();
        other.apply(&ring, "v", 4, &first).unwrap();
        assert!(diverged(replay(&ring, &mut other.clone(), &[(5, after.clone())])).contains("position #6"));
        other.apply(&ring, "v", 5, &late).unwrap();
        other.apply(&ring, "v", 6, &after).unwrap();
        chain.apply(&ring, "v", 6, &after).unwrap();
        assert_eq!(other, chain);
    }

    #[test]
    fn resuming_from_a_legacy_snapshot_skips_only_the_first_prev_check() {
        let ring = KeyRing::new(0, crypto::VaultKey::generate());
        let log = honest_log(&ring, 4);
        let mut t = Tree::new();
        let mut chain = ChainState::GENESIS;
        for (seq, c) in replay(&ring, &mut chain, &log[..2]).unwrap().iter().enumerate() {
            t.apply_commit(seq as u64 + 1, c);
        }
        let l = LegacySnapshot { seq: 2, nodes: t.snapshot(2).nodes, tombstones: vec![], seen: t.snapshot(2).seen };
        let enc = ring.seal_with(|k| &k.meta, &snapshot_aad("v", 2), &postcard::to_allocvec(&l).unwrap());
        let snap = Snapshot::decrypt(&ring, "v", 2, &enc).unwrap();
        assert_eq!((snap.last, snap.epoch, snap.nodes.len()), (None, 0, 3)); // root + 2 files
        let mut resumed = ChainState::from_snapshot(&snap);
        assert_eq!(resumed.last, None);
        // Position is still checked for record 3; its prev can't be.
        assert!(diverged(replay(&ring, &mut resumed.clone(), &[(3, log[3].1.clone())])).contains("position #4"));
        replay(&ring, &mut resumed, &log[2..]).unwrap();
        assert_eq!(resumed, chain_after(&ring, &log));
        // A device in that state writes prev = GENESIS, which devices that
        // know the hash accept (and pin by position); from then on everyone
        // knows the hash again.
        let mut unknown = ChainState::from_snapshot(&snap);
        let zero_prev = chained(&ring, &unknown, commit("c", vec![]));
        let mut full = ChainState::GENESIS;
        replay(&ring, &mut full, &log[..2]).unwrap();
        full.apply(&ring, "v", 3, &zero_prev).unwrap();
        unknown.apply(&ring, "v", 3, &zero_prev).unwrap();
        assert_eq!(full, unknown);
        assert!(full.last.is_some());
        assert!(diverged(replay(&ring, &mut full.clone(), &[(4, zero_prev)])).contains("position #3"));
    }

    fn chain_after(ring: &KeyRing, log: &[(u64, Vec<u8>)]) -> ChainState {
        let mut c = ChainState::GENESIS;
        replay(ring, &mut c, log).unwrap();
        c
    }

    #[test]
    fn records_under_a_retired_epoch_are_refused() {
        let r0 = KeyRing::new(0, crypto::VaultKey::generate());
        let (r1, _) = r0.rotate("v");
        let mut chain = ChainState::GENESIS;
        let first = chained(&r0, &chain, commit("a", vec![]));
        chain.apply(&r1, "v", 1, &first).unwrap();
        let rotated = chained(&r1, &chain, commit("a", vec![]));
        chain.apply(&r1, "v", 2, &rotated).unwrap();
        assert_eq!(chain.epoch, 1);
        // The revoked device (epoch-0 key) colludes with the server to append
        // a correctly chained record under the old key.
        let stale = chained(&r0, &chain, commit("revoked", vec![]));
        let m = diverged(replay(&r1, &mut chain.clone(), &[(3, stale)]));
        assert!(m.contains("retired key epoch 0"), "{m}");
        let legacy_stale = legacy_record(&r0, &commit("revoked", vec![]));
        assert!(diverged(replay(&r1, &mut chain.clone(), &[(3, legacy_stale)])).contains("retired key epoch 0"));
        // Epoch tracking survives a snapshot.
        let snap = Tree::new().snapshot_at(&chain);
        assert_eq!(ChainState::from_snapshot(&Snapshot::decrypt(&r1, "v", 2, &snap.encrypt(&r1, "v")).unwrap()), chain);
        // A reader without the new key reports that, not divergence.
        let revoked = KeyRing::new(0, r0.current_key().clone());
        let mut c = ChainState::GENESIS;
        c.apply(&revoked, "v", 1, &first).unwrap();
        assert!(matches!(c.apply(&revoked, "v", 2, &rotated), Err(Error::UnknownEpoch(1))));
    }

    #[test]
    fn commits_after_rotation_unreadable_with_revoked_key() {
        let before = KeyRing::new(0, crypto::VaultKey::generate());
        let old = commit("a", vec![put(file(1, ROOT, "x", 1), 0)]).encrypt(&before, "v");
        // Device b is revoked: the remaining devices move to epoch 1.
        let (after, link) = before.rotate("v");
        let new = commit("a", vec![put(file(1, ROOT, "x", 2), 1)]).encrypt(&after, "v");
        assert_eq!(crypto::record_epoch(&new), Some(1));

        // b still holds the epoch-0 key and can't read anything written since.
        let revoked = KeyRing::new(0, before.current_key().clone());
        assert!(matches!(Commit::decrypt(&revoked, "v", &new), Err(Error::UnknownEpoch(1))));
        assert!(Commit::decrypt(&revoked, "v", &old).is_ok());

        // A device joining in epoch 1 gets only the new key, and reads all history via the chain.
        let joined = KeyRing::from_chain("v", 1, after.current_key().clone(), &[link]).unwrap();
        assert!(Commit::decrypt(&joined, "v", &old).is_ok());
        assert!(Commit::decrypt(&joined, "v", &new).is_ok());
    }

    fn history() -> Vec<Commit> {
        let mut retried = commit("b", vec![put(file(30, 1, "retry.txt", 9), 0)]);
        retried.time += 1;
        vec![
            commit("a", vec![put(dir(1, ROOT, "d"), 0), put(file(2, 1, "f.txt", 1), 0)]),
            commit("b", vec![put(file(2, 1, "f.txt", 2), 1)]),
            commit("a", vec![put(file(2, 1, "f.txt", 3), 1)]), // concurrent: conflict copy
            retried.clone(),
            commit("b", vec![put(dir(5, ROOT, "gone"), 0), put(file(6, 5, "x", 1), 0)]),
            commit("b", vec![Op::Delete { id: 6, base: 5 }, Op::Delete { id: 5, base: 5 }]),
            commit("a", vec![Op::Delete { id: 2, base: 1 }]), // loses against the newer edit
            commit("c", vec![put(file(0xbbbb << 112, ROOT, "same.txt", 4), 0)]),
            retried, // a retried upload landing twice
            commit("a", vec![put(file(7, 5, "back", 1), 0)]), // resurrects "gone"
            commit("c", vec![put(file(0xaaaa << 112, ROOT, "SAME.txt", 5), 0)]),
            commit("a", vec![put(dir(1, 5, "d"), 1)]), // move
            commit("b", vec![put(dir(5, 1, "gone"), 10)]), // would be a cycle
        ]
    }

    fn listing(t: &Tree) -> Vec<(String, NodeId, u64)> {
        let mut out: Vec<_> = t.nodes().filter_map(|n| Some((t.path_of(n.entry.id)?, n.entry.id, n.seq))).collect();
        out.sort();
        out
    }

    #[test]
    fn snapshot_then_replay_matches_full_replay() {
        let commits = history();
        let mut full = Tree::new();
        for (i, c) in commits.iter().enumerate() {
            full.apply_commit(i as u64 + 1, c);
        }
        for split in 0..=commits.len() {
            let mut prefix = Tree::new();
            for (i, c) in commits[..split].iter().enumerate() {
                prefix.apply_commit(i as u64 + 1, c);
            }
            let snap = prefix.snapshot(split as u64);
            let mut t = Tree::from_snapshot(&snap).unwrap();
            for (i, c) in commits.iter().enumerate().skip(split) {
                t.apply_commit(i as u64 + 1, c);
            }
            assert_eq!(t.snapshot(0), full.snapshot(0), "diverged when snapshotting at {split}");
            assert_eq!(listing(&t), listing(&full));
        }
        assert!(full.resolve("gone\\d\\f.txt").is_some());
        assert!(full.children(1).iter().any(|(n, _)| n.contains("conflict")));
        assert_eq!(full.live_chunks().len(), 6);
    }

    #[test]
    fn snapshot_encryption_is_bound_to_position() {
        let ring = KeyRing::new(3, crypto::VaultKey::generate());
        let mut t = Tree::new();
        t.apply_commit(1, &history()[0]);
        let enc = t.snapshot(1).encrypt(&ring, "v");
        assert_eq!(crypto::record_epoch(&enc), Some(3));
        let back = Snapshot::decrypt(&ring, "v", 1, &enc).unwrap();
        assert_eq!(listing(&Tree::from_snapshot(&back).unwrap()), listing(&t));
        assert!(Snapshot::decrypt(&ring, "v", 2, &enc).is_err());
        assert!(Snapshot::decrypt(&ring, "w", 1, &enc).is_err());
    }

    #[test]
    fn malformed_snapshots_are_rejected() {
        let mut t = Tree::new();
        t.apply_commit(1, &commit("a", vec![put(dir(1, ROOT, "d"), 0), put(file(2, 1, "f", 1), 0)]));
        let good = t.snapshot(1);
        assert!(Tree::from_snapshot(&good).is_ok());

        let mut orphan = good.clone();
        orphan.nodes.retain(|n| n.entry.id != 1);
        assert!(Tree::from_snapshot(&orphan).is_err());

        let mut cycle = good.clone();
        cycle.nodes.iter_mut().find(|n| n.entry.id == 1).unwrap().entry.parent = 2;
        cycle.nodes.iter_mut().find(|n| n.entry.id == 2).unwrap().entry.kind = Kind::Dir;
        assert!(Tree::from_snapshot(&cycle).is_err());

        let mut rootless = good;
        rootless.nodes.retain(|n| n.entry.id != ROOT);
        assert!(Tree::from_snapshot(&rootless).is_err());
    }

    fn at(time: u64, ops: Vec<Op>) -> Commit {
        Commit { time, ..commit("a", ops) }
    }

    fn del(id: NodeId, base: u64) -> Op {
        Op::Delete { id, base }
    }

    fn restore(t: &mut Tree, seq: u64, since: u64) -> RestorePlan {
        let plan = t.restore_plan(since);
        t.apply_commit(seq, &at(9_000, plan.ops.clone()));
        plan
    }

    #[test]
    fn restores_recent_deletes_only() {
        let mut t = Tree::new();
        t.apply_commit(1, &at(100, vec![put(file(10, ROOT, "old.txt", 1), 0), put(file(11, ROOT, "new.txt", 2), 0)]));
        t.apply_commit(2, &at(1_000, vec![del(10, 1)]));
        t.apply_commit(3, &at(5_000, vec![del(11, 1)]));
        assert_eq!(t.trash_chunks(4_000), HashSet::from([ChunkId([2; 32])]));
        assert_eq!(t.trash_chunks(0).len(), 2);

        let plan = restore(&mut t, 4, 4_000);
        assert_eq!(plan.files, vec![r"\new.txt".to_string()]);
        assert_eq!(t.get(11).unwrap().entry.chunks, vec![ChunkId([2; 32])]);
        assert!(t.get(10).is_none());
        // Nothing left to restore in that window.
        assert!(t.restore_plan(4_000).ops.is_empty());
    }

    #[test]
    fn restores_deleted_folders_with_their_files() {
        let mut t = Tree::new();
        t.apply_commit(1, &at(100, vec![put(dir(5, ROOT, "d"), 0), put(dir(6, 5, "e"), 0), put(file(10, 6, "f.txt", 1), 0)]));
        t.apply_commit(2, &at(1_000, vec![del(10, 1), del(6, 1), del(5, 1)]));
        let plan = restore(&mut t, 3, 500);
        assert_eq!((plan.files.as_slice(), plan.dirs), (&[r"\d\e\f.txt".to_string()][..], 2));
        assert_eq!(t.resolve(r"d\e\f.txt"), Some(10));
    }

    #[test]
    fn skips_replaced_and_temporary_files() {
        let mut t = Tree::new();
        t.apply_commit(1, &at(100, vec![put(file(10, ROOT, "doc.docx", 1), 0), put(file(12, ROOT, "~$doc.docx", 3), 0)]));
        // Saved by writing a new file and deleting the old one.
        t.apply_commit(2, &at(1_000, vec![put(file(11, ROOT, "doc.docx", 2), 0), del(10, 1), del(12, 1)]));
        let plan = t.restore_plan(0);
        assert!(plan.ops.is_empty());
        assert_eq!(plan.replaced, 1);
    }

    #[test]
    fn merges_into_a_recreated_folder() {
        let mut t = Tree::new();
        t.apply_commit(1, &at(100, vec![put(dir(5, ROOT, "Photos"), 0), put(file(10, 5, "a.jpg", 1), 0)]));
        t.apply_commit(2, &at(1_000, vec![del(10, 1), del(5, 1)]));
        t.apply_commit(3, &at(2_000, vec![put(dir(7, ROOT, "photos"), 0)]));
        let plan = restore(&mut t, 4, 500);
        assert_eq!((plan.dirs, plan.files.len()), (0, 1));
        assert_eq!(t.get(10).unwrap().entry.parent, 7);
        assert_eq!(t.children(ROOT).len(), 1);
    }

    #[test]
    fn newest_of_same_named_deletes_wins() {
        let mut t = Tree::new();
        t.apply_commit(1, &at(100, vec![put(file(10, ROOT, "a.txt", 1), 0)]));
        t.apply_commit(2, &at(1_000, vec![del(10, 1)]));
        t.apply_commit(3, &at(1_100, vec![put(file(11, ROOT, "a.txt", 2), 0)]));
        t.apply_commit(4, &at(1_200, vec![del(11, 3)]));
        let plan = restore(&mut t, 5, 0);
        assert_eq!((plan.files.len(), plan.replaced), (1, 1));
        assert_eq!(t.get(11).unwrap().entry.chunks, vec![ChunkId([2; 32])]);
    }
}
