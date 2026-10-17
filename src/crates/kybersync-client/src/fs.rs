//! WinFsp filesystem presenting the decrypted vault as a drive.
//!
//! Plaintext only ever lives in memory: open files keep a per-chunk slot list
//! where modified chunks are held as plaintext buffers until they are sealed
//! (encrypted into the local chunk cache) on close/flush, or earlier when a
//! large sequential write accumulates too many dirty chunks.
//!
//! Lock order: open-file registry -> open-file data -> engine state. The
//! engine state lock is never held while taking a file lock.

use crate::engine::{ChangeAction, Engine};
use anyhow::{Context, Result};
use kybersync_core::CHUNK_SIZE;
use kybersync_core::crypto::ChunkId;
use kybersync_core::tree::{self, Entry, Kind, NodeId, Op, ROOT, new_node_id, now_filetime};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, ModificationDescriptor, OpenFileInfo,
    VolumeInfo, WideNameInfo,
};
use winfsp::host::{DebugMode, FileSystemHost, FileSystemParams, FineGuard, VolumeParams};
use winfsp::notify::{Notifier, NotifyInfo, NotifyingFileSystemContext};
use winfsp::{FspError, U16CStr};

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;
const CLEANUP_DELETE: u32 = 0x1;
const CLEANUP_SET_LAST_WRITE_TIME: u32 = 0x40;

const STATUS_OBJECT_NAME_INVALID: i32 = 0xC000_0033_u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
const STATUS_END_OF_FILE: i32 = 0xC000_0011_u32 as i32;
const STATUS_DIRECTORY_NOT_EMPTY: i32 = 0xC000_0101_u32 as i32;
const STATUS_NOT_A_DIRECTORY: i32 = 0xC000_0103_u32 as i32;
const STATUS_CANNOT_DELETE: i32 = 0xC000_0121_u32 as i32;
const STATUS_IO_DEVICE_ERROR: i32 = 0xC000_0185_u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;

const FILE_ACTION_ADDED: u32 = 1;
const FILE_ACTION_REMOVED: u32 = 2;
const FILE_ACTION_MODIFIED: u32 = 3;
const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x1;
const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x2;
const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x4;
const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x8;
const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x10;

/// Seal dirty chunks once this many accumulate in one open file.
const MAX_DIRTY_CHUNKS: usize = 32;
/// How often queued remote changes are reported to the kernel.
const NOTIFY_INTERVAL_MS: u32 = 500;
/// Longest full path (in UTF-16 units) a change notification can carry.
const NOTIFY_NAME_MAX: usize = 1024;

fn nt(code: i32) -> FspError {
    FspError::NTSTATUS(code)
}

fn io_err(e: anyhow::Error) -> FspError {
    tracing::error!("I/O error: {e:#}");
    nt(STATUS_IO_DEVICE_ERROR)
}

type FsResult<T> = winfsp::Result<T>;

// ---------------------------------------------------------------------------
// open file state
// ---------------------------------------------------------------------------

enum Slot {
    Clean(ChunkId),
    Dirty(Vec<u8>),
    Zero,
}

struct FileData {
    size: u64,
    slots: Vec<Slot>,
    /// Node version this content derives from.
    base: u64,
    dirty: bool,
    meta_dirty: bool,
    deleted: bool,
    attributes: u32,
    created: u64,
    modified: u64,
    accessed: u64,
}

pub struct OpenFile {
    node: NodeId,
    data: Mutex<FileData>,
    handles: Mutex<usize>,
}

impl FileData {
    fn from_entry(e: &Entry, seq: u64) -> Self {
        Self {
            size: e.size,
            slots: e.chunks.iter().map(|c| Slot::Clean(*c)).collect(),
            base: seq,
            dirty: false,
            meta_dirty: false,
            deleted: false,
            attributes: e.attributes,
            created: e.created,
            modified: e.modified,
            accessed: e.modified,
        }
    }
}

fn chunk_count(size: u64) -> usize {
    size.div_ceil(CHUNK_SIZE as u64) as usize
}

fn chunk_len(size: u64, i: usize) -> usize {
    let start = i as u64 * CHUNK_SIZE as u64;
    (size.saturating_sub(start)).min(CHUNK_SIZE as u64) as usize
}

pub struct Handle {
    node: NodeId,
    kind: Kind,
    file: Option<Arc<OpenFile>>,
    dir_buffer: DirBuffer,
}

// ---------------------------------------------------------------------------
// filesystem
// ---------------------------------------------------------------------------

pub struct CryptFs {
    engine: Arc<Engine>,
    sd: Vec<u8>,
    open: Mutex<HashMap<NodeId, Arc<OpenFile>>>,
    label: String,
    read_only: AtomicBool,
    /// Nodes whose deletion was requested but whose final cleanup has not
    /// been processed yet. WinFsp may deliver a parent directory's delete
    /// check before the child's cleanup, so these count as already gone.
    deleting: Mutex<HashSet<NodeId>>,
    /// Timestamp shown for the root directory.
    mounted_at: u64,
}

struct NodeInfo {
    entry: Entry,
    seq: u64,
}

impl CryptFs {
    pub fn new(engine: Arc<Engine>) -> Result<Self> {
        let label = engine.profile.vault.chars().take(32).collect();
        Ok(Self {
            engine,
            sd: default_security_descriptor()?,
            open: Mutex::default(),
            label,
            read_only: AtomicBool::new(false),
            deleting: Mutex::default(),
            mounted_at: now_filetime(),
        })
    }

    fn path_str(name: &U16CStr) -> String {
        name.to_string_lossy()
    }

    fn split(path: &str) -> (&str, &str) {
        let p = path.trim_end_matches('\\');
        match p.rfind('\\') {
            Some(i) => (&p[..i], &p[i + 1..]),
            None => ("", p),
        }
    }

    fn node_info(&self, id: NodeId) -> Option<NodeInfo> {
        let st = self.engine.state();
        st.view.get(id).map(|n| NodeInfo { entry: n.entry.clone(), seq: n.seq })
    }

    /// Resolve a path, returning the right NTSTATUS for missing parents.
    fn resolve(&self, path: &str) -> FsResult<NodeInfo> {
        let st = self.engine.state();
        if let Some(id) = st.view.resolve(path) {
            let n = st.view.get(id).unwrap();
            return Ok(NodeInfo { entry: n.entry.clone(), seq: n.seq });
        }
        let (parent, _) = Self::split(path);
        if st.view.resolve(parent).is_some() {
            Err(nt(STATUS_OBJECT_NAME_NOT_FOUND))
        } else {
            Err(nt(STATUS_OBJECT_PATH_NOT_FOUND))
        }
    }

    fn get_open(&self, info: &NodeInfo) -> Arc<OpenFile> {
        let mut open = self.open.lock().unwrap();
        let f = open
            .entry(info.entry.id)
            .or_insert_with(|| {
                Arc::new(OpenFile {
                    node: info.entry.id,
                    data: Mutex::new(FileData::from_entry(&info.entry, info.seq)),
                    handles: Mutex::new(0),
                })
            })
            .clone();
        *f.handles.lock().unwrap() += 1;
        // Pick up remote changes if nobody has local modifications pending.
        let mut d = f.data.lock().unwrap();
        if !d.dirty && !d.meta_dirty && d.base != info.seq {
            *d = FileData::from_entry(&info.entry, info.seq);
        }
        drop(d);
        f
    }

    fn fill_from_entry(&self, info: &mut FileInfo, e: &Entry) {
        // Show live size/times of files that are open with unsaved changes.
        if e.kind == Kind::File {
            if let Some(f) = self.open.lock().unwrap().get(&e.id).cloned() {
                let d = f.data.lock().unwrap();
                fill_file(info, e.id, &d);
                return;
            }
        }
        let (c, m) = if e.id == ROOT { (self.mounted_at, self.mounted_at) } else { (e.created, e.modified) };
        fill(info, e.id, e.kind, e.attributes, e.size, c, m, m);
    }

    fn fill_handle(&self, h: &Handle, info: &mut FileInfo) -> FsResult<()> {
        if let Some(f) = &h.file {
            let d = f.data.lock().unwrap();
            fill_file(info, h.node, &d);
            return Ok(());
        }
        match self.node_info(h.node) {
            Some(n) => self.fill_from_entry(info, &n.entry),
            None => fill(info, h.node, Kind::Dir, 0, 0, self.mounted_at, self.mounted_at, self.mounted_at),
        }
        Ok(())
    }

    // ----- chunk manipulation ---------------------------------------------

    /// Turn slot `i` into an owned plaintext buffer of exactly `len` bytes.
    fn materialize(&self, d: &mut FileData, i: usize, len: usize) -> Result<()> {
        if i >= d.slots.len() {
            anyhow::bail!("chunk {i} is beyond the file's chunk list ({} chunks)", d.slots.len());
        }
        let mut buf = match std::mem::replace(&mut d.slots[i], Slot::Zero) {
            Slot::Dirty(v) => v,
            Slot::Zero => Vec::new(),
            Slot::Clean(id) => match self.engine.read_chunk(&id) {
                Ok(pt) => pt.to_vec(),
                Err(e) => {
                    d.slots[i] = Slot::Clean(id);
                    return Err(e);
                }
            },
        };
        buf.resize(len, 0);
        d.slots[i] = Slot::Dirty(buf);
        Ok(())
    }

    fn resize(&self, d: &mut FileData, new_size: u64) -> Result<()> {
        let old = d.size;
        if new_size == old {
            return Ok(());
        }
        if new_size > old {
            let old_n = chunk_count(old);
            if old_n > 0 && old % CHUNK_SIZE as u64 != 0 {
                self.materialize(d, old_n - 1, chunk_len(new_size, old_n - 1))?;
            }
            d.slots.resize_with(chunk_count(new_size), || Slot::Zero);
        } else {
            let new_n = chunk_count(new_size);
            d.slots.truncate(new_n);
            if new_n > 0 && new_size % CHUNK_SIZE as u64 != 0 {
                self.materialize(d, new_n - 1, chunk_len(new_size, new_n - 1))?;
            }
        }
        d.size = new_size;
        d.dirty = true;
        Ok(())
    }

    /// Encrypt dirty chunks into the cache. With `all == false` only chunks
    /// strictly before `before` are sealed (the tail of a sequential write
    /// stays in memory).
    fn seal(&self, d: &mut FileData, all: bool, before: usize) -> Result<()> {
        let size = d.size;
        for (i, slot) in d.slots.iter_mut().enumerate() {
            if !all && i >= before {
                break;
            }
            match slot {
                Slot::Dirty(v) => {
                    debug_assert_eq!(v.len(), chunk_len(size, i));
                    *slot = Slot::Clean(self.engine.store_chunk(v)?);
                }
                Slot::Zero if all => {
                    *slot = Slot::Clean(self.engine.store_chunk(&vec![0u8; chunk_len(size, i)])?);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Persist an open file's content/metadata as a new local commit.
    fn commit_file(&self, f: &OpenFile) -> Result<()> {
        let mut d = f.data.lock().unwrap();
        if d.deleted || (!d.dirty && !d.meta_dirty) {
            return Ok(());
        }
        self.seal(&mut d, true, 0)?;
        let chunks: Vec<ChunkId> = d
            .slots
            .iter()
            .map(|s| match s {
                Slot::Clean(id) => *id,
                _ => unreachable!("sealed"),
            })
            .collect();
        let Some(node) = self.node_info(f.node) else {
            tracing::warn!("open file {:x} vanished before commit; changes dropped", f.node);
            return Ok(());
        };
        let entry = Entry {
            id: f.node,
            parent: node.entry.parent,
            name: node.entry.name.clone(),
            kind: Kind::File,
            size: d.size,
            chunks,
            attributes: d.attributes,
            created: d.created,
            modified: d.modified,
        };
        let base = self.engine.translate(d.base);
        let local = self.engine.commit(vec![Op::Put { entry, base }])?;
        d.base = local;
        d.dirty = false;
        d.meta_dirty = false;
        Ok(())
    }

    /// Whether `dir` has children that are not about to be deleted.
    fn has_live_children(&self, dir: NodeId) -> bool {
        let st = self.engine.state();
        let deleting = self.deleting.lock().unwrap();
        st.view.children(dir).iter().any(|(_, n)| !deleting.contains(&n.entry.id))
    }

    fn rebase_open(&self, id: NodeId, seq: u64) {
        if let Some(f) = self.open.lock().unwrap().get(&id).cloned() {
            f.data.lock().unwrap().base = seq;
        }
    }

    fn mark_deleted(&self, id: NodeId) {
        if let Some(f) = self.open.lock().unwrap().get(&id).cloned() {
            f.data.lock().unwrap().deleted = true;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn fill(info: &mut FileInfo, id: NodeId, kind: Kind, attrs: u32, size: u64, created: u64, modified: u64, accessed: u64) {
    info.file_attributes = match kind {
        Kind::Dir => attrs | FILE_ATTRIBUTE_DIRECTORY,
        Kind::File if attrs == 0 => FILE_ATTRIBUTE_NORMAL,
        Kind::File => attrs & !FILE_ATTRIBUTE_DIRECTORY,
    };
    info.reparse_tag = 0;
    info.file_size = size;
    info.allocation_size = size.div_ceil(4096) * 4096;
    info.creation_time = created;
    info.last_access_time = accessed;
    info.last_write_time = modified;
    info.change_time = modified;
    info.index_number = (id as u64) & 0x7FFF_FFFF_FFFF_FFFF;
    info.hard_links = 0;
    info.ea_size = 0;
}

fn fill_file(info: &mut FileInfo, id: NodeId, d: &FileData) {
    fill(info, id, Kind::File, d.attributes, d.size, d.created, d.modified, d.accessed);
}

fn lock(f: &OpenFile) -> MutexGuard<'_, FileData> {
    f.data.lock().unwrap()
}

impl FileSystemContext for CryptFs {
    type FileContext = Handle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        _resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> FsResult<FileSecurity> {
        // Never log names or paths: the log file is plaintext on disk.
        tracing::trace!(len = file_name.len(), "get_security_by_name");
        let n = self.resolve(&Self::path_str(file_name))?;
        if let Some(buf) = security_descriptor {
            if buf.len() < self.sd.len() {
                return Err(nt(STATUS_BUFFER_OVERFLOW));
            }
            unsafe { std::ptr::copy_nonoverlapping(self.sd.as_ptr(), buf.as_mut_ptr().cast::<u8>(), self.sd.len()) };
        }
        let mut info = FileInfo::default();
        fill(&mut info, n.entry.id, n.entry.kind, n.entry.attributes, 0, 0, 0, 0);
        Ok(FileSecurity { reparse: false, sz_security_descriptor: self.sd.len() as u64, attributes: info.file_attributes })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> FsResult<Handle> {
        let path = Self::path_str(file_name);
        let n = self.resolve(&path)?;
        tracing::trace!(node = format!("{:x}", n.entry.id), "open");
        if create_options & FILE_DELETE_ON_CLOSE != 0 {
            if n.entry.kind == Kind::Dir && self.has_live_children(n.entry.id) {
                return Err(nt(STATUS_DIRECTORY_NOT_EMPTY));
            }
            self.deleting.lock().unwrap().insert(n.entry.id);
        }
        let normalized = self.engine.state().view.path_of(n.entry.id);
        let file = (n.entry.kind == Kind::File).then(|| self.get_open(&n));
        let h = Handle { node: n.entry.id, kind: n.entry.kind, file, dir_buffer: DirBuffer::new() };
        self.fill_handle(&h, file_info.as_mut())?;
        if let Some(norm) = normalized {
            let wide: Vec<u16> = norm.encode_utf16().collect();
            file_info.set_normalized_name(&wide, None);
        }
        Ok(h)
    }

    fn close(&self, context: Handle) {
        self.deleting.lock().unwrap().remove(&context.node);
        if let Some(f) = context.file {
            let mut open = self.open.lock().unwrap();
            let mut handles = f.handles.lock().unwrap();
            *handles = handles.saturating_sub(1);
            if *handles == 0 {
                let d = f.data.lock().unwrap();
                if d.dirty && !d.deleted {
                    tracing::warn!("closing file {:x} with uncommitted changes", f.node);
                }
                drop(d);
                open.remove(&f.node);
            }
        }
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> FsResult<Handle> {
        let path = Self::path_str(file_name);
        let (parent_path, name) = Self::split(&path);
        if name.is_empty() || !tree::valid_name(name) {
            return Err(nt(STATUS_OBJECT_NAME_INVALID));
        }
        let parent = {
            let st = self.engine.state();
            let pid = st.view.resolve(parent_path).ok_or(nt(STATUS_OBJECT_PATH_NOT_FOUND))?;
            if st.view.get(pid).unwrap().entry.kind != Kind::Dir {
                return Err(nt(STATUS_NOT_A_DIRECTORY));
            }
            if st.view.lookup(pid, name).is_some() {
                return Err(nt(STATUS_OBJECT_NAME_COLLISION));
            }
            pid
        };
        let kind = if create_options & FILE_DIRECTORY_FILE != 0 { Kind::Dir } else { Kind::File };
        let now = now_filetime();
        let mut attributes = file_attributes & !(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NORMAL);
        if kind == Kind::File {
            attributes |= FILE_ATTRIBUTE_ARCHIVE;
        }
        let entry = Entry {
            id: new_node_id(),
            parent,
            name: name.to_string(),
            kind,
            size: 0,
            chunks: vec![],
            attributes,
            created: now,
            modified: now,
        };
        let seq = self.engine.commit(vec![Op::Put { entry: entry.clone(), base: 0 }]).map_err(io_err)?;
        let info = NodeInfo { entry, seq };
        let file = (kind == Kind::File).then(|| self.get_open(&info));
        let h = Handle { node: info.entry.id, kind, file, dir_buffer: DirBuffer::new() };
        self.fill_handle(&h, file_info.as_mut())?;
        Ok(h)
    }

    fn cleanup(&self, context: &Handle, _file_name: Option<&U16CStr>, flags: u32) {
        tracing::debug!(node = format!("{:x}", context.node), flags, "cleanup");
        if flags & CLEANUP_DELETE != 0 {
            let Some(n) = self.node_info(context.node) else { return };
            self.mark_deleted(context.node);
            let mut ops = Vec::new();
            if n.entry.kind == Kind::Dir {
                let st = self.engine.state();
                for id in st.view.descendants_bottom_up(context.node) {
                    if let Some(c) = st.view.get(id) {
                        ops.push(Op::Delete { id, base: c.seq });
                    }
                }
            }
            ops.push(Op::Delete { id: context.node, base: self.engine.translate(n.seq) });
            if let Err(e) = self.engine.commit(ops) {
                tracing::error!("delete failed: {e:#}");
            }
            self.deleting.lock().unwrap().remove(&context.node);
            return;
        }
        if let Some(f) = &context.file {
            if flags & CLEANUP_SET_LAST_WRITE_TIME != 0 {
                let mut d = lock(f);
                if d.dirty {
                    d.modified = now_filetime();
                }
            }
            if let Err(e) = self.commit_file(f) {
                tracing::error!("saving file failed: {e:#}");
            }
        }
    }

    fn flush(&self, context: Option<&Handle>, file_info: &mut FileInfo) -> FsResult<()> {
        let Some(h) = context else { return Ok(()) };
        if let Some(f) = &h.file {
            self.commit_file(f).map_err(io_err)?;
        }
        self.fill_handle(h, file_info)
    }

    fn get_file_info(&self, context: &Handle, file_info: &mut FileInfo) -> FsResult<()> {
        tracing::trace!(node = format!("{:x}", context.node), "get_file_info");
        self.fill_handle(context, file_info)
    }

    fn get_security(&self, _context: &Handle, security_descriptor: Option<&mut [c_void]>) -> FsResult<u64> {
        if let Some(buf) = security_descriptor {
            if buf.len() < self.sd.len() {
                return Err(nt(STATUS_BUFFER_OVERFLOW));
            }
            unsafe { std::ptr::copy_nonoverlapping(self.sd.as_ptr(), buf.as_mut_ptr().cast::<u8>(), self.sd.len()) };
        }
        Ok(self.sd.len() as u64)
    }

    fn set_security(&self, _context: &Handle, _info: u32, _desc: ModificationDescriptor) -> FsResult<()> {
        // ACLs are not stored; accept so applications that set them keep working.
        Ok(())
    }

    fn overwrite(
        &self,
        context: &Handle,
        file_attributes: u32,
        replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> FsResult<()> {
        let f = context.file.as_ref().ok_or(nt(STATUS_ACCESS_DENIED))?;
        let mut d = lock(f);
        d.slots.clear();
        d.size = 0;
        d.dirty = true;
        let attrs = file_attributes & !(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NORMAL);
        d.attributes = if replace_file_attributes { attrs | FILE_ATTRIBUTE_ARCHIVE } else { d.attributes | attrs | FILE_ATTRIBUTE_ARCHIVE };
        d.modified = now_filetime();
        fill_file(file_info, context.node, &d);
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Handle,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> FsResult<u32> {
        tracing::trace!(node = format!("{:x}", context.node), marker = ?marker.inner_as_cstr().map(|m| m.to_string_lossy()), len = buffer.len(), "read_directory");
        if let Ok(lock) = context.dir_buffer.acquire(marker.is_none(), None) {
            let entries: Vec<(String, Entry)> = {
                let st = self.engine.state();
                let mut v: Vec<(String, Entry)> =
                    st.view.children(context.node).into_iter().map(|(name, n)| (name, n.entry.clone())).collect();
                let deleting = self.deleting.lock().unwrap();
                v.retain(|(_, e)| !deleting.contains(&e.id));
                drop(deleting);
                if context.node != ROOT {
                    if let Some(me) = st.view.get(context.node) {
                        v.push((".".into(), me.entry.clone()));
                        let parent = st.view.get(me.entry.parent).unwrap_or(me);
                        v.push(("..".into(), parent.entry.clone()));
                    }
                }
                v
            };
            let mut di: DirInfo = DirInfo::new();
            for (name, e) in entries {
                di.reset();
                self.fill_from_entry(di.file_info_mut(), &e);
                // Not `set_name`: it counts the trailing NUL as part of the name,
                // which breaks the kernel's directory marker comparisons.
                let wide: Vec<u16> = name.encode_utf16().collect();
                if di.set_name_raw(wide.as_slice()).is_err() {
                    tracing::warn!(node = format!("{:x}", e.id), units = wide.len(), "skipping over-long name");
                    continue;
                }
                lock.write(&mut di)?;
            }
        }
        let n = context.dir_buffer.read(marker, buffer);
        tracing::trace!(n, "read_directory done");
        Ok(n)
    }

    fn rename(
        &self,
        context: &Handle,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> FsResult<()> {
        let new_path = Self::path_str(new_file_name);
        let (parent_path, name) = Self::split(&new_path);
        if name.is_empty() || !tree::valid_name(name) {
            return Err(nt(STATUS_OBJECT_NAME_INVALID));
        }
        let (ops, replaced) = {
            let st = self.engine.state();
            let me = st.view.get(context.node).ok_or(nt(STATUS_OBJECT_NAME_NOT_FOUND))?;
            let parent = st.view.resolve(parent_path).ok_or(nt(STATUS_OBJECT_PATH_NOT_FOUND))?;
            if st.view.get(parent).unwrap().entry.kind != Kind::Dir {
                return Err(nt(STATUS_NOT_A_DIRECTORY));
            }
            let mut ops = Vec::new();
            let mut replaced = None;
            if let Some(existing) = st.view.lookup(parent, name).filter(|x| *x != context.node) {
                let ex = st.view.get(existing).unwrap();
                if !replace_if_exists {
                    return Err(nt(STATUS_OBJECT_NAME_COLLISION));
                }
                if ex.entry.kind == Kind::Dir {
                    return Err(nt(STATUS_ACCESS_DENIED));
                }
                ops.push(Op::Delete { id: existing, base: ex.seq });
                replaced = Some(existing);
            }
            let mut entry = me.entry.clone();
            entry.parent = parent;
            entry.name = name.to_string();
            ops.push(Op::Put { entry, base: me.seq });
            (ops, replaced)
        };
        let seq = self.engine.commit(ops).map_err(io_err)?;
        self.rebase_open(context.node, seq);
        if let Some(r) = replaced {
            self.mark_deleted(r);
        }
        Ok(())
    }

    fn set_basic_info(
        &self,
        context: &Handle,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        _last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> FsResult<()> {
        let attrs = (file_attributes != INVALID_FILE_ATTRIBUTES)
            .then_some(file_attributes & !(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NORMAL));
        if let Some(f) = &context.file {
            let mut d = lock(f);
            if let Some(a) = attrs {
                d.attributes = a;
            }
            if creation_time != 0 {
                d.created = creation_time;
            }
            if last_write_time != 0 {
                d.modified = last_write_time;
            }
            if last_access_time != 0 {
                d.accessed = last_access_time;
            }
            d.meta_dirty = true;
            fill_file(file_info, context.node, &d);
            return Ok(());
        }
        // Directory: commit right away.
        let n = self.node_info(context.node).ok_or(nt(STATUS_OBJECT_NAME_NOT_FOUND))?;
        if context.node != ROOT {
            let mut e = n.entry.clone();
            if let Some(a) = attrs {
                e.attributes = a;
            }
            if creation_time != 0 {
                e.created = creation_time;
            }
            if last_write_time != 0 {
                e.modified = last_write_time;
            }
            if e != n.entry {
                self.engine.commit(vec![Op::Put { entry: e, base: n.seq }]).map_err(io_err)?;
            }
        }
        self.fill_handle(context, file_info)
    }

    fn set_delete(&self, context: &Handle, _file_name: &U16CStr, delete_file: bool) -> FsResult<()> {
        tracing::debug!(node = format!("{:x}", context.node), delete_file, "set_delete");
        if !delete_file {
            self.deleting.lock().unwrap().remove(&context.node);
            return Ok(());
        }
        if context.node == ROOT {
            return Err(nt(STATUS_CANNOT_DELETE));
        }
        let st = self.engine.state();
        let n = st.view.get(context.node).ok_or(nt(STATUS_OBJECT_NAME_NOT_FOUND))?;
        if n.entry.attributes & FILE_ATTRIBUTE_READONLY != 0 {
            return Err(nt(STATUS_CANNOT_DELETE));
        }
        drop(st);
        if context.kind == Kind::Dir && self.has_live_children(context.node) {
            return Err(nt(STATUS_DIRECTORY_NOT_EMPTY));
        }
        self.deleting.lock().unwrap().insert(context.node);
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Handle,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> FsResult<()> {
        let f = context.file.as_ref().ok_or(nt(STATUS_ACCESS_DENIED))?;
        let mut d = lock(f);
        if !set_allocation_size || new_size < d.size {
            self.resize(&mut d, new_size).map_err(io_err)?;
            d.modified = now_filetime();
        }
        fill_file(file_info, context.node, &d);
        Ok(())
    }

    fn read(&self, context: &Handle, buffer: &mut [u8], offset: u64) -> FsResult<u32> {
        let f = context.file.as_ref().ok_or(nt(STATUS_ACCESS_DENIED))?;
        let mut d = lock(f);
        if offset >= d.size {
            return Err(nt(STATUS_END_OF_FILE));
        }
        let end = d.size.min(offset + buffer.len() as u64);
        let mut pos = offset;
        while pos < end {
            let i = (pos / CHUNK_SIZE as u64) as usize;
            let within = (pos % CHUNK_SIZE as u64) as usize;
            let n = ((CHUNK_SIZE - within) as u64).min(end - pos) as usize;
            let out = &mut buffer[(pos - offset) as usize..(pos - offset) as usize + n];
            // The entry's size and chunk list are validated when applied, but
            // never trust the index: a mismatch must not take the drive down.
            let Some(slot) = d.slots.get(i) else {
                tracing::error!(node = format!("{:x}", context.node), chunk = i, "file size exceeds its chunk list");
                return Err(nt(STATUS_IO_DEVICE_ERROR));
            };
            match slot {
                Slot::Zero => out.fill(0),
                Slot::Dirty(v) => copy_from(out, v, within),
                Slot::Clean(id) => {
                    let id = *id;
                    let data = self.engine.read_chunk(&id).map_err(io_err)?;
                    copy_from(out, &data, within);
                }
            }
            pos += n as u64;
        }
        d.accessed = now_filetime();
        Ok((end - offset) as u32)
    }

    fn write(
        &self,
        context: &Handle,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> FsResult<u32> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err(nt(STATUS_ACCESS_DENIED));
        }
        let f = context.file.as_ref().ok_or(nt(STATUS_ACCESS_DENIED))?;
        let mut d = lock(f);
        let offset = if write_to_eof { d.size } else { offset };
        let mut len = buffer.len() as u64;
        if constrained_io {
            if offset >= d.size {
                fill_file(file_info, context.node, &d);
                return Ok(0);
            }
            len = len.min(d.size - offset);
        }
        let end = offset + len;
        if end > d.size {
            self.resize(&mut d, end).map_err(io_err)?;
        }
        let mut pos = offset;
        while pos < end {
            let i = (pos / CHUNK_SIZE as u64) as usize;
            let within = (pos % CHUNK_SIZE as u64) as usize;
            let n = ((CHUNK_SIZE - within) as u64).min(end - pos) as usize;
            let clen = chunk_len(d.size, i);
            if i >= d.slots.len() {
                tracing::error!(node = format!("{:x}", context.node), chunk = i, "file size exceeds its chunk list");
                return Err(nt(STATUS_IO_DEVICE_ERROR));
            }
            if !matches!(d.slots[i], Slot::Dirty(_)) {
                self.materialize(&mut d, i, clen).map_err(io_err)?;
            }
            if let Slot::Dirty(v) = &mut d.slots[i] {
                let src = &buffer[(pos - offset) as usize..(pos - offset) as usize + n];
                v[within..within + n].copy_from_slice(src);
            }
            pos += n as u64;
        }
        d.dirty = true;
        d.modified = now_filetime();
        let dirty = d.slots.iter().filter(|s| matches!(s, Slot::Dirty(_))).count();
        if dirty > MAX_DIRTY_CHUNKS {
            // Keep the chunk currently being written in memory.
            let current = (end.saturating_sub(1) / CHUNK_SIZE as u64) as usize;
            self.seal(&mut d, false, current).map_err(io_err)?;
        }
        fill_file(file_info, context.node, &d);
        Ok(len as u32)
    }

    fn get_volume_info(&self, out: &mut VolumeInfo) -> FsResult<()> {
        tracing::trace!("get_volume_info");
        // Files land in the local chunk cache and on the server, so whichever
        // has less room left is the limit. Explorer shows total − free as
        // used, so make that the vault's own files, not whatever else fills
        // the disks behind it.
        let local = free_space(&self.engine.profile.chunk_cache_dir());
        let server = self.engine.server_space().map(|s| s.free);
        let free = match (local, server) {
            (Some(l), Some(s)) => l.min(s),
            (l, s) => l.or(s).unwrap_or(1 << 39),
        };
        let used: u64 =
            self.engine.state().view.nodes().filter(|n| n.entry.kind == Kind::File).map(|n| n.entry.size).sum();
        out.total_size = used.saturating_add(free);
        out.free_size = free;
        out.set_volume_label(&self.label);
        Ok(())
    }
}

/// Remote commits are reported to the kernel from a WinFsp timer, so open
/// Explorer windows refresh without F5.
impl NotifyingFileSystemContext<()> for CryptFs {
    fn should_notify(&self) -> Option<()> {
        self.engine.has_fs_changes().then_some(())
    }

    // Runs between FspFileSystemNotifyBegin/End (which hold off renames); takes
    // only the engine's change queue lock.
    fn notify(&self, _: (), notifier: &Notifier) {
        for c in self.engine.take_fs_changes() {
            let mut info = NotifyInfo::<NOTIFY_NAME_MAX>::new();
            let wide: Vec<u16> = c.path.encode_utf16().collect();
            if info.set_name_raw(wide.as_slice()).is_err() {
                continue;
            }
            let name = if c.dir { FILE_NOTIFY_CHANGE_DIR_NAME } else { FILE_NOTIFY_CHANGE_FILE_NAME };
            (info.action, info.filter) = match c.action {
                ChangeAction::Added => (FILE_ACTION_ADDED, name),
                ChangeAction::Removed => (FILE_ACTION_REMOVED, name),
                ChangeAction::Modified => (FILE_ACTION_MODIFIED, FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE),
            };
            tracing::trace!(action = ?c.action, dir = c.dir, "notify");
            notifier.notify(&info);
        }
    }
}

/// Copy `src[within..]` into `out`, zero-filling what `src` doesn't cover (a
/// chunk shorter than expected, e.g. from a malformed peer upload).
fn copy_from(out: &mut [u8], src: &[u8], within: usize) {
    if within >= src.len() {
        out.fill(0);
        return;
    }
    let avail = (src.len() - within).min(out.len());
    out[..avail].copy_from_slice(&src[within..within + avail]);
    out[avail..].fill(0);
}

/// SID of the user this process runs as (e.g. `S-1-5-21-…-1001` for a local
/// or domain account, `S-1-12-1-…` for a Microsoft Entra ID account).
fn current_user_sid() -> Result<String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::PWSTR;
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).context("opening process token")?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let r = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len);
        let _ = CloseHandle(token);
        r.context("reading token user")?;
        let user = &*buf.as_ptr().cast::<TOKEN_USER>();
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut s).context("converting SID")?;
        let sid = s.to_string();
        let _ = LocalFree(Some(HLOCAL(s.0.cast())));
        Ok(sid?)
    }
}

/// Every file on the drive is owned by, and fully accessible to, the user who
/// mounted it (plus SYSTEM and Administrators). Nothing is granted to
/// Everyone: the drive letter is per logon session anyway, but the
/// descriptor is what WinFsp checks, so it must not rely on that.
fn default_security_descriptor() -> Result<Vec<u8>> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;
    use windows::core::HSTRING;
    let sid = current_user_sid()?;
    let sddl = format!("O:{sid}G:{sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})");
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let mut len = 0u32;
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(sddl), SDDL_REVISION_1, &mut psd, Some(&mut len))
            .context("building security descriptor")?;
        let v = std::slice::from_raw_parts(psd.0 as *const u8, len as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(psd.0)));
        Ok(v)
    }
}

/// Bytes available to this user on the drive holding `path`.
fn free_space(path: &std::path::Path) -> Option<u64> {
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows::core::HSTRING;
    let mut free = 0u64;
    unsafe {
        GetDiskFreeSpaceExW(&HSTRING::from(path.as_os_str()), Some(&mut free), None, None).ok()?;
    }
    Some(free)
}

// ---------------------------------------------------------------------------
// mounting
// ---------------------------------------------------------------------------

pub struct Mount {
    host: FileSystemHost<CryptFs, FineGuard>,
    pub drive: String,
}

impl Mount {
    pub fn unmount(mut self) {
        self.host.stop();
        self.host.unmount();
    }
}

/// First unused drive letter from Z: downwards.
pub fn free_drive() -> Option<String> {
    free_drives().into_iter().next()
}

/// Unused drive letters (`"Z:"` first), the way [`free_drive`] picks them.
pub fn free_drives() -> Vec<String> {
    let used = unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };
    (b'D'..=b'Z').rev().filter(|l| used & (1 << (l - b'A')) == 0).map(|l| format!("{}:", l as char)).collect()
}

pub fn mount(engine: Arc<Engine>, mount_point: &str) -> Result<Mount> {
    winfsp::winfsp_init().map_err(|e| anyhow::anyhow!("WinFsp is not installed or failed to load: {e:?}"))?;
    let drive = if mount_point.is_empty() {
        free_drive().context("no free drive letter")?
    } else {
        mount_point.to_uppercase()
    };
    let serial = u32::from_le_bytes(blake3::hash(engine.profile.vault.as_bytes()).as_bytes()[..4].try_into().unwrap());
    let mut vp = VolumeParams::new();
    vp.sector_size(4096)
        .sectors_per_allocation_unit(1)
        .max_component_length(255)
        .volume_creation_time(now_filetime())
        .volume_serial_number(serial)
        // No kernel metadata caching: remote commits change the tree at any time.
        .file_info_timeout(0)
        .case_sensitive_search(false)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(false)
        .post_cleanup_when_modified_only(true)
        .filesystem_name("kybersync");
    engine.watch_fs_changes();
    let fs = CryptFs::new(engine)?;
    let params = FileSystemParams { use_dir_info_by_name: false, volume_params: vp, debug_mode: DebugMode::none() };
    let mut host = FileSystemHost::<CryptFs, FineGuard>::new_with_timer::<(), NOTIFY_INTERVAL_MS>(params, fs)
        .map_err(|e| anyhow::anyhow!("creating filesystem: {e:?}"))?;
    host.mount(drive.as_str()).map_err(|e| anyhow::anyhow!("mounting {drive}: {e:?}"))?;
    host.start().map_err(|e| anyhow::anyhow!("starting dispatcher: {e:?}"))?;
    tracing::info!(drive, "mounted");
    Ok(Mount { host, drive })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `S-1-<authority>-<sub>-…`: local and domain accounts are `S-1-5-21-…`,
    /// Microsoft Entra ID accounts `S-1-12-1-…`.
    fn is_user_sid(s: &str) -> bool {
        let parts: Vec<&str> = s.split('-').collect();
        parts.len() >= 4
            && parts[0] == "S"
            && parts[1] == "1"
            && parts[2..].iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    }

    #[test]
    fn sid_shapes() {
        assert!(is_user_sid("S-1-5-21-1004336348-1177238915-682003330-1001"));
        assert!(is_user_sid("S-1-12-1-1723396532-1108212103-1723068580-2130556903"));
        assert!(!is_user_sid("S-1-5"));
        assert!(!is_user_sid("S-1-5-x-1"));
        assert!(!is_user_sid("BA"));
    }

    #[test]
    fn descriptor_is_built_for_the_current_user() {
        let sid = current_user_sid().unwrap();
        assert!(is_user_sid(&sid), "{sid}");
        let sd = default_security_descriptor().unwrap();
        // A self-relative descriptor starts with revision 1 and is never tiny.
        assert_eq!(sd[0], 1);
        assert!(sd.len() > 64, "{}", sd.len());
    }

    #[test]
    fn short_chunks_read_as_zeros() {
        let mut out = [7u8; 4];
        copy_from(&mut out, b"ab", 1);
        assert_eq!(out, [b'b', 0, 0, 0]);
        copy_from(&mut out, b"ab", 2);
        assert_eq!(out, [0; 4]);
        copy_from(&mut out, b"ab", 9);
        assert_eq!(out, [0; 4]);
    }
}
