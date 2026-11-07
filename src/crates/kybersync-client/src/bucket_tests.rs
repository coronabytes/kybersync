//! Serverless vault behaviour on an in-memory bucket.

use super::*;
use kybersync_core::crypto::{KeyRing, VaultKey, WrappedKey};
use object_store::memory::InMemory;

const VAULT: &str = "v1";

fn bucket() -> Arc<dyn ObjectStore> {
    Arc::new(InMemory::new())
}

fn api(store: &Arc<dyn ObjectStore>, secret: &DeviceSecret) -> BucketApi {
    let id = secret.public().unwrap().device_id();
    BucketApi::with_store(store.clone(), VAULT, &id, Some(Arc::new(secret.clone())), Duration::from_millis(10))
}

/// An opaque record in key epoch `epoch` (only the header is ever read here).
fn rec(epoch: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![crypto::EPOCH_RECORD];
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

fn device(secret: &DeviceSecret, name: &str) -> DeviceInfo {
    let public = secret.public().unwrap();
    DeviceInfo { device_id: public.device_id(), name: name.into(), public, state: DeviceState::Pending, created: 0 }
}

fn wrap(secret: &DeviceSecret, vk: &VaultKey) -> Vec<u8> {
    serde_json::to_vec(&crypto::wrap_for_device(&secret.public().unwrap(), vk.as_bytes()).unwrap()).unwrap()
}

fn unwrap_key(secret: &DeviceSecret, slot: &[u8]) -> VaultKey {
    let w: WrappedKey = serde_json::from_slice(slot).unwrap();
    VaultKey::from_bytes(&crypto::unwrap_with_device(secret, &w).unwrap()).unwrap()
}

fn recovery_update(rec: &DeviceSecret, vk: &VaultKey) -> RecoveryUpdate {
    let public = rec.public().unwrap();
    RecoveryUpdate { mac: crypto::recovery_mac(vk, VAULT, &public), keyslot: wrap(rec, vk), public }
}

/// A vault created by device `a`, plus the recovery identity and the key.
async fn create(store: &Arc<dyn ObjectStore>) -> (DeviceSecret, DeviceSecret, VaultKey) {
    let (a, recovery, vk) = (DeviceSecret::generate(), DeviceSecret::generate(), VaultKey::generate());
    let req = CreateVaultRequest {
        device: device(&a, "a"),
        enroll_verifier: String::new(),
        keyslot: wrap(&a, &vk),
        recovery: Some(recovery_update(&recovery, &vk)),
    };
    api(store, &a).create_vault("", &req).await.unwrap();
    (a, recovery, vk)
}

/// Device `name` joins and `approver` lets it in.
async fn join(store: &Arc<dyn ObjectStore>, approver: &DeviceSecret, vk: &VaultKey, name: &str) -> DeviceSecret {
    let s = DeviceSecret::generate();
    let me = api(store, &s);
    assert_eq!(me.join(device(&s, name), "").await.unwrap(), DeviceState::Pending);
    let id = s.public().unwrap().device_id();
    api(store, approver).approve(&id, wrap(&s, vk), 0).await.unwrap();
    assert_eq!(me.join_status().await.unwrap(), DeviceState::Authorized);
    s
}

#[tokio::test]
async fn bucket_supports_what_serverless_vaults_need() {
    let store = bucket();
    api(&store, &DeviceSecret::generate()).check_bucket().await.unwrap();
}

#[tokio::test]
async fn create_join_approve() {
    let store = bucket();
    let (a, recovery, vk) = create(&store).await;
    let a_api = api(&store, &a);

    // The name is taken now.
    let req = CreateVaultRequest {
        device: device(&a, "a"),
        enroll_verifier: String::new(),
        keyslot: wrap(&a, &vk),
        recovery: Some(recovery_update(&recovery, &vk)),
    };
    assert!(a_api.create_vault("", &req).await.unwrap_err().to_string().contains("already exists"));

    // A pending device shows up, and gets no keyslot until approved.
    let b = DeviceSecret::generate();
    let b_api = api(&store, &b);
    assert_eq!(b_api.join(device(&b, "b"), "").await.unwrap(), DeviceState::Pending);
    assert!(matches!(b_api.keyslot().await, Err(ApiError::NotFound)));
    let pending: Vec<_> = a_api.devices().await.unwrap().into_iter().filter(|d| d.state == DeviceState::Pending).collect();
    assert_eq!(pending.len(), 1);
    a_api.approve(&pending[0].device_id, wrap(&b, &vk), 0).await.unwrap();
    assert_eq!(b_api.join_status().await.unwrap(), DeviceState::Authorized);
    let (epoch, slot) = b_api.keyslot().await.unwrap();
    assert_eq!(epoch, 0);
    assert_eq!(unwrap_key(&b, &slot).as_bytes(), vk.as_bytes());

    // Approving twice, or approving for an old epoch, is refused.
    assert!(a_api.approve(&pending[0].device_id, wrap(&b, &vk), 0).await.is_err());

    // The kit holder finds its identity; a stranger's id gets "not found".
    let rid = recovery.public().unwrap().device_id();
    assert_eq!(a_api.recovery_for_kit(&rid).await.unwrap().epoch, 0);
    assert!(a_api.recovery_for_kit("nope").await.unwrap_err().downcast_ref::<ApiError>().is_some_and(|e| matches!(e, ApiError::NotFound)));
}

#[tokio::test]
async fn joining_a_missing_vault_says_so() {
    let store = bucket();
    let s = DeviceSecret::generate();
    let err = api(&store, &s).join(device(&s, "b"), "").await.unwrap_err();
    assert!(err.to_string().contains("no vault named"), "{err}");
}

#[tokio::test]
async fn appends_take_positions_in_order() {
    let store = bucket();
    let (a, _, vk) = create(&store).await;
    let b = join(&store, &a, &vk, "b").await;
    let (a_api, b_api) = (api(&store, &a), api(&store, &b));

    assert_eq!(a_api.append(rec(0, b"one"), Some(0)).await.unwrap(), 1);
    // b sealed its record for head 0 too: the position is taken.
    let err = b_api.append(rec(0, b"two"), Some(0)).await.unwrap_err();
    assert!(err.is_head_moved(), "{err:?}");
    assert_eq!(b_api.head(0, 0).await.unwrap(), 1);
    assert_eq!(b_api.append(rec(0, b"two"), Some(1)).await.unwrap(), 2);

    let frames = a_api.read_log(0).await.unwrap();
    assert_eq!(frames.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(frames[1].1, rec(0, b"two"));
    assert!(a_api.read_log(2).await.unwrap().is_empty());
    assert_eq!(a_api.head(2, 0).await.unwrap(), 2);

    // A record under another key epoch is refused.
    assert!(a_api.append(rec(1, b"x"), Some(2)).await.unwrap_err().is_stale_epoch());
}

#[tokio::test]
async fn head_waits_for_another_device() {
    let store = bucket();
    let (a, _, vk) = create(&store).await;
    let b = join(&store, &a, &vk, "b").await;
    let (a_api, b_api) = (api(&store, &a), api(&store, &b));
    let waiter = tokio::spawn(async move { b_api.head(0, 5).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    a_api.append(rec(0, b"one"), Some(0)).await.unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(2), waiter).await.unwrap().unwrap(), 1);
}

#[tokio::test]
async fn compaction_drops_the_log_before_a_snapshot() {
    let store = bucket();
    let (a, _, vk) = create(&store).await;
    let b = join(&store, &a, &vk, "b").await;
    let (a_api, b_api) = (api(&store, &a), api(&store, &b));
    for h in 0..3 {
        a_api.append(rec(0, b"c"), Some(h)).await.unwrap();
    }
    assert!(a_api.compact(2).await.is_err(), "no snapshot yet");
    assert!(a_api.put_snapshot(9, rec(0, b"s")).await.is_err(), "past the head");
    a_api.put_snapshot(2, rec(0, b"s")).await.unwrap();

    let lease = a_api.take_lease(MaintenanceTask::Compact, true).await.unwrap().unwrap();
    // Another device can neither take the lease nor compact meanwhile.
    assert!(b_api.take_lease(MaintenanceTask::Compact, true).await.unwrap().is_none());
    assert!(b_api.compact(2).await.is_err());
    assert_eq!(a_api.compact(2).await.unwrap(), 3);
    a_api.release_lease(&lease.lease, true).await.unwrap();

    assert!(matches!(b_api.read_log(0).await, Err(ApiError::Gone)));
    assert_eq!(b_api.read_log(2).await.unwrap().len(), 1);
    assert_eq!(b_api.snapshot().await.unwrap().unwrap().0, 2);
    // A device still at head 1 can't write into the compacted range.
    assert!(b_api.append(rec(0, b"late"), Some(1)).await.unwrap_err().is_head_moved());
    assert_eq!(b_api.append(rec(0, b"ok"), Some(3)).await.unwrap(), 4);

    let status = b_api.maintenance().await.unwrap();
    assert_eq!((status.head, status.log_start, status.snapshot), (4, 3, Some(2)));
    assert!(status.last_compact > 0 && status.lease.is_none());
}

#[tokio::test]
async fn an_expired_lease_can_be_taken_over() {
    let store = bucket();
    let (a, _, vk) = create(&store).await;
    let b = join(&store, &a, &vk, "b").await;
    let (a_api, b_api) = (api(&store, &a), api(&store, &b));
    a_api.take_lease(MaintenanceTask::Gc, true).await.unwrap().unwrap();
    assert!(b_api.take_lease(MaintenanceTask::Gc, true).await.unwrap().is_none());

    // Let a's lease run out.
    let s = Store::new(store.clone());
    let (mut lease, version) = s.lease(VAULT).await.unwrap().unwrap();
    lease.expires = 1;
    assert!(s.update(&object_store::path::Path::from(format!("vaults/{VAULT}/lease.json")), serde_json::to_vec(&lease).unwrap().into(), version).await.unwrap());

    let taken = b_api.take_lease(MaintenanceTask::Gc, true).await.unwrap().unwrap();
    // a's old lease id is no longer valid.
    assert!(a_api.release_lease(&lease.id, true).await.is_err());
    b_api.release_lease(&taken.lease, true).await.unwrap();
    assert!(b_api.maintenance().await.unwrap().last_gc > 0);
    // Not due right after a run, so a normal request gets nothing.
    assert!(a_api.take_lease(MaintenanceTask::Gc, false).await.unwrap().is_none());
}

#[tokio::test]
async fn gc_keeps_young_blobs_and_refuses_a_moved_log() {
    let store = bucket();
    let (a, _, _) = create(&store).await;
    let a_api = api(&store, &a);
    let id = ChunkId([7; 32]);
    a_api.put_blob(&id, rec(0, b"chunk")).await.unwrap();
    assert!(a_api.missing(&[id, ChunkId([8; 32])]).await.unwrap() == vec![ChunkId([8; 32])]);
    assert_eq!(a_api.list_blobs("07").await.unwrap().len(), 1);

    let req = GcRequest { head: 0, grace_secs: 0, ids: vec![id.to_hex()] };
    let r = a_api.gc(&req).await.unwrap();
    assert_eq!((r.deleted, r.kept), (0, 1), "younger than the minimum grace period");

    a_api.append(rec(0, b"c"), Some(0)).await.unwrap();
    assert!(a_api.gc(&req).await.is_err(), "the log moved past head 0");
    assert!(a_api.put_blob(&ChunkId([9; 32]), rec(1, b"x")).await.unwrap_err().is_stale_epoch());
}

fn rotate_req(ring: &KeyRing, recovery: &DeviceSecret, keep: &[&DeviceSecret], revoke: &[&DeviceSecret]) -> (RotateRequest, VaultKey) {
    let (next, link) = ring.rotate(VAULT);
    let vk = next.current_key().clone();
    let req = RotateRequest {
        epoch: next.epoch(),
        revoke: revoke.iter().map(|s| s.public().unwrap().device_id()).collect(),
        keyslots: keep
            .iter()
            .map(|s| DeviceKeyslot { device_id: s.public().unwrap().device_id(), keyslot: wrap(s, &vk) })
            .collect(),
        link,
        recovery: recovery_update(recovery, &vk),
        challenge: vec![],
        signature: vec![],
    };
    (req, vk)
}

#[tokio::test]
async fn rotation_revokes_and_only_one_wins() {
    let store = bucket();
    let (a, recovery, vk) = create(&store).await;
    let b = join(&store, &a, &vk, "b").await;
    let (a_api, b_api) = (api(&store, &a), api(&store, &b));
    let ring = KeyRing::new(0, vk.clone());

    // Keyslots must cover exactly the devices that stay.
    let (bad_req, _) = rotate_req(&ring, &recovery, &[&a], &[]);
    assert!(a_api.rotate(&bad_req).await.is_err());
    // A refused rotation must not leave the epoch claimed.
    let (req, vk1) = rotate_req(&ring, &recovery, &[&a], &[&b]);
    a_api.rotate(&req).await.unwrap();

    // A second rotation from the same starting point lost the race.
    let (late, _) = rotate_req(&ring, &recovery, &[&a, &b], &[]);
    assert!(b_api.rotate(&late).await.unwrap_err().is_stale_epoch());

    let (epoch, slot) = a_api.keyslot().await.unwrap();
    assert_eq!(epoch, 1);
    assert_eq!(unwrap_key(&a, &slot).as_bytes(), vk1.as_bytes());
    assert!(matches!(b_api.keyslot().await, Err(ApiError::NotFound)));
    assert_eq!(a_api.devices().await.unwrap().len(), 1);
    let chain = a_api.keychain().await.unwrap();
    KeyRing::from_chain(VAULT, chain.epoch, vk1, &chain.links).unwrap();
    // Writes under the old key are refused from now on.
    assert!(b_api.append(rec(0, b"x"), Some(0)).await.unwrap_err().is_stale_epoch());
    assert_eq!(a_api.recovery().await.unwrap().epoch, 1);
}

/// Against a real S3 service: set `KYBERSYNC_TEST_S3` to
/// `endpoint,region,bucket,key id,secret[,path|virtual]` and run with `--ignored`.
#[tokio::test]
#[ignore = "needs an S3 service (KYBERSYNC_TEST_S3)"]
async fn real_bucket() {
    let spec = std::env::var("KYBERSYNC_TEST_S3").expect("KYBERSYNC_TEST_S3=endpoint,region,bucket,key id,secret");
    let f: Vec<&str> = spec.split(',').collect();
    let path_style = f.get(5).is_none_or(|s| *s != "virtual");
    let s3 = S3Settings::new(f[0], f[1], f[2], path_style, f[3], f[4]).unwrap();
    check_s3(&s3).await.unwrap();

    let vault = format!("test-{}", hex::encode(crypto::random::<4>()));
    let (a, recovery, vk) = (DeviceSecret::generate(), DeviceSecret::generate(), VaultKey::generate());
    let s3_api = |s: &DeviceSecret| BucketApi::s3(&s3, &vault, &s.public().unwrap().device_id(), Some(Arc::new(s.clone()))).unwrap();
    let a_api = s3_api(&a);
    let public = recovery.public().unwrap();
    let rec_update = RecoveryUpdate { mac: crypto::recovery_mac(&vk, &vault, &public), keyslot: wrap(&recovery, &vk), public };
    let req = CreateVaultRequest { device: device(&a, "a"), enroll_verifier: String::new(), keyslot: wrap(&a, &vk), recovery: Some(rec_update) };
    a_api.create_vault("", &req).await.unwrap();
    assert!(a_api.create_vault("", &req).await.is_err());

    let b = DeviceSecret::generate();
    let b_api = s3_api(&b);
    b_api.join(device(&b, "b"), "").await.unwrap();
    a_api.approve(&b.public().unwrap().device_id(), wrap(&b, &vk), 0).await.unwrap();
    assert_eq!(unwrap_key(&b, &b_api.keyslot().await.unwrap().1).as_bytes(), vk.as_bytes());

    assert_eq!(a_api.append(rec(0, b"one"), Some(0)).await.unwrap(), 1);
    assert!(b_api.append(rec(0, b"two"), Some(0)).await.unwrap_err().is_head_moved());
    assert_eq!(b_api.head(0, 0).await.unwrap(), 1);
    assert_eq!(b_api.append(rec(0, b"two"), Some(1)).await.unwrap(), 2);
    assert_eq!(a_api.read_log(0).await.unwrap().len(), 2);

    let lease = a_api.take_lease(MaintenanceTask::Gc, true).await.unwrap().unwrap();
    assert!(b_api.take_lease(MaintenanceTask::Gc, true).await.unwrap().is_none());
    a_api.release_lease(&lease.lease, true).await.unwrap();

    let ring = KeyRing::new(0, vk.clone());
    let (next, link) = ring.rotate(&vault);
    let vk1 = next.current_key().clone();
    let public = recovery.public().unwrap();
    let rotate = |keep: Vec<&DeviceSecret>, revoke: Vec<&DeviceSecret>, link| RotateRequest {
        epoch: 1,
        revoke: revoke.iter().map(|s| s.public().unwrap().device_id()).collect(),
        keyslots: keep.iter().map(|s| DeviceKeyslot { device_id: s.public().unwrap().device_id(), keyslot: wrap(s, &vk1) }).collect(),
        link,
        recovery: RecoveryUpdate { mac: crypto::recovery_mac(&vk1, &vault, &public), keyslot: wrap(&recovery, &vk1), public: public.clone() },
        challenge: vec![],
        signature: vec![],
    };
    a_api.rotate(&rotate(vec![&a], vec![&b], link.clone())).await.unwrap();
    assert!(a_api.rotate(&rotate(vec![&a], vec![], link)).await.unwrap_err().is_stale_epoch());
    assert_eq!(a_api.keyslot().await.unwrap().0, 1);
    assert!(b_api.append(rec(0, b"x"), Some(2)).await.unwrap_err().is_stale_epoch());
}

#[tokio::test]
async fn pending_requests_can_be_rejected_but_members_need_a_rotation() {
    let store = bucket();
    let (a, _, vk) = create(&store).await;
    let a_api = api(&store, &a);
    let b = join(&store, &a, &vk, "b").await;
    let c = DeviceSecret::generate();
    api(&store, &c).join(device(&c, "c"), "").await.unwrap();
    a_api.revoke(&c.public().unwrap().device_id()).await.unwrap();
    assert!(a_api.revoke(&b.public().unwrap().device_id()).await.is_err());
    assert_eq!(a_api.devices().await.unwrap().len(), 2);
}

/// Counts the requests that reach the bucket, by kind.
#[derive(Debug, Default)]
struct Counting {
    inner: InMemory,
    gets: std::sync::atomic::AtomicU64,
    lists: std::sync::atomic::AtomicU64,
    puts: std::sync::atomic::AtomicU64,
}

impl std::fmt::Display for Counting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Counting")
    }
}

impl Counting {
    fn take(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering::SeqCst;
        (self.gets.swap(0, SeqCst), self.lists.swap(0, SeqCst), self.puts.swap(0, SeqCst))
    }
}

#[async_trait::async_trait]
impl ObjectStore for Counting {
    async fn put_opts(
        &self,
        location: &object_store::path::Path,
        payload: object_store::PutPayload,
        opts: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        self.puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.put_opts(location, payload, opts).await
    }
    async fn put_multipart_opts(
        &self,
        location: &object_store::path::Path,
        opts: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        self.inner.put_multipart_opts(location, opts).await
    }
    async fn get_opts(
        &self,
        location: &object_store::path::Path,
        options: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get_opts(location, options).await
    }
    fn delete_stream(
        &self,
        locations: futures::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::path::Path>> {
        self.inner.delete_stream(locations)
    }
    fn list(
        &self,
        prefix: Option<&object_store::path::Path>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>> {
        self.lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.list(prefix)
    }
    fn list_with_offset(
        &self,
        prefix: Option<&object_store::path::Path>,
        offset: &object_store::path::Path,
    ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>> {
        self.lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.list_with_offset(prefix, offset)
    }
    async fn list_with_delimiter(
        &self,
        prefix: Option<&object_store::path::Path>,
    ) -> object_store::Result<object_store::ListResult> {
        self.lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.list_with_delimiter(prefix).await
    }
    async fn copy_opts(
        &self,
        from: &object_store::path::Path,
        to: &object_store::path::Path,
        options: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        self.inner.copy_opts(from, to, options).await
    }
}

/// One idle sync cycle (`read_log`, then `head` with the engine's wait) at
/// `poll_secs`: the requests it sends, as `(GET/HEAD, LIST, PUT)`.
async fn idle_cycle(poll_secs: u64) -> (u64, u64, u64) {
    let counting = Arc::new(Counting::default());
    let store: Arc<dyn ObjectStore> = counting.clone();
    let (a, _, _) = create(&store).await;
    let id = a.public().unwrap().device_id();
    let a_api = BucketApi::with_store(store.clone(), VAULT, &id, None, Duration::from_secs(poll_secs));
    a_api.append(rec(0, b"one"), Some(0)).await.unwrap();
    counting.take();

    assert!(a_api.read_log(1).await.unwrap().is_empty());
    assert_eq!(a_api.head(1, crate::config::LONG_POLL_SECS).await.unwrap(), 1);
    counting.take()
}

#[tokio::test(start_paused = true)]
async fn an_idle_cycle_costs_what_the_settings_say() {
    for poll in crate::config::POLL_CHOICES {
        let (gets, lists, puts) = idle_cycle(poll).await;
        assert_eq!((lists, puts), (0, 0), "an idle device neither lists nor writes (poll {poll}s)");
        let cycle = poll.max(crate::config::LONG_POLL_SECS);
        assert_eq!(gets * (86_400 / cycle), crate::config::idle_requests_per_day(poll), "poll {poll}s");
    }
    assert_eq!(idle_cycle(5).await.0, 7, "5 s: the log check (GET + HEAD) and a HEAD at 5, 10, 15, 20, 25 s");
}

#[tokio::test(start_paused = true)]
async fn polling_sees_a_new_entry_at_the_next_check() {
    let store = bucket();
    let (a, _, vk) = create(&store).await;
    let b = join(&store, &a, &vk, "b").await;
    let b_id = b.public().unwrap().device_id();
    let b_api = BucketApi::with_store(store.clone(), VAULT, &b_id, None, Duration::from_secs(15));
    let a_api = api(&store, &a);
    let start = tokio::time::Instant::now();
    let waiter = tokio::spawn(async move { b_api.head(0, 30).await.unwrap() });
    tokio::time::sleep(Duration::from_secs(10)).await;
    a_api.append(rec(0, b"one"), Some(0)).await.unwrap();
    assert_eq!(waiter.await.unwrap(), 1);
    assert_eq!(start.elapsed().as_secs(), 15, "found by the check one interval in");
}
