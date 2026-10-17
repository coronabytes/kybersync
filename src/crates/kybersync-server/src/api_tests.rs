//! API-level tests: authentication, authorization and storage semantics.

use crate::api::{AppState, router};
use crate::store::Store;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, Response, StatusCode};
use kybersync_core::crypto::{self, DeviceSecret, KeyRing, VaultKey, WrappedKey};
use kybersync_core::proto::*;
use kybersync_core::tree::{Commit, Entry, GENESIS, Kind, Op, ROOT, Snapshot, Tree};
use http_body_util::BodyExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

struct Fixture {
    app: Router,
    dir: tempfile::TempDir,
}

fn app_on(dir: &std::path::Path, min_gc_grace: Duration) -> Router {
    let fs = object_store::local::LocalFileSystem::new_with_prefix(dir).unwrap();
    let state = AppState::new(Store::new(Arc::new(fs)), "admin".into()).with_min_gc_grace(min_gc_grace);
    router(Arc::new(state))
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    Fixture { app: app_on(dir.path(), Duration::from_secs(3600)), dir }
}

async fn call(app: &Router, req: Request<Body>) -> Response<Body> {
    app.clone().oneshot(req).await.unwrap()
}

async fn body(r: Response<Body>) -> Vec<u8> {
    r.into_body().collect().await.unwrap().to_bytes().to_vec()
}

async fn json<T: serde::de::DeserializeOwned>(r: Response<Body>) -> T {
    assert!(r.status().is_success(), "status {}", r.status());
    serde_json::from_slice(&body(r).await).unwrap()
}

fn json_req(method: &str, uri: &str, token: Option<&str>, body: &impl serde::Serialize) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(serde_json::to_vec(body).unwrap())).unwrap()
}

fn raw_req(method: &str, uri: &str, token: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body))
        .unwrap()
}

/// An opaque record in key epoch `epoch` (the server only reads the header).
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
    RecoveryUpdate { mac: crypto::recovery_mac(vk, "v1", &public), keyslot: wrap(rec, vk), public }
}

async fn login(app: &Router, vault: &str, secret: &DeviceSecret) -> Result<String, StatusCode> {
    let id = secret.public().unwrap().device_id();
    let challenge = challenge(app, vault, &id).await?;
    let signature = secret.sign(AUTH_CONTEXT, &auth_message(vault, &id, &challenge)).unwrap();
    let r = call(
        app,
        json_req("POST", &format!("/v1/vaults/{vault}/auth/token"), None, &TokenRequest { device_id: id, challenge, signature }),
    )
    .await;
    if !r.status().is_success() {
        return Err(r.status());
    }
    Ok(serde_json::from_slice::<TokenResponse>(&body(r).await).unwrap().token)
}

async fn challenge(app: &Router, vault: &str, id: &str) -> Result<Vec<u8>, StatusCode> {
    let r = call(
        app,
        json_req("POST", &format!("/v1/vaults/{vault}/auth/challenge"), None, &ChallengeRequest { device_id: id.into() }),
    )
    .await;
    if !r.status().is_success() {
        return Err(r.status());
    }
    Ok(serde_json::from_slice::<ChallengeResponse>(&body(r).await).unwrap().challenge)
}

async fn create(app: &Router, admin: &str, secret: &DeviceSecret, verifier: String) -> StatusCode {
    let req = CreateVaultRequest { device: device(secret, "a"), enroll_verifier: verifier, keyslot: b"slot".to_vec(), recovery: None };
    create_with(app, admin, &req).await
}

async fn create_with(app: &Router, admin: &str, req: &CreateVaultRequest) -> StatusCode {
    let mut req = json_req("POST", "/v1/vaults/v1", None, req);
    req.headers_mut().insert(HEADER_ADMIN, admin.parse().unwrap());
    call(app, req).await.status()
}

/// A v2 vault: device `a` holds the epoch-0 key, `rec` is the recovery identity.
async fn create_v2(app: &Router, a: &DeviceSecret, rec: &DeviceSecret, vk: &VaultKey) -> String {
    let req = CreateVaultRequest {
        device: device(a, "a"),
        enroll_verifier: String::new(),
        keyslot: wrap(a, vk),
        recovery: Some(recovery_update(rec, vk)),
    };
    assert_eq!(create_with(app, "admin", &req).await, StatusCode::CREATED);
    login(app, "v1", a).await.unwrap()
}

/// Mint an invite code on an authorized device.
async fn invite(app: &Router, token: &str) -> String {
    let r = call(app, raw_req("POST", "/v1/vaults/v1/invites", token, vec![])).await;
    json::<InviteResponse>(r).await.code
}

fn join_req(vault: &str, code: &str, s: &DeviceSecret, name: &str) -> Request<Body> {
    json_req("POST", &format!("/v1/vaults/{vault}/join"), None, &JoinRequest { device: device(s, name), code: code.into() })
}

/// Invite + join, as a new device does with a code from an existing one.
async fn join(app: &Router, token: &str, s: &DeviceSecret, name: &str) -> StatusCode {
    let code = invite(app, token).await;
    call(app, join_req("v1", &code, s, name)).await.status()
}

async fn join_and_approve(app: &Router, token: &str, s: &DeviceSecret, name: &str, slot: Vec<u8>, epoch: u32) -> StatusCode {
    assert_eq!(join(app, token, s, name).await, StatusCode::OK);
    let id = s.public().unwrap().device_id();
    let r = call(
        app,
        json_req("POST", &format!("/v1/vaults/v1/devices/{id}/approve"), Some(token), &ApproveRequest { keyslot: slot, epoch }),
    )
    .await;
    r.status()
}

async fn append(app: &Router, token: &str, record: Vec<u8>) -> Result<u64, StatusCode> {
    let r = call(app, raw_req("POST", "/v1/vaults/v1/log", token, record)).await;
    if !r.status().is_success() {
        return Err(r.status());
    }
    Ok(serde_json::from_slice::<AppendResponse>(&body(r).await).unwrap().seq)
}

/// Append as a chained client does: only if the log head is still `head`.
async fn append_at(app: &Router, token: &str, head: u64, record: Vec<u8>) -> Result<u64, StatusCode> {
    let r = call(app, raw_req("POST", &format!("/v1/vaults/v1/log?head={head}"), token, record)).await;
    if !r.status().is_success() {
        return Err(r.status());
    }
    Ok(serde_json::from_slice::<AppendResponse>(&body(r).await).unwrap().seq)
}

async fn read_log(app: &Router, token: &str, after: u64) -> Result<Vec<(u64, Vec<u8>)>, StatusCode> {
    let r = call(app, raw_req("GET", &format!("/v1/vaults/v1/log?after={after}"), token, vec![])).await;
    if !r.status().is_success() {
        return Err(r.status());
    }
    Ok(decode_frames(&body(r).await).unwrap())
}

fn commit(dev: &str, ops: Vec<Op>) -> Commit {
    Commit { id: crypto::random(), device_id: dev.into(), device_name: dev.into(), time: 1_760_000_000, ops, prev: GENESIS, head: 0 }
}

fn file(id: u128, name: &str, content: u8) -> Op {
    let entry = Entry {
        id,
        parent: ROOT,
        name: name.into(),
        kind: Kind::File,
        size: 1,
        chunks: vec![crypto::ChunkId([content; 32])],
        attributes: 0,
        created: 0,
        modified: 0,
    };
    Op::Put { entry, base: 0 }
}

#[tokio::test]
async fn vault_lifecycle() {
    let f = fixture();
    let a = DeviceSecret::generate();
    assert_eq!(create(&f.app, "wrong", &a, "0".repeat(64)).await, StatusCode::FORBIDDEN);
    assert_eq!(create(&f.app, "admin", &a, "0".repeat(64)).await, StatusCode::CREATED);
    assert_eq!(create(&f.app, "admin", &a, "0".repeat(64)).await, StatusCode::CONFLICT);

    // Unknown devices and bogus tokens are rejected.
    assert_eq!(login(&f.app, "v1", &DeviceSecret::generate()).await, Err(StatusCode::UNAUTHORIZED));
    let r = call(
        &f.app,
        Request::get("/v1/vaults/v1/devices").header("authorization", "Bearer nope").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let token = login(&f.app, "v1", &a).await.unwrap();

    // Commit log: appends get increasing seqs; reads are framed. An append
    // that names the head it was sealed for is refused once the log moved
    // past it (a concurrent writer got there first); legacy appends without
    // it always go through.
    assert_eq!(append_at(&f.app, &token, 0, rec(0, &[1; 10])).await, Ok(1));
    assert_eq!(append_at(&f.app, &token, 0, rec(0, &[2; 10])).await, Err(StatusCode::CONFLICT));
    assert_eq!(append_at(&f.app, &token, 1, rec(0, &[2; 10])).await, Ok(2));
    assert_eq!(append_at(&f.app, &token, 1, rec(0, &[3; 10])).await, Err(StatusCode::CONFLICT));
    assert_eq!(append(&f.app, &token, rec(0, &[3; 10])).await, Ok(3));
    assert_eq!(append(&f.app, &token, vec![9; 10]).await, Err(StatusCode::BAD_REQUEST));
    let frames = read_log(&f.app, &token, 1).await.unwrap();
    assert_eq!(frames.iter().map(|f| f.0).collect::<Vec<_>>(), vec![2, 3]);
    let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/log/head?after=3&wait=0", &token, vec![])).await;
    assert_eq!(json::<HeadResponse>(r).await.head, 3);

    // Blobs are write-once and addressed by validated ids.
    let id = "ab".repeat(32);
    let put = |b: &[u8]| raw_req("PUT", &format!("/v1/vaults/v1/blobs/{id}"), &token, rec(0, b));
    assert_eq!(call(&f.app, put(b"x")).await.status(), StatusCode::CREATED);
    assert_eq!(call(&f.app, put(b"y")).await.status(), StatusCode::OK);
    let r = call(&f.app, raw_req("GET", &format!("/v1/vaults/v1/blobs/{id}"), &token, vec![])).await;
    assert_eq!(body(r).await, rec(0, b"x"));
    let r = call(&f.app, raw_req("PUT", "/v1/vaults/v1/blobs/..%2Fescape", &token, vec![])).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let other = "cd".repeat(32);
    let r = call(
        &f.app,
        json_req("POST", "/v1/vaults/v1/blobs/missing", Some(&token), &MissingRequest { ids: vec![id.clone(), other.clone()] }),
    )
    .await;
    assert_eq!(json::<MissingResponse>(r).await.missing, vec![other]);

    // Join -> pending can't log in -> approve -> can log in -> revoke -> locked out.
    let b = DeviceSecret::generate();
    let b_id = b.public().unwrap().device_id();
    assert_eq!(join(&f.app, &token, &b, "b").await, StatusCode::OK);
    assert_eq!(login(&f.app, "v1", &b).await, Err(StatusCode::FORBIDDEN));
    let r = call(
        &f.app,
        json_req(
            "POST",
            &format!("/v1/vaults/v1/devices/{b_id}/approve"),
            Some(&token),
            &ApproveRequest { keyslot: b"kb".to_vec(), epoch: 0 },
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let tb = login(&f.app, "v1", &b).await.unwrap();
    let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/keyslot", &tb, vec![])).await;
    let ks: KeyslotResponse = json(r).await;
    assert_eq!((ks.keyslot.as_slice(), ks.epoch), (&b"kb"[..], 0));
    // An authorized device holds the key: it can only go through /rotate.
    let r = call(&f.app, raw_req("DELETE", &format!("/v1/vaults/v1/devices/{b_id}"), &token, vec![])).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/keyslot", &tb, vec![])).await;
    assert_eq!(r.status(), StatusCode::OK);
    // A pending join request can be rejected.
    let c = DeviceSecret::generate();
    let c_id = c.public().unwrap().device_id();
    assert_eq!(join(&f.app, &token, &c, "c").await, StatusCode::OK);
    let r = call(&f.app, raw_req("DELETE", &format!("/v1/vaults/v1/devices/{c_id}"), &token, vec![])).await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let r = call(&f.app, Request::get(format!("/v1/vaults/v1/join/{c_id}")).body(Body::empty()).unwrap()).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tokens_are_bound_to_their_vault() {
    let f = fixture();
    let a = DeviceSecret::generate();
    assert_eq!(create(&f.app, "admin", &a, "0".repeat(64)).await, StatusCode::CREATED);
    let token = login(&f.app, "v1", &a).await.unwrap();
    let r = call(&f.app, raw_req("GET", "/v1/vaults/other/log?after=0", &token, vec![])).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_requires_proof() {
    let f = fixture();
    let a = DeviceSecret::generate();
    let keys = VaultKey::generate().derive();
    assert_eq!(create(&f.app, "admin", &a, keys.enroll_verifier()).await, StatusCode::CREATED);

    let c = DeviceSecret::generate();
    let enroll = |proof: String| EnrollRequest {
        device: device(&c, "c"),
        proof,
        keyslot: vec![2],
        epoch: 0,
        challenge: vec![],
        signature: vec![],
    };
    let bad = enroll(hex::encode([7u8; 32]));
    assert_eq!(call(&f.app, json_req("POST", "/v1/vaults/v1/enroll", None, &bad)).await.status(), StatusCode::FORBIDDEN);
    let good = enroll(keys.enroll_proof());
    assert_eq!(call(&f.app, json_req("POST", "/v1/vaults/v1/enroll", None, &good)).await.status(), StatusCode::CREATED);
    assert!(login(&f.app, "v1", &c).await.is_ok());
}

/// The headline property: after `revoke` rotates the key, the revoked
/// device's copy of the old key can't decrypt anything written later, the
/// server refuses new records under the old key, and remaining devices still
/// read the whole history through the key chain.
#[tokio::test]
async fn rotation_locks_revoked_device_out_of_new_data() {
    let f = fixture();
    let (a, b, rec_id) = (DeviceSecret::generate(), DeviceSecret::generate(), DeviceSecret::generate());
    let ring0 = KeyRing::new(0, VaultKey::generate());
    let ta = create_v2(&f.app, &a, &rec_id, ring0.current_key()).await;
    let b_id = b.public().unwrap().device_id();
    let a_id = a.public().unwrap().device_id();
    assert_eq!(join_and_approve(&f.app, &ta, &b, "b", wrap(&b, ring0.current_key()), 0).await, StatusCode::NO_CONTENT);

    // Both devices share epoch 0.
    let before = commit("a", vec![file(1, "before.txt", 1)]);
    assert_eq!(append(&f.app, &ta, before.encrypt(&ring0, "v1")).await, Ok(1));
    let tb = login(&f.app, "v1", &b).await.unwrap();
    let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/keyslot", &tb, vec![])).await;
    let b_ring = KeyRing::new(0, unwrap_key(&b, &json::<KeyslotResponse>(r).await.keyslot));
    let frames = read_log(&f.app, &tb, 0).await.unwrap();
    assert_eq!(Commit::decrypt(&b_ring, "v1", &frames[0].1).unwrap(), before);

    // a revokes b: new epoch, new key for a (and the recovery identity) only.
    let (ring1, link) = ring0.rotate("v1");
    let rotate = |epoch: u32, revoke: Vec<String>, slots: Vec<DeviceKeyslot>| RotateRequest {
        epoch,
        revoke,
        keyslots: slots,
        link: link.clone(),
        recovery: recovery_update(&rec_id, ring1.current_key()),
        challenge: vec![],
        signature: vec![],
    };
    let slot_a = || DeviceKeyslot { device_id: a_id.clone(), keyslot: wrap(&a, ring1.current_key()) };
    let post = |r: &RotateRequest| json_req("POST", "/v1/vaults/v1/rotate", Some(&ta), r);
    assert_eq!(call(&f.app, post(&rotate(2, vec![b_id.clone()], vec![slot_a()]))).await.status(), StatusCode::CONFLICT);
    // b isn't revoked, so it must get a keyslot too.
    assert_eq!(call(&f.app, post(&rotate(1, vec![], vec![slot_a()]))).await.status(), StatusCode::BAD_REQUEST);
    // Wrapping the new key for the device being revoked is refused.
    let leak = DeviceKeyslot { device_id: b_id.clone(), keyslot: wrap(&b, ring1.current_key()) };
    assert_eq!(call(&f.app, post(&rotate(1, vec![b_id.clone()], vec![slot_a(), leak]))).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(call(&f.app, post(&rotate(1, vec![a_id.clone()], vec![]))).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(call(&f.app, post(&rotate(1, vec![b_id.clone()], vec![slot_a()]))).await.status(), StatusCode::NO_CONTENT);

    // b is locked out, even with a token from before.
    assert_eq!(login(&f.app, "v1", &b).await, Err(StatusCode::UNAUTHORIZED));
    assert_eq!(read_log(&f.app, &tb, 0).await, Err(StatusCode::UNAUTHORIZED));

    // Records under the retired key are refused; a falls behind until it refreshes.
    let stale = commit("a", vec![file(2, "stale.txt", 2)]);
    let r = call(&f.app, raw_req("POST", "/v1/vaults/v1/log", &ta, stale.encrypt(&ring0, "v1"))).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(serde_json::from_slice::<ErrorResponse>(&body(r).await).unwrap().error, STALE_EPOCH);
    let (_, blob) = crypto::encrypt_chunk(&ring0, b"old key chunk");
    let r = call(&f.app, raw_req("PUT", &format!("/v1/vaults/v1/blobs/{}", "ee".repeat(32)), &ta, blob)).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);

    // a refreshes: current keyslot + chain rebuild the full ring.
    let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/keyslot", &ta, vec![])).await;
    let ks: KeyslotResponse = json(r).await;
    assert_eq!(ks.epoch, 1);
    let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/keychain", &ta, vec![])).await;
    let chain: KeychainResponse = json(r).await;
    let a_ring = KeyRing::from_chain("v1", ks.epoch, unwrap_key(&a, &ks.keyslot), &chain.links).unwrap();
    assert_eq!(a_ring.key(0).unwrap().as_bytes(), ring0.current_key().as_bytes());

    let after = commit("a", vec![file(3, "after.txt", 3)]);
    assert_eq!(append(&f.app, &ta, after.encrypt(&a_ring, "v1")).await, Ok(2));
    let (cid, blob) = crypto::encrypt_chunk(&a_ring, b"new key chunk");
    let r = call(&f.app, raw_req("PUT", &format!("/v1/vaults/v1/blobs/{cid}"), &ta, blob.clone())).await;
    assert_eq!(r.status(), StatusCode::CREATED);

    // The revoked device's epoch-0 key opens the old commit but nothing after the rotation.
    let frames = read_log(&f.app, &ta, 0).await.unwrap();
    assert_eq!(frames.len(), 2);
    assert!(Commit::decrypt(&b_ring, "v1", &frames[0].1).is_ok());
    assert!(Commit::decrypt(&b_ring, "v1", &frames[1].1).is_err());
    assert!(crypto::decrypt_chunk(&b_ring, &cid, &blob).is_err());
    assert_eq!(Commit::decrypt(&a_ring, "v1", &frames[0].1).unwrap(), before);
    assert_eq!(Commit::decrypt(&a_ring, "v1", &frames[1].1).unwrap(), after);

    // New devices must be approved with a key of the current epoch.
    let c = DeviceSecret::generate();
    assert_eq!(join_and_approve(&f.app, &ta, &c, "c", wrap(&c, ring0.current_key()), 0).await, StatusCode::CONFLICT);
    assert_eq!(join_and_approve(&f.app, &ta, &c, "c", wrap(&c, a_ring.current_key()), 1).await, StatusCode::NO_CONTENT);

    // The rotation survives a server restart.
    let app2 = app_on(f.dir.path(), Duration::from_secs(3600));
    let tc = login(&app2, "v1", &c).await.unwrap();
    let r = call(&app2, raw_req("GET", "/v1/vaults/v1/keyslot", &tc, vec![])).await;
    assert_eq!(json::<KeyslotResponse>(r).await.epoch, 1);
    assert_eq!(login(&app2, "v1", &b).await, Err(StatusCode::UNAUTHORIZED));
}

#[tokio::test]
async fn recovery_enrollment_is_signed_by_the_kit_identity() {
    let f = fixture();
    let (a, rec_id) = (DeviceSecret::generate(), DeviceSecret::generate());
    let ring0 = KeyRing::new(0, VaultKey::generate());
    let ta = create_v2(&f.app, &a, &rec_id, ring0.current_key()).await;

    // Rotate once (no revocation); the kit keeps working across epochs.
    let (ring1, link) = ring0.rotate("v1");
    let a_id = a.public().unwrap().device_id();
    let req = RotateRequest {
        epoch: 1,
        revoke: vec![],
        keyslots: vec![DeviceKeyslot { device_id: a_id, keyslot: wrap(&a, ring1.current_key()) }],
        link,
        recovery: recovery_update(&rec_id, ring1.current_key()),
        challenge: vec![],
        signature: vec![],
    };
    assert_eq!(call(&f.app, json_req("POST", "/v1/vaults/v1/rotate", Some(&ta), &req)).await.status(), StatusCode::NO_CONTENT);

    // The kit holder fetches the current key wrapped to the recovery identity,
    // naming the identity from the kit (without it the vault looks absent).
    let rid = rec_id.public().unwrap().device_id();
    let r = call(&f.app, Request::get(format!("/v1/vaults/v1/recovery?id={rid}")).body(Body::empty()).unwrap()).await;
    let info: RecoveryResponse = json(r).await;
    let rec_info = info.info.unwrap();
    assert_eq!((info.epoch, rec_info.public.device_id()), (1, rid.clone()));
    let k1 = unwrap_key(&rec_id, &info.keyslot);
    assert_eq!(rec_info.mac, crypto::recovery_mac(&k1, "v1", &rec_info.public));

    // The recovery identity can sign challenges but never gets a session.
    assert_eq!(login(&f.app, "v1", &rec_id).await, Err(StatusCode::UNAUTHORIZED));

    let c = DeviceSecret::generate();
    let c_id = c.public().unwrap().device_id();
    let signed = |challenge: Vec<u8>, epoch: u32, signer: &DeviceSecret| {
        let signature = signer.sign(ENROLL_CONTEXT, &enroll_message("v1", &rid, &challenge, &c_id, epoch)).unwrap();
        EnrollRequest { device: device(&c, "c"), proof: String::new(), keyslot: wrap(&c, &k1), epoch, challenge, signature }
    };
    let enroll = |r: &EnrollRequest| json_req("POST", "/v1/vaults/v1/enroll", None, r);

    let forged = signed(challenge(&f.app, "v1", &rid).await.unwrap(), 1, &DeviceSecret::generate());
    assert_eq!(call(&f.app, enroll(&forged)).await.status(), StatusCode::FORBIDDEN);
    let old_epoch = signed(challenge(&f.app, "v1", &rid).await.unwrap(), 0, &rec_id);
    assert_eq!(call(&f.app, enroll(&old_epoch)).await.status(), StatusCode::CONFLICT);
    let good = signed(challenge(&f.app, "v1", &rid).await.unwrap(), 1, &rec_id);
    assert_eq!(call(&f.app, enroll(&good)).await.status(), StatusCode::CREATED);
    // A recorded enrollment can't be replayed (e.g. after the device is revoked).
    assert_eq!(call(&f.app, enroll(&good)).await.status(), StatusCode::FORBIDDEN);

    let tc = login(&f.app, "v1", &c).await.unwrap();
    let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/keyslot", &tc, vec![])).await;
    let ks: KeyslotResponse = json(r).await;
    assert_eq!((unwrap_key(&c, &ks.keyslot).as_bytes(), ks.epoch), (k1.as_bytes(), 1));
}

/// A compromised device can rotate, but it can't swap in a recovery identity
/// of its own and so invalidate the owner's kit: that needs a challenge
/// signed by the current identity.
#[tokio::test]
async fn replacing_the_recovery_identity_needs_its_signature() {
    let f = fixture();
    let (a, rec_id, rogue) = (DeviceSecret::generate(), DeviceSecret::generate(), DeviceSecret::generate());
    let ring0 = KeyRing::new(0, VaultKey::generate());
    let ta = create_v2(&f.app, &a, &rec_id, ring0.current_key()).await;
    let (ring1, link) = ring0.rotate("v1");
    let a_id = a.public().unwrap().device_id();
    let (rid, rogue_id) = (rec_id.public().unwrap().device_id(), rogue.public().unwrap().device_id());
    let req = |challenge: Vec<u8>, signature: Vec<u8>| RotateRequest {
        epoch: 1,
        revoke: vec![],
        keyslots: vec![DeviceKeyslot { device_id: a_id.clone(), keyslot: wrap(&a, ring1.current_key()) }],
        link: link.clone(),
        recovery: recovery_update(&rogue, ring1.current_key()),
        challenge,
        signature,
    };
    let post = |r: &RotateRequest| json_req("POST", "/v1/vaults/v1/rotate", Some(&ta), r);
    let sign = |c: &[u8], signer: &DeviceSecret, epoch: u32| {
        signer.sign(ROTATE_RECOVERY_CONTEXT, &rotate_recovery_message("v1", &rid, c, &rogue_id, epoch)).unwrap()
    };
    let recovery = || async {
        let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/recovery", &ta, vec![])).await;
        let info: RecoveryResponse = json(r).await;
        (info.epoch, info.info.unwrap().public.device_id(), info.keyslot)
    };

    // No signature, one by the new identity, and one for the wrong epoch are all refused.
    assert_eq!(call(&f.app, post(&req(vec![], vec![]))).await.status(), StatusCode::FORBIDDEN);
    let c = challenge(&f.app, "v1", &rid).await.unwrap();
    assert_eq!(call(&f.app, post(&req(c.clone(), sign(&c, &rogue, 1)))).await.status(), StatusCode::FORBIDDEN);
    let c = challenge(&f.app, "v1", &rid).await.unwrap();
    assert_eq!(call(&f.app, post(&req(c.clone(), sign(&c, &rec_id, 2)))).await.status(), StatusCode::FORBIDDEN);
    // A challenge is consumed by the attempt, so a good signature over it is too late.
    assert_eq!(call(&f.app, post(&req(c.clone(), sign(&c, &rec_id, 1)))).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(recovery().await.0, 0);
    assert_eq!(recovery().await.1, rid);

    let c = challenge(&f.app, "v1", &rid).await.unwrap();
    assert_eq!(call(&f.app, post(&req(c.clone(), sign(&c, &rec_id, 1)))).await.status(), StatusCode::NO_CONTENT);
    let (epoch, id, slot) = recovery().await;
    assert_eq!((epoch, id), (1, rogue_id.clone()));
    assert_eq!(unwrap_key(&rogue, &slot).as_bytes(), ring1.current_key().as_bytes());
}

#[tokio::test]
async fn first_rotation_disables_legacy_kit_proof() {
    let f = fixture();
    let a = DeviceSecret::generate();
    let ring0 = KeyRing::new(0, VaultKey::generate());
    let keys = ring0.current().clone();
    let req = CreateVaultRequest {
        device: device(&a, "a"),
        enroll_verifier: keys.enroll_verifier(),
        keyslot: wrap(&a, ring0.current_key()),
        recovery: None,
    };
    assert_eq!(create_with(&f.app, "admin", &req).await, StatusCode::CREATED);
    let ta = login(&f.app, "v1", &a).await.unwrap();
    let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/recovery", &ta, vec![])).await;
    assert!(json::<RecoveryResponse>(r).await.info.is_none());

    // Rotating a legacy vault requires registering a recovery identity.
    let (ring1, link) = ring0.rotate("v1");
    let rec_id = DeviceSecret::generate();
    let rotate = RotateRequest {
        epoch: 1,
        revoke: vec![],
        keyslots: vec![DeviceKeyslot { device_id: a.public().unwrap().device_id(), keyslot: wrap(&a, ring1.current_key()) }],
        link,
        recovery: recovery_update(&rec_id, ring1.current_key()),
        challenge: vec![],
        signature: vec![],
    };
    assert_eq!(call(&f.app, json_req("POST", "/v1/vaults/v1/rotate", Some(&ta), &rotate)).await.status(), StatusCode::NO_CONTENT);

    // The old proof derives from the epoch-0 key every former device knew: no longer accepted.
    let c = DeviceSecret::generate();
    let legacy = EnrollRequest {
        device: device(&c, "c"),
        proof: keys.enroll_proof(),
        keyslot: vec![1],
        epoch: 1,
        challenge: vec![],
        signature: vec![],
    };
    assert_eq!(call(&f.app, json_req("POST", "/v1/vaults/v1/enroll", None, &legacy)).await.status(), StatusCode::FORBIDDEN);
}

/// Compaction: a device uploads an encrypted snapshot, the server drops the
/// log before it, and a fresh device starts from the snapshot plus the log
/// tail, ending in exactly the state of a full replay.
#[tokio::test]
async fn compacted_log_and_fresh_device_joining_from_snapshot() {
    let f = fixture();
    let (a, rec_id) = (DeviceSecret::generate(), DeviceSecret::generate());
    let ring = KeyRing::new(0, VaultKey::generate());
    let ta = create_v2(&f.app, &a, &rec_id, ring.current_key()).await;

    let commits = [
        commit("a", vec![file(1, "one.txt", 1)]),
        commit("a", vec![file(2, "two.txt", 2)]),
        commit("b", vec![Op::Delete { id: 1, base: 1 }]),
        commit("b", vec![file(3, "three.txt", 3)]),
        commit("a", vec![file(2, "two.txt", 4)]),
    ];
    let mut full = Tree::new();
    for (i, c) in commits.iter().enumerate() {
        assert_eq!(append(&f.app, &ta, c.encrypt(&ring, "v1")).await, Ok(i as u64 + 1));
        full.apply_commit(i as u64 + 1, c);
    }

    // a snapshots its state at seq 3.
    let mut at3 = Tree::new();
    for (i, c) in commits[..3].iter().enumerate() {
        at3.apply_commit(i as u64 + 1, c);
    }
    let snap = at3.snapshot(3).encrypt(&ring, "v1");
    let put = |seq: u64, data: Vec<u8>| raw_req("PUT", &format!("/v1/vaults/v1/snapshot/{seq}"), &ta, data);
    assert_eq!(call(&f.app, put(9, snap.clone())).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(call(&f.app, put(3, rec(7, b"wrong epoch"))).await.status(), StatusCode::CONFLICT);
    assert_eq!(call(&f.app, put(3, snap)).await.status(), StatusCode::CREATED);

    let compact = |upto: u64| json_req("POST", "/v1/vaults/v1/log/compact", Some(&ta), &CompactRequest { upto });
    assert_eq!(call(&f.app, compact(4)).await.status(), StatusCode::CONFLICT); // no snapshot covers 4
    assert_eq!(json::<CompactResponse>(call(&f.app, compact(3)).await).await.log_start, 4);
    assert_eq!(read_log(&f.app, &ta, 0).await, Err(StatusCode::GONE));
    assert_eq!(read_log(&f.app, &ta, 2).await, Err(StatusCode::GONE));

    // A fresh device joins and never sees entries 1..=3.
    let c = DeviceSecret::generate();
    assert_eq!(join_and_approve(&f.app, &ta, &c, "c", wrap(&c, ring.current_key()), 0).await, StatusCode::NO_CONTENT);
    let tc = login(&f.app, "v1", &c).await.unwrap();
    let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/snapshot", &tc, vec![])).await;
    let frames = decode_frames(&body(r).await).unwrap();
    let (seq, data) = &frames[0];
    assert_eq!(*seq, 3);
    let mut tree = Tree::from_snapshot(&Snapshot::decrypt(&ring, "v1", *seq, data).unwrap()).unwrap();
    let tail = read_log(&f.app, &tc, *seq).await.unwrap();
    assert_eq!(tail.iter().map(|f| f.0).collect::<Vec<_>>(), vec![4, 5]);
    for (s, data) in &tail {
        tree.apply_commit(*s, &Commit::decrypt(&ring, "v1", data).unwrap());
    }
    assert_eq!(tree.snapshot(0), full.snapshot(0));
    assert!(tree.resolve("one.txt").is_none() && tree.resolve("three.txt").is_some());

    // After a restart without the head hint the head is still found, and appends continue at 6.
    std::fs::remove_file(f.dir.path().join("vaults/v1/head")).unwrap();
    let app2 = app_on(f.dir.path(), Duration::from_secs(3600));
    let ta2 = login(&app2, "v1", &a).await.unwrap();
    assert_eq!(read_log(&app2, &ta2, 0).await, Err(StatusCode::GONE));
    assert_eq!(append(&app2, &ta2, commit("a", vec![]).encrypt(&ring, "v1")).await, Ok(6));
}

#[tokio::test]
async fn gc_deletes_only_requested_blobs_past_grace_at_current_head() {
    let dir = tempfile::tempdir().unwrap();
    let app = app_on(dir.path(), Duration::ZERO);
    let (a, rec_id) = (DeviceSecret::generate(), DeviceSecret::generate());
    let ring = KeyRing::new(0, VaultKey::generate());
    let ta = create_v2(&app, &a, &rec_id, ring.current_key()).await;

    let mut ids = Vec::new();
    for content in [&b"live"[..], b"dead", b"young"] {
        let (id, blob) = crypto::encrypt_chunk(&ring, content);
        let r = call(&app, raw_req("PUT", &format!("/v1/vaults/v1/blobs/{id}"), &ta, blob)).await;
        assert_eq!(r.status(), StatusCode::CREATED);
        ids.push(id.to_hex());
    }
    assert_eq!(append(&app, &ta, commit("a", vec![]).encrypt(&ring, "v1")).await, Ok(1));

    // Listing by prefix (the server knows ids, sizes and times, nothing else).
    let r = call(&app, raw_req("GET", &format!("/v1/vaults/v1/blobs?prefix={}", &ids[1][..2]), &ta, vec![])).await;
    assert!(json::<BlobListResponse>(r).await.blobs.iter().any(|b| b.id == ids[1]));
    let r = call(&app, raw_req("GET", "/v1/vaults/v1/blobs?prefix=zz", &ta, vec![])).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let gc = |head: u64, grace_secs: u64, ids: Vec<String>, token: &str| {
        json_req("POST", "/v1/vaults/v1/blobs/gc", Some(token), &GcRequest { head, grace_secs, ids })
    };
    assert_eq!(call(&app, gc(1, 0, vec![ids[1].clone()], "bogus")).await.status(), StatusCode::UNAUTHORIZED);
    // The client's live set was computed at an old head: refused.
    assert_eq!(call(&app, gc(0, 0, vec![ids[1].clone()], &ta)).await.status(), StatusCode::CONFLICT);
    // Too young for the requested grace: kept.
    let r: GcResponse = json(call(&app, gc(1, 3600, vec![ids[1].clone()], &ta)).await).await;
    assert_eq!((r.deleted, r.kept), (0, 1));
    let r: GcResponse = json(call(&app, gc(1, 0, vec![ids[1].clone()], &ta)).await).await;
    assert_eq!((r.deleted, r.kept), (1, 0));

    let missing = MissingRequest { ids: ids.clone() };
    let r = call(&app, json_req("POST", "/v1/vaults/v1/blobs/missing", Some(&ta), &missing)).await;
    assert_eq!(json::<MissingResponse>(r).await.missing, vec![ids[1].clone()]);

    // The server's own minimum grace wins over a client asking for zero.
    let strict = app_on(dir.path(), Duration::from_secs(3600));
    let ts = login(&strict, "v1", &a).await.unwrap();
    let r: GcResponse = json(call(&strict, gc(1, 0, vec![ids[2].clone()], &ts)).await).await;
    assert_eq!((r.deleted, r.kept), (0, 1));
}

// ----- invite codes and the unauthenticated surface ---------------------------

/// `/join` needs a one-time invite code minted by an authorized device; the
/// approval and fingerprint check afterwards are unchanged.
#[tokio::test]
async fn joining_needs_a_fresh_invite_code() {
    let f = fixture();
    let (a, rec_id) = (DeviceSecret::generate(), DeviceSecret::generate());
    let ring = KeyRing::new(0, VaultKey::generate());
    let ta = create_v2(&f.app, &a, &rec_id, ring.current_key()).await;
    let (b, c) = (DeviceSecret::generate(), DeviceSecret::generate());
    let b_id = b.public().unwrap().device_id();
    let status = |r: Response<Body>| async move {
        let code = r.status();
        (code, serde_json::from_slice::<ErrorResponse>(&body(r).await).map(|e| e.error).unwrap_or_default())
    };

    // Without a code, with a made-up one, or with a malformed one: refused, nothing stored.
    let (code, msg) = status(call(&f.app, join_req("v1", "", &b, "b")).await).await;
    assert_eq!((code, msg.as_str()), (StatusCode::FORBIDDEN, "invite code required"));
    let (code, msg) = status(call(&f.app, join_req("v1", "ABCD-EFGH", &b, "b")).await).await;
    assert_eq!((code, msg.as_str()), (StatusCode::FORBIDDEN, "invalid, expired or already used invite code"));
    assert_eq!(call(&f.app, join_req("v1", "0000-0000", &b, "b")).await.status(), StatusCode::FORBIDDEN);
    let r = call(&f.app, Request::get(format!("/v1/vaults/v1/join/{b_id}")).body(Body::empty()).unwrap()).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let devices: Vec<DeviceInfo> = json(call(&f.app, raw_req("GET", "/v1/vaults/v1/devices", &ta, vec![])).await).await;
    assert_eq!(devices.len(), 1);

    // Only authorized devices mint codes.
    let r = call(&f.app, Request::post("/v1/vaults/v1/invites").body(Body::empty()).unwrap()).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = call(&f.app, raw_req("POST", "/v1/vaults/v1/invites", "bogus", vec![])).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let inv: InviteResponse = json(call(&f.app, raw_req("POST", "/v1/vaults/v1/invites", &ta, vec![])).await).await;
    assert_eq!(inv.expires_in, 3600);
    let plain = normalize_invite_code(&inv.code).expect("code is made of the invite alphabet");
    assert_eq!((plain.len(), inv.code.len(), &inv.code[4..5]), (INVITE_CODE_LEN, 9, "-"));
    assert_ne!(invite(&f.app, &ta).await, inv.code);

    // A real code for a vault that doesn't exist looks like a wrong code.
    assert_eq!(call(&f.app, join_req("nope", &inv.code, &b, "b")).await.status(), StatusCode::FORBIDDEN);

    // Happy path, typed loosely; the same device may repeat the request, nobody else may.
    let typed = format!(" {} ", plain.to_lowercase());
    let st: JoinStatus = json(call(&f.app, join_req("v1", &typed, &b, "b")).await).await;
    assert_eq!(st.state, DeviceState::Pending);
    let st: JoinStatus = json(call(&f.app, join_req("v1", &inv.code, &b, "b")).await).await;
    assert_eq!(st.state, DeviceState::Pending);
    assert_eq!(call(&f.app, join_req("v1", &inv.code, &c, "c")).await.status(), StatusCode::FORBIDDEN);
    let devices: Vec<DeviceInfo> = json(call(&f.app, raw_req("GET", "/v1/vaults/v1/devices", &ta, vec![])).await).await;
    assert_eq!(devices.iter().filter(|d| d.state == DeviceState::Pending).map(|d| &d.name).collect::<Vec<_>>(), ["b"]);

    // Approval works as before: the pending device gets its keyslot and can log in.
    let r = call(&f.app, Request::get(format!("/v1/vaults/v1/join/{b_id}")).body(Body::empty()).unwrap()).await;
    assert_eq!(json::<JoinStatus>(r).await.state, DeviceState::Pending);
    let approve = ApproveRequest { keyslot: wrap(&b, ring.current_key()), epoch: 0 };
    let r = call(&f.app, json_req("POST", &format!("/v1/vaults/v1/devices/{b_id}/approve"), Some(&ta), &approve)).await;
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let tb = login(&f.app, "v1", &b).await.unwrap();
    let ks: KeyslotResponse = json(call(&f.app, raw_req("GET", "/v1/vaults/v1/keyslot", &tb, vec![])).await).await;
    assert_eq!(unwrap_key(&b, &ks.keyslot).as_bytes(), ring.current_key().as_bytes());
    // The code is spent even after the join was approved; a newly minted one works for c.
    assert_eq!(call(&f.app, join_req("v1", &inv.code, &c, "c")).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(join(&f.app, &tb, &c, "c").await, StatusCode::OK);
}

#[tokio::test]
async fn expired_invite_codes_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let fs = object_store::local::LocalFileSystem::new_with_prefix(dir.path()).unwrap();
    let state = AppState::new(Store::new(Arc::new(fs)), "admin".into()).with_invite_ttl(Duration::from_millis(50));
    let app = router(Arc::new(state));
    let (a, rec_id, b) = (DeviceSecret::generate(), DeviceSecret::generate(), DeviceSecret::generate());
    let ta = create_v2(&app, &a, &rec_id, &VaultKey::generate()).await;

    let r: InviteResponse = json(call(&app, raw_req("POST", "/v1/vaults/v1/invites", &ta, vec![])).await).await;
    assert_eq!(r.expires_in, 0);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(call(&app, join_req("v1", &r.code, &b, "b")).await.status(), StatusCode::FORBIDDEN);
    // Expired codes make room for new ones; a fresh one works.
    assert_eq!(join(&app, &ta, &b, "b").await, StatusCode::OK);
}

/// Strangers can't tell a vault that exists from one that doesn't: the open
/// endpoints answer unknown vaults, unknown devices and bad requests alike.
#[tokio::test]
async fn open_endpoints_do_not_confirm_vault_existence() {
    let f = fixture();
    let (a, rec_id) = (DeviceSecret::generate(), DeviceSecret::generate());
    let ta = create_v2(&f.app, &a, &rec_id, &VaultKey::generate()).await;
    let rid = rec_id.public().unwrap().device_id();
    let get = |uri: String| async { call(&f.app, Request::get(uri).body(Body::empty()).unwrap()).await.status() };

    // /recovery: 404 without the recovery id from the kit, for known and unknown vaults.
    assert_eq!(get("/v1/vaults/v1/recovery".into()).await, StatusCode::NOT_FOUND);
    assert_eq!(get(format!("/v1/vaults/v1/recovery?id={}", "0".repeat(32))).await, StatusCode::NOT_FOUND);
    assert_eq!(get(format!("/v1/vaults/nope/recovery?id={rid}")).await, StatusCode::NOT_FOUND);
    assert_eq!(get(format!("/v1/vaults/v1/recovery?id={rid}")).await, StatusCode::OK);
    let r = call(&f.app, raw_req("GET", "/v1/vaults/v1/recovery", &ta, vec![])).await;
    assert_eq!(json::<RecoveryResponse>(r).await.info.map(|i| i.public.device_id()), Some(rid.clone()));
    assert_eq!(call(&f.app, raw_req("GET", "/v1/vaults/v1/recovery", "bogus", vec![])).await.status(), StatusCode::UNAUTHORIZED);

    // /join/{device}: unknown device and unknown vault both 404.
    let id = "a".repeat(32);
    assert_eq!(get(format!("/v1/vaults/v1/join/{id}")).await, StatusCode::NOT_FOUND);
    assert_eq!(get(format!("/v1/vaults/nope/join/{id}")).await, StatusCode::NOT_FOUND);

    // The auth handshake and /enroll answer unknown vaults like unknown devices.
    assert_eq!(challenge(&f.app, "v1", &id).await, Err(StatusCode::UNAUTHORIZED));
    assert_eq!(challenge(&f.app, "nope", &id).await, Err(StatusCode::UNAUTHORIZED));
    assert_eq!(login(&f.app, "nope", &a).await, Err(StatusCode::UNAUTHORIZED));
    let enroll = |vault: &str| {
        let req = EnrollRequest {
            device: device(&a, "x"),
            proof: String::new(),
            keyslot: vec![1],
            epoch: 0,
            challenge: vec![],
            signature: vec![],
        };
        json_req("POST", &format!("/v1/vaults/{vault}/enroll"), None, &req)
    };
    assert_eq!(call(&f.app, enroll("v1")).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(call(&f.app, enroll("nope")).await.status(), StatusCode::FORBIDDEN);
}

/// The unauthenticated routes share a small per-IP budget; authenticated ones don't.
#[tokio::test]
async fn open_endpoints_are_rate_limited_per_ip() {
    let dir = tempfile::tempdir().unwrap();
    let fs = object_store::local::LocalFileSystem::new_with_prefix(dir.path()).unwrap();
    let state = AppState::new(Store::new(Arc::new(fs)), "admin".into()).with_rate_limit(3);
    let app = router(Arc::new(state));
    let from = |ip: &str, mut req: Request<Body>| {
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip.parse().unwrap(), 4242)));
        req
    };
    let poll = |ip: &str| from(ip, Request::get(format!("/v1/vaults/v1/join/{}", "a".repeat(32))).body(Body::empty()).unwrap());

    for _ in 0..3 {
        assert_eq!(call(&app, poll("10.0.0.1")).await.status(), StatusCode::NOT_FOUND);
    }
    let r = call(&app, poll("10.0.0.1")).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers().get("retry-after").is_some());
    // Another client is unaffected, and so is the authenticated API.
    assert_eq!(call(&app, poll("10.0.0.2")).await.status(), StatusCode::NOT_FOUND);
    let (a, rec_id) = (DeviceSecret::generate(), DeviceSecret::generate());
    let ta = create_v2(&app, &a, &rec_id, &VaultKey::generate()).await; // 3 open requests, from the shared bucket
    for _ in 0..5 {
        assert_eq!(call(&app, raw_req("GET", "/v1/vaults/v1/devices", &ta, vec![])).await.status(), StatusCode::OK);
        assert_eq!(call(&app, raw_req("POST", "/v1/vaults/v1/invites", &ta, vec![])).await.status(), StatusCode::OK);
    }
    assert_eq!(call(&app, poll("10.0.0.1")).await.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ----- automatic maintenance ---------------------------------------------------

fn app_with(dir: &std::path::Path, policy: crate::api::MaintenancePolicy) -> (Router, Arc<AppState>) {
    let fs = object_store::local::LocalFileSystem::new_with_prefix(dir).unwrap();
    let state = Arc::new(
        AppState::new(Store::new(Arc::new(fs)), "admin".into())
            .with_min_gc_grace(Duration::from_secs(1))
            .with_policy(policy),
    );
    (router(state.clone()), state)
}

async fn status(app: &Router, token: &str) -> MaintenanceStatus {
    json(call(app, raw_req("GET", "/v1/vaults/v1/maintenance", token, vec![])).await).await
}

async fn lease(app: &Router, token: &str, task: MaintenanceTask, force: bool) -> Result<String, StatusCode> {
    let r = call(app, json_req("POST", "/v1/vaults/v1/maintenance/lease", Some(token), &LeaseRequest { task, force })).await;
    if !r.status().is_success() {
        return Err(r.status());
    }
    Ok(serde_json::from_slice::<LeaseResponse>(&body(r).await).unwrap().lease)
}

async fn release(app: &Router, token: &str, lease: &str, success: bool) -> StatusCode {
    let uri = format!("/v1/vaults/v1/maintenance/lease/{lease}");
    call(app, json_req("POST", &uri, Some(token), &ReleaseRequest { success })).await.status()
}

/// The server says when compaction/GC are due and lets only one device at a
/// time run them; other devices are refused until the lease is released.
#[tokio::test]
async fn maintenance_policy_and_lease() {
    let dir = tempfile::tempdir().unwrap();
    let policy = crate::api::MaintenancePolicy {
        compact_after: 3,
        compact_min_interval: Duration::ZERO,
        gc_interval: Duration::from_secs(1),
        gc_grace: Duration::from_secs(1),
        trash: Duration::from_secs(3 * 86_400),
        lease_ttl: Duration::from_secs(60),
    };
    let (app, _) = app_with(dir.path(), policy);
    let (a, rec_id) = (DeviceSecret::generate(), DeviceSecret::generate());
    let ring = KeyRing::new(0, VaultKey::generate());
    let ta = create_v2(&app, &a, &rec_id, ring.current_key()).await;
    let b = DeviceSecret::generate();
    assert_eq!(join_and_approve(&app, &ta, &b, "b", wrap(&b, ring.current_key()), 0).await, StatusCode::NO_CONTENT);
    let tb = login(&app, "v1", &b).await.unwrap();

    let mut tree = Tree::new();
    for i in 1..=2u64 {
        let c = commit("a", vec![file(i as u128, &format!("f{i}"), i as u8)]);
        append(&app, &ta, c.encrypt(&ring, "v1")).await.unwrap();
        tree.apply_commit(i, &c);
    }
    let s = status(&app, &ta).await;
    assert!(!s.compact_due && s.commits_since_snapshot == 2);
    assert_eq!(s.trash_secs, 3 * 86_400);
    assert_eq!(lease(&app, &ta, MaintenanceTask::Compact, false).await, Err(StatusCode::CONFLICT)); // not due
    let c = commit("a", vec![file(3, "f3", 3)]);
    append(&app, &ta, c.encrypt(&ring, "v1")).await.unwrap();
    tree.apply_commit(3, &c);
    assert!(status(&app, &ta).await.compact_due);

    // b takes the lease; a is locked out of compaction and GC meanwhile.
    let lb = lease(&app, &tb, MaintenanceTask::Compact, false).await.unwrap();
    assert_eq!(lease(&app, &ta, MaintenanceTask::Gc, true).await, Err(StatusCode::CONFLICT));
    let s = status(&app, &ta).await;
    assert_eq!(s.lease.as_ref().map(|l| l.task), Some(MaintenanceTask::Compact));
    let compact = |t: &str| json_req("POST", "/v1/vaults/v1/log/compact", Some(t), &CompactRequest { upto: 3 });
    assert_eq!(call(&app, compact(&ta)).await.status(), StatusCode::CONFLICT);
    let gc = |t: &str| json_req("POST", "/v1/vaults/v1/blobs/gc", Some(t), &GcRequest { head: 3, grace_secs: 1, ids: vec![] });
    assert_eq!(call(&app, gc(&ta)).await.status(), StatusCode::CONFLICT);

    // b compacts; the server records it and compaction is no longer due.
    let snap = tree.snapshot(3).encrypt(&ring, "v1");
    assert_eq!(call(&app, raw_req("PUT", "/v1/vaults/v1/snapshot/3", &tb, snap)).await.status(), StatusCode::CREATED);
    assert!(call(&app, compact(&tb)).await.status().is_success());
    assert_eq!(release(&app, &ta, &lb, true).await, StatusCode::NOT_FOUND); // not a's lease
    assert_eq!(release(&app, &tb, &lb, true).await, StatusCode::NO_CONTENT);
    let s = status(&app, &ta).await;
    assert!(s.last_compact > 0 && !s.compact_due && s.commits_since_snapshot == 0 && s.lease.is_none());

    // GC becomes due after its interval; a successful run resets it.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(status(&app, &ta).await.gc_due);
    let la = lease(&app, &ta, MaintenanceTask::Gc, false).await.unwrap();
    assert!(call(&app, gc(&ta)).await.status().is_success());
    assert_eq!(release(&app, &ta, &la, true).await, StatusCode::NO_CONTENT);
    let s = status(&app, &ta).await;
    assert!(s.last_gc > 0 && !s.gc_due);
    assert_eq!(lease(&app, &ta, MaintenanceTask::Gc, false).await, Err(StatusCode::CONFLICT));
    // A failed run doesn't count as done; `force` works even when not due.
    let la = lease(&app, &ta, MaintenanceTask::Gc, true).await.unwrap();
    assert_eq!(release(&app, &ta, &la, false).await, StatusCode::NO_CONTENT);
    assert_eq!(status(&app, &ta).await.last_gc, s.last_gc);
}

/// The sweeper removes what an interrupted compaction left behind, superseded
/// snapshots and expired join requests.
#[tokio::test]
async fn sweep_cleans_leftovers() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app_with(dir.path(), Default::default());
    let (a, rec_id) = (DeviceSecret::generate(), DeviceSecret::generate());
    let ring = KeyRing::new(0, VaultKey::generate());
    let ta = create_v2(&app, &a, &rec_id, ring.current_key()).await;
    let mut tree = Tree::new();
    for i in 1..=3u64 {
        let c = commit("a", vec![file(i as u128, &format!("f{i}"), i as u8)]);
        append(&app, &ta, c.encrypt(&ring, "v1")).await.unwrap();
        tree.apply_commit(i, &c);
        if i >= 2 {
            let snap = tree.snapshot(i).encrypt(&ring, "v1");
            let r = call(&app, raw_req("PUT", &format!("/v1/vaults/v1/snapshot/{i}"), &ta, snap)).await;
            assert_eq!(r.status(), StatusCode::CREATED);
        }
    }
    let stale = DeviceSecret::generate();
    assert_eq!(join(&app, &ta, &stale, "old").await, StatusCode::OK);

    // Simulate a compaction that recorded the new log start but crashed
    // before deleting entries, and a join request older than its TTL.
    let v = dir.path().join("vaults/v1");
    std::fs::write(v.join("log_start"), "3").unwrap();
    let dev_file = v.join(format!("devices/{}.json", stale.public().unwrap().device_id()));
    let mut d: DeviceInfo = serde_json::from_slice(&std::fs::read(&dev_file).unwrap()).unwrap();
    d.created = 1;
    std::fs::write(&dev_file, serde_json::to_vec(&d).unwrap()).unwrap();

    let (_, state) = app_with(dir.path(), Default::default());
    crate::api::sweep(&state).await.unwrap();
    let exists = |p: &str| v.join(p).exists();
    assert!(!exists("log/00000000000000000001") && !exists("log/00000000000000000002"));
    assert!(exists("log/00000000000000000003"));
    assert!(!exists("snapshots/00000000000000000002") && exists("snapshots/00000000000000000003"));
    assert!(!dev_file.exists());
    assert!(exists(&format!("devices/{}.json", a.public().unwrap().device_id())));
}

/// Devices see the `fs` backend's free space; without a data dir (S3) it's unknown.
#[tokio::test]
async fn storage_space() {
    let dir = tempfile::tempdir().unwrap();
    let fs = object_store::local::LocalFileSystem::new_with_prefix(dir.path()).unwrap();
    let state = AppState::new(Store::new(Arc::new(fs)), "admin".into()).with_data_dir(dir.path().into());
    let app = router(Arc::new(state));
    let (a, rec_id) = (DeviceSecret::generate(), DeviceSecret::generate());
    let token = create_v2(&app, &a, &rec_id, &VaultKey::generate()).await;

    let r = call(&app, Request::builder().uri("/v1/vaults/v1/storage").body(Body::empty()).unwrap()).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let info: StorageInfo = json(call(&app, raw_req("GET", "/v1/vaults/v1/storage", &token, vec![])).await).await;
    let space = info.space.expect("fs backend reports space");
    assert!(space.total > 0 && space.free <= space.total);

    let f = fixture();
    let token = create_v2(&f.app, &a, &rec_id, &VaultKey::generate()).await;
    let info: StorageInfo = json(call(&f.app, raw_req("GET", "/v1/vaults/v1/storage", &token, vec![])).await).await;
    assert_eq!(info.space, None);
}
