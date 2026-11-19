use super::*;
use ssh_agent_lib::proto::PublicCredential;
use ssh_key::rand_core::OsRng;
use rsa::signature::Verifier;
use ssh_key::private::KeypairData;
use ssh_key::{LineEnding, PublicKey};

fn openssh(key: &PrivateKey) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(key.to_openssh(LineEnding::LF).unwrap().as_bytes().to_vec())
}

fn ed25519(comment: &str) -> PrivateKey {
    let mut k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    k.set_comment(comment);
    k
}

fn live() -> AtomicBool {
    AtomicBool::new(true)
}

fn sign_req(key: &PrivateKey, data: &[u8], flags: u32) -> Request {
    Request::SignRequest(SignRequest {
        credential: PublicCredential::Key(key.public_key().key_data().clone()),
        data: data.to_vec(),
        flags,
    })
}

fn identities(store: &KeyStore) -> Vec<Identity> {
    match store.handle(Request::RequestIdentities) {
        Response::IdentitiesAnswer(ids) => ids,
        other => panic!("{other:?}"),
    }
}

#[test]
fn parses_only_unencrypted_openssh_private_keys() {
    let plain = ed25519("me@laptop");
    let no_comment = ed25519("");
    let locked = ed25519("locked").encrypt(&mut OsRng, "pw").unwrap();
    let files = vec![
        ("id_ed25519".to_string(), openssh(&plain)),
        ("work".to_string(), openssh(&no_comment)),
        ("locked".to_string(), openssh(&locked)),
        ("config".to_string(), Zeroizing::new(b"Host *\n  User me\n".to_vec())),
        ("garbage".to_string(), Zeroizing::new(b"-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n".to_vec())),
    ];
    let found = parse_keys("family", ".ssh", files);
    let keys = &found.keys;
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].comment, "me@laptop");
    assert_eq!(keys[0].source, "family:\\.ssh\\id_ed25519");
    // Without a comment in the key, the file it came from is shown.
    assert_eq!(keys[1].comment, "family:\\.ssh\\work");
    // Key-looking files that can't be used are reported; `config` isn't.
    let skipped: Vec<&str> = found.skipped.iter().map(|s| s.file.as_str()).collect();
    assert_eq!(skipped, ["locked", "garbage"]);
    assert!(found.skipped[0].reason.contains("passphrase"));
}

/// PuTTYgen's OpenSSH exports wrap at 64 columns; Windows editors use CRLF.
#[test]
fn openssh_keys_load_whatever_the_line_width() {
    let key = ed25519("exported");
    let text = String::from_utf8(openssh(&key).to_vec()).unwrap();
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let wrapped: Vec<&str> = body.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    let putty = format!("{OPENSSH_BEGIN}\r\n{}\r\n{OPENSSH_END}\r\n", wrapped.join("\r\n"));
    assert!(PrivateKey::from_openssh(&putty).is_err(), "ssh-key alone refuses it");

    let found = parse_keys("v", ".ssh", vec![("id".into(), Zeroizing::new(putty.into_bytes()))]);
    assert!(found.skipped.is_empty(), "{:?}", found.skipped);
    assert_eq!(found.keys[0].public(), key.public_key().key_data());
}

/// PuTTYgen pads an exported key's private section to 16 bytes; OpenSSH
/// accepts that, `ssh-key` alone doesn't.
#[test]
fn openssh_keys_padded_like_puttygen_load() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let key = ecdsa(ssh_key::EcdsaCurve::NistP384);
    let text = String::from_utf8(openssh(&key).to_vec()).unwrap();
    let mut blob = b64.decode(text.lines().filter(|l| !l.starts_with("-----")).collect::<String>()).unwrap();

    // Skip the magic, cipher, kdf, kdf options, key count and public key.
    let mut at = b"openssh-key-v1\0".len();
    let len_at = |b: &[u8], at: usize| u32::from_be_bytes(b[at..at + 4].try_into().unwrap()) as usize;
    for _ in 0..3 {
        at += 4 + len_at(&blob, at);
    }
    at += 4;
    at += 4 + len_at(&blob, at);
    // Eight more padding bytes, continuing the 1, 2, 3, … sequence.
    let private_len = len_at(&blob, at);
    let last = blob[at + 4 + private_len - 1];
    let extra: Vec<u8> = (1..=8).map(|i| last + i).collect();
    blob.splice(at + 4 + private_len..at + 4 + private_len, extra);
    blob[at..at + 4].copy_from_slice(&((private_len + 8) as u32).to_be_bytes());

    let body = b64.encode(&blob);
    let lines: Vec<&str> = body.as_bytes().chunks(70).map(|c| std::str::from_utf8(c).unwrap()).collect();
    let padded = format!("{OPENSSH_BEGIN}\n{}\n{OPENSSH_END}\n", lines.join("\n"));
    assert!(PrivateKey::from_openssh(&padded).is_err(), "ssh-key alone refuses it");

    let found = parse_keys("v", ".ssh", vec![("id_ecdsa".into(), Zeroizing::new(padded.into_bytes()))]);
    assert!(found.skipped.is_empty(), "{:?}", found.skipped);
    assert_eq!(found.keys[0].public(), key.public_key().key_data());
}

/// A 2048-bit RSA key, made once per test run (RSA generation is the slow
/// part; the dev profile builds `rsa` and `num-bigint-dig` optimized).
fn rsa_key() -> PrivateKey {
    static KEY: std::sync::OnceLock<PrivateKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let kp = ssh_key::private::RsaKeypair::random(&mut OsRng, 2048).unwrap();
        PrivateKey::new(KeypairData::Rsa(kp), "rsa").unwrap()
    })
    .clone()
}

fn ecdsa(curve: ssh_key::EcdsaCurve) -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ecdsa { curve }).unwrap()
}

/// A random ECDSA key whose private scalar passes `pick` (to hit the
/// short-number cases on purpose rather than by luck).
fn ecdsa_where(curve: ssh_key::EcdsaCurve, pick: impl Fn(&[u8]) -> bool) -> PrivateKey {
    loop {
        let key = ecdsa(curve);
        let KeypairData::Ecdsa(k) = key.key_data() else { unreachable!() };
        if pick(k.private_key_bytes()) {
            return key;
        }
    }
}

/// `key` (ECDSA) as an unencrypted OpenSSH file the way OpenSSH writes it:
/// the scalar as the shortest number, which `ssh-key` alone refuses when
/// that is shorter than the curve's size.
fn openssh_minimal_ecdsa(key: &PrivateKey) -> String {
    use base64::Engine as _;
    use ssh_agent_lib::ssh_encoding::Encode;
    let KeypairData::Ecdsa(k) = key.key_data() else { panic!("not ECDSA") };
    let mut public = Vec::new();
    key.public_key().key_data().encode(&mut public).unwrap();
    // checkints, then the public fields (algorithm, curve, point), d, comment.
    let mut private = vec![7, 7, 7, 7, 7, 7, 7, 7];
    private.extend_from_slice(&public);
    ssh_key::Mpint::from_positive_bytes(k.private_key_bytes()).unwrap().encode(&mut private).unwrap();
    put_string(&mut private, key.comment().as_bytes());
    let pad = (8 - private.len() % 8) % 8;
    private.extend((1..=pad as u8).collect::<Vec<u8>>());

    let mut blob = b"openssh-key-v1\0".to_vec();
    for s in [&b"none"[..], b"none", b""] {
        put_string(&mut blob, s);
    }
    blob.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut blob, &public);
    put_string(&mut blob, &private);
    let body = base64::engine::general_purpose::STANDARD.encode(&blob);
    let lines: Vec<&str> = body.as_bytes().chunks(70).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("{OPENSSH_BEGIN}\n{}\n{OPENSSH_END}\n", lines.join("\n"))
}

#[test]
fn openssh_ecdsa_keys_with_short_scalars_load() {
    for curve in [ssh_key::EcdsaCurve::NistP521, ssh_key::EcdsaCurve::NistP256] {
        let key = ecdsa_where(curve, |d| d[0] == 0 && d[1] < 0x80);
        let file = openssh_minimal_ecdsa(&key);
        assert!(PrivateKey::from_openssh(&file).is_err(), "ssh-key alone refuses it");
        let found = parse_keys("v", ".ssh", vec![("id_ecdsa".into(), Zeroizing::new(file.into_bytes()))]);
        assert!(found.skipped.is_empty(), "{curve:?}: {:?}", found.skipped);
        assert_eq!(found.keys[0].public(), key.public_key().key_data());

        let store = KeyStore::default();
        store.set_vault("v", found, &live());
        let Response::SignResponse(sig) = store.handle(sign_req(&key, b"short", 0)) else { panic!() };
        Verifier::verify(&PublicKey::from(&key), b"short", &sig).unwrap();
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// `key` as an unencrypted `.ppk` file in format `version` (2 or 3), laid
/// out as PuTTYgen writes it. [`ppk_writer_matches_puttygen`] checks this
/// against real PuTTYgen output, so the tests below don't need key files
/// in the repository.
fn to_ppk(key: &PrivateKey, version: u8) -> String {
    use base64::Engine as _;
    use hmac::{Hmac, KeyInit, Mac};
    use ssh_agent_lib::ssh_encoding::Encode;
    let b64 = base64::engine::general_purpose::STANDARD;

    let alg = key.algorithm().to_string();
    let mut public = Vec::new();
    key.public_key().key_data().encode(&mut public).unwrap();
    let mut private = Vec::new();
    match key.key_data() {
        KeypairData::Ed25519(k) => put_string(&mut private, &k.private.to_bytes()),
        KeypairData::Rsa(k) => {
            for m in [&k.private.d, &k.private.p, &k.private.q, &k.private.iqmp] {
                m.encode(&mut private).unwrap();
            }
        }
        KeypairData::Ecdsa(k) => {
            ssh_key::Mpint::from_positive_bytes(k.private_key_bytes()).unwrap().encode(&mut private).unwrap();
        }
        other => panic!("no PPK layout for {other:?}"),
    }
    let mut covered = Vec::new();
    for field in [alg.as_bytes(), b"none", key.comment().as_bytes(), &public, &private] {
        put_string(&mut covered, field);
    }
    let mac = if version == 2 {
        let k = <sha1::Sha1 as sha1::Digest>::digest(b"putty-private-key-file-mac-key");
        let mut m = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(&k).unwrap();
        m.update(&covered);
        hex::encode(m.finalize().into_bytes())
    } else {
        let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&[]).unwrap();
        m.update(&covered);
        hex::encode(m.finalize().into_bytes())
    };
    let lines = |data: &[u8]| {
        let text = b64.encode(data);
        let chunks: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
        format!("{}\n{}\n", chunks.len(), chunks.join("\n"))
    };
    format!(
        "PuTTY-User-Key-File-{version}: {alg}\nEncryption: none\nComment: {}\nPublic-Lines: {}Private-Lines: {}Private-MAC: {mac}\n",
        key.comment(),
        lines(&public),
        lines(&private),
    )
}

/// The key types PuTTYgen makes, each in both file formats.
fn ppk_cases() -> Vec<(String, PrivateKey, u8)> {
    let mut keys = vec![
        ("ed25519", ed25519("")),
        ("rsa", rsa_key()),
        ("p256", ecdsa(ssh_key::EcdsaCurve::NistP256)),
        ("p384", ecdsa(ssh_key::EcdsaCurve::NistP384)),
        // P-521 scalars are 66 bytes, but files store the shortest number:
        // about half have a zero top byte, and so a shorter field.
        ("p521-short", ecdsa_where(ssh_key::EcdsaCurve::NistP521, |d| d[0] == 0 && d[1] < 0x80)),
        ("p521-long", ecdsa_where(ssh_key::EcdsaCurve::NistP521, |d| d[0] != 0)),
        ("p256-short", ecdsa_where(ssh_key::EcdsaCurve::NistP256, |d| d[0] == 0 && d[1] < 0x80)),
    ];
    let mut out = Vec::new();
    for (name, key) in keys.drain(..) {
        for version in [2, 3] {
            let mut key = key.clone();
            key.set_comment(format!("{name}-v{version}"));
            out.push((format!("{name}-v{version}"), key, version));
        }
    }
    out
}

#[test]
fn putty_ppk_keys_load_and_sign() {
    let store = KeyStore::default();
    for (name, key, version) in ppk_cases() {
        let file = to_ppk(&key, version);
        let loaded = ppk::parse(file.as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(loaded.public_key().key_data(), key.public_key().key_data(), "{name}");
        assert_eq!(loaded.comment(), name);
        // PuTTY on Windows writes CRLF line endings.
        assert!(ppk::parse(file.replace('\n', "\r\n").as_bytes()).is_ok(), "{name} with CRLF");

        let files = vec![(format!("{name}.ppk"), Zeroizing::new(file.into_bytes()))];
        store.set_vault("v", parse_keys("v", ".ssh", files), &live());
        let Response::SignResponse(sig) = store.handle(sign_req(&key, b"putty", flags::RSA_SHA2_256)) else {
            panic!("{name}: no signature")
        };
        Verifier::verify(&PublicKey::from(&key), b"putty", &sig).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

/// A passphrase-protected file, as PuTTYgen 0.83 lays one out (format 3,
/// Argon2id); only the headers matter, as it's refused before decrypting.
fn locked_ppk() -> String {
    to_ppk(&ed25519("locked"), 3).replace("Encryption: none", "Encryption: aes256-cbc").replace(
        "Private-Lines:",
        "Key-Derivation: Argon2id\nArgon2-Memory: 8192\nArgon2-Passes: 13\nArgon2-Parallelism: 1\n\
         Argon2-Salt: 8d2c56d0ba2f0b5f1e3b2d1c0a9f8e7d\nPrivate-Lines:",
    )
}

#[test]
fn passphrase_protected_ppk_is_reported_not_loaded() {
    assert_eq!(ppk::parse(locked_ppk().as_bytes()).unwrap_err(), ppk::PpkError::Encrypted);
    let found = parse_keys("v", ".ssh", vec![("work.ppk".into(), Zeroizing::new(locked_ppk().into_bytes()))]);
    assert!(found.keys.is_empty());
    assert_eq!(found.skipped[0].file, "work.ppk");
    assert!(found.skipped[0].reason.contains("passphrase"), "{}", found.skipped[0].reason);
}

#[test]
fn edited_ppk_fails_its_mac() {
    for version in [2, 3] {
        let text = to_ppk(&ed25519("mine"), version);
        let edited = text.replacen("Comment: mine", "Comment: theirs", 1);
        let err = ppk::parse(edited.as_bytes()).unwrap_err();
        assert!(matches!(&err, ppk::PpkError::Invalid(w) if w.contains("MAC")), "v{version}: {err}");
    }
    assert!(matches!(ppk::parse(b"PuTTY-User-Key-File-9: ssh-ed25519\n"), Err(ppk::PpkError::Invalid(_))));
    assert!(matches!(ppk::parse(b"PuTTY-User-Key-File-3: ssh-ed25519\n"), Err(ppk::PpkError::Invalid(_))));
}

/// Compares [`to_ppk`] with real PuTTYgen output, byte for byte. Runs when
/// `KYBERSYNC_PUTTYGEN_SAMPLES` names a folder of `<name>.ppk` files made by
/// PuTTYgen, each with `<name>.openssh`, the same key exported as OpenSSH.
/// One way to make them (PuTTYgen's command line isn't on Windows):
///
/// ```text
/// docker run --rm -v "<folder>:/out" alpine:3.22 sh -c 'apk add -q putty && cd /out && : > /tmp/e &&
///   for t in ed25519 rsa ecdsa; do for v in 2 3; do
///     puttygen -q -t $t -C $t-v$v --new-passphrase /tmp/e --ppk-param version=$v -o $t-v$v.ppk &&
///     puttygen $t-v$v.ppk -O private-openssh-new -o $t-v$v.openssh; done; done'
/// ```
#[test]
fn ppk_writer_matches_puttygen() {
    let Ok(dir) = std::env::var("KYBERSYNC_PUTTYGEN_SAMPLES") else {
        eprintln!("KYBERSYNC_PUTTYGEN_SAMPLES is not set; skipping");
        return;
    };
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "ppk") {
            continue;
        }
        let expected = std::fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
        // Through the agent's own loader: PuTTYgen wraps OpenSSH keys at 64.
        let openssh = std::fs::read(path.with_extension("openssh")).unwrap();
        let key = PrivateKey::from_openssh(&*rewrap_openssh(&openssh))
            .unwrap_or_else(|e| panic!("{}: {e}", path.with_extension("openssh").display()));
        let version = if expected.starts_with("PuTTY-User-Key-File-2") { 2 } else { 3 };
        assert_eq!(to_ppk(&key, version), expected, "{}", path.display());
        ppk::parse(expected.as_bytes()).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        checked += 1;
    }
    assert!(checked > 0, "no .ppk files in {dir}");
    eprintln!("{checked} PuTTYgen files match");
}

#[test]
fn key_folders_are_normalized() {
    assert_eq!(normalize_dir(""), ".ssh");
    assert_eq!(normalize_dir("  \\ / "), ".ssh");
    assert_eq!(normalize_dir(".ssh"), ".ssh");
    assert_eq!(normalize_dir("\\keys/ssh\\"), "keys\\ssh");
    assert_eq!(normalize_dir("./work//ssh"), "work\\ssh");
}

#[test]
fn lists_and_signs_with_vault_keys() {
    let store = KeyStore::default();
    let key = ed25519("me@laptop");
    store.set_vault("family", parse_keys("family", ".ssh", vec![("id".into(), openssh(&key))]), &live());

    let ids = identities(&store);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].comment, "me@laptop");
    assert_eq!(ids[0].credential.key_data(), key.public_key().key_data());

    let Response::SignResponse(sig) = store.handle(sign_req(&key, b"session data", 0)) else { panic!() };
    Verifier::verify(&PublicKey::from(&key), b"session data", &sig).unwrap();

    // An unknown key is refused.
    assert!(matches!(store.handle(sign_req(&ed25519("other"), b"x", 0)), Response::Failure));
}

#[test]
fn ecdsa_keys_sign() {
    let store = KeyStore::default();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP256 }).unwrap();
    store.set_vault("v", parse_keys("v", ".ssh", vec![("id_ecdsa".into(), openssh(&key))]), &live());
    let Response::SignResponse(sig) = store.handle(sign_req(&key, b"data", 0)) else { panic!() };
    Verifier::verify(&PublicKey::from(&key), b"data", &sig).unwrap();
}

#[test]
fn rsa_honours_hash_flags_and_refuses_sha1() {
    let store = KeyStore::default();
    let key = rsa_key();
    store.set_vault("v", parse_keys("v", ".ssh", vec![("id_rsa".into(), openssh(&key))]), &live());
    let public = PublicKey::from(&key);
    for (flag, alg) in [(flags::RSA_SHA2_256, "rsa-sha2-256"), (flags::RSA_SHA2_512, "rsa-sha2-512")] {
        let Response::SignResponse(sig) = store.handle(sign_req(&key, b"data", flag)) else { panic!() };
        assert_eq!(sig.algorithm().as_str(), alg);
        Verifier::verify(&public, b"data", &sig).unwrap();
    }
    assert!(matches!(store.handle(sign_req(&key, b"data", 0)), Response::Failure));
}

#[test]
fn ssh_add_keys_can_be_removed_but_vault_keys_cannot() {
    let store = KeyStore::default();
    let vault_key = ed25519("vault");
    store.set_vault("v", parse_keys("v", ".ssh", vec![("id".into(), openssh(&vault_key))]), &live());

    let added = ed25519("added");
    let add = Request::AddIdentity(AddIdentity {
        credential: PrivateCredential::Key { privkey: added.key_data().clone(), comment: "added".into() },
    });
    assert!(matches!(store.handle(add.clone()), Response::Success));
    assert!(matches!(store.handle(add), Response::Success));
    assert_eq!(identities(&store).len(), 2, "adding twice keeps one copy");

    let remove = |k: &PrivateKey| {
        store.handle(Request::RemoveIdentity(RemoveIdentity {
            credential: PublicCredential::Key(k.public_key().key_data().clone()),
        }))
    };
    assert!(matches!(remove(&vault_key), Response::Failure));
    assert!(matches!(remove(&added), Response::Success));
    assert_eq!(identities(&store).len(), 1);

    assert!(matches!(store.handle(Request::RemoveAllIdentities), Response::Success));
    assert_eq!(identities(&store).len(), 1, "vault keys stay until the vault goes");
}

#[test]
fn a_key_in_two_vaults_is_listed_once_and_removed_with_its_vault() {
    let store = KeyStore::default();
    let key = ed25519("shared");
    let (a, b) = (live(), live());
    store.set_vault("a", parse_keys("a", ".ssh", vec![("id".into(), openssh(&key))]), &a);
    store.set_vault("b", parse_keys("b", ".ssh", vec![("id".into(), openssh(&key))]), &b);
    assert_eq!(identities(&store).len(), 1);
    assert_eq!(store.vault_keys("b").len(), 1);
    assert_eq!(store.vault_keys("b")[0].vault, "b");

    // Once a vault's watcher is told it's gone, late writes are ignored.
    a.store(false, Ordering::SeqCst);
    store.keys.write().unwrap().vaults.remove("a");
    store.set_vault("a", parse_keys("a", ".ssh", vec![("id".into(), openssh(&key))]), &a);
    assert_eq!(store.keys.read().unwrap().vaults.len(), 1);
    store.keys.write().unwrap().vaults.remove("b");
    assert!(identities(&store).is_empty());
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn named_pipe_serves_the_store() {
    use ssh_agent_lib::client::Client;
    let store = Arc::new(KeyStore::default());
    let key = ed25519("piped");
    store.set_vault("v", parse_keys("v", ".ssh", vec![("id".into(), openssh(&key))]), &live());

    let name = format!(r"\\.\pipe\kybersync-ssh-agent-test-{}", std::process::id());
    let task = pipe::serve(&tokio::runtime::Handle::current(), &name, store.clone()).unwrap();
    // A second agent on the same pipe must fail rather than share it.
    assert!(pipe::serve(&tokio::runtime::Handle::current(), &name, store.clone()).is_err());

    let conn = tokio::net::windows::named_pipe::ClientOptions::new().open(&name).unwrap();
    let mut client = Client::new(conn);
    let ids = client.request_identities().await.unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].comment, "piped");
    let sig = client
        .sign(SignRequest { credential: ids[0].credential.clone(), data: b"over the pipe".to_vec(), flags: 0 })
        .await
        .unwrap();
    Verifier::verify(&PublicKey::from(&key), b"over the pipe", &sig).unwrap();
    task.abort();
}

/// Talks to the Pageant window the way PuTTY does. Skipped when a real
/// Pageant is running (the window name is per desktop, not per process).
#[cfg(windows)]
#[test]
fn pageant_window_answers_copydata_requests() {
    use ssh_agent_lib::ssh_encoding::{Decode, Encode};
    use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LPARAM, WPARAM};
    use windows::Win32::System::DataExchange::COPYDATASTRUCT;
    use windows::Win32::System::Memory::{
        CreateFileMappingA, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
    };
    use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SendMessageW, WM_COPYDATA};
    use windows::core::{PCSTR, w};

    if unsafe { FindWindowW(w!("Pageant"), w!("Pageant")) }.is_ok() {
        eprintln!("a Pageant window already exists; skipping");
        return;
    }
    let store = Arc::new(KeyStore::default());
    let key = ed25519("pageant");
    store.set_vault("v", parse_keys("v", ".ssh", vec![("id".into(), openssh(&key))]), &live());
    let agent = pageant::serve(store.clone()).unwrap();
    assert!(pageant::serve(store.clone()).is_err(), "a second Pageant must not start");

    let ask = |req: Request| -> Response {
        const SIZE: usize = 8192;
        let name = format!("PageantRequest{:08x}\0", std::process::id());
        unsafe {
            let map = CreateFileMappingA(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, SIZE as u32, PCSTR(name.as_ptr()))
                .unwrap();
            let view = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 0);
            let buf = std::slice::from_raw_parts_mut(view.Value as *mut u8, SIZE);
            let mut msg = Vec::new();
            req.encode(&mut msg).unwrap();
            buf[..4].copy_from_slice(&(msg.len() as u32).to_be_bytes());
            buf[4..4 + msg.len()].copy_from_slice(&msg);

            let hwnd = FindWindowW(w!("Pageant"), w!("Pageant")).unwrap();
            let cds = COPYDATASTRUCT { dwData: 0x804e_50ba, cbData: name.len() as u32, lpData: name.as_ptr() as *mut _ };
            let ok = SendMessageW(hwnd, WM_COPYDATA, Some(WPARAM(0)), Some(LPARAM(&cds as *const _ as isize)));
            assert_eq!(ok.0, 1, "the window refused the request");

            let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
            let resp = Response::decode(&mut &buf[4..4 + len]).unwrap();
            let _ = UnmapViewOfFile(view);
            let _ = CloseHandle(map);
            resp
        }
    };

    let Response::IdentitiesAnswer(ids) = ask(Request::RequestIdentities) else { panic!() };
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].comment, "pageant");
    let Response::SignResponse(sig) = ask(sign_req(&key, b"via pageant", 0)) else { panic!() };
    Verifier::verify(&PublicKey::from(&key), b"via pageant", &sig).unwrap();

    drop(agent);
    assert!(unsafe { FindWindowW(w!("Pageant"), w!("Pageant")) }.is_err(), "the window closes with the agent");
}

/// The real Windows OpenSSH tools against the pipe: `ssh-add -L` lists the
/// vault key, `ssh-add` adds one, and `ssh-keygen -Y sign` signs through
/// the agent. Skipped when OpenSSH isn't installed.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn windows_openssh_tools_use_the_pipe() {
    use std::process::Command;
    let tools = std::path::Path::new(r"C:\Windows\System32\OpenSSH");
    if !tools.join("ssh-add.exe").exists() {
        eprintln!("Windows OpenSSH is not installed; skipping");
        return;
    }
    let store = Arc::new(KeyStore::default());
    let key = ed25519("from-the-vault");
    store.set_vault("v", parse_keys("v", ".ssh", vec![("id".into(), openssh(&key))]), &live());
    let name = format!(r"\\.\pipe\kybersync-ssh-agent-e2e-{}", std::process::id());
    let task = pipe::serve(&tokio::runtime::Handle::current(), &name, store.clone()).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let run = move |args: Vec<String>| {
        let name = name.clone();
        let tool = args[0].clone();
        tokio::task::spawn_blocking(move || {
            let out = Command::new(tools.join(&tool)).args(&args[1..]).env("SSH_AUTH_SOCK", &name).output().unwrap();
            (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
        })
    };
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();

    let (ok, listed) = run(s(&["ssh-add.exe", "-L"])).await.unwrap();
    assert!(ok, "{listed}");
    assert!(listed.contains("from-the-vault"), "{listed}");

    // `ssh-add <file>` sends the key to the agent.
    let extra = ed25519("added-by-ssh-add");
    let extra_path = dir.path().join("extra");
    std::fs::write(&extra_path, &*openssh(&extra)).unwrap();
    // ssh-add ignores key files other users could read.
    let user = std::env::var("USERNAME").unwrap();
    let acl = Command::new("icacls")
        .arg(&extra_path)
        .args(["/inheritance:r", "/grant:r", &format!("{user}:F")])
        .output()
        .unwrap();
    assert!(acl.status.success(), "{}", String::from_utf8_lossy(&acl.stdout));
    let (ok, out) = run(s(&["ssh-add.exe", extra_path.to_str().unwrap()])).await.unwrap();
    assert!(ok, "{out}");
    assert_eq!(store.list().len(), 2);

    // Sign with the public key only: the private half comes from the agent.
    let pub_path = dir.path().join("vault.pub");
    std::fs::write(&pub_path, key.public_key().to_openssh().unwrap()).unwrap();
    let data = dir.path().join("data.txt");
    std::fs::write(&data, b"signed through kybersync").unwrap();
    let (ok, out) =
        run(s(&["ssh-keygen.exe", "-Y", "sign", "-f", pub_path.to_str().unwrap(), "-n", "file", data.to_str().unwrap()]))
            .await
            .unwrap();
    assert!(ok, "{out}");
    let sig = std::fs::read_to_string(dir.path().join("data.txt.sig")).unwrap();
    let sshsig: ssh_key::SshSig = sig.parse().unwrap();
    key.public_key().verify("file", b"signed through kybersync", &sshsig).unwrap();

    let (ok, out) = run(s(&["ssh-add.exe", "-D"])).await.unwrap();
    assert!(ok, "{out}");
    assert_eq!(store.list().len(), 1, "-D removes only what ssh-add added");
    task.abort();
}
