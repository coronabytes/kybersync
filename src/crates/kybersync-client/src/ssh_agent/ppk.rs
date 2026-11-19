//! PuTTY private key files (`.ppk`, formats 2 and 3), as PuTTYgen writes
//! them. Only unencrypted keys can be read for now; encrypted ones are
//! recognised and reported, since asking for the passphrase isn't built yet.
//!
//! The private half is checked with the file's MAC, then re-encoded in the
//! OpenSSH layout so `ssh-key` builds the key, and the result must match the
//! file's public half.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, KeyInit, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use ssh_key::PrivateKey;
use ssh_key::private::KeypairData;
use std::collections::HashMap;
use zeroize::Zeroizing;

pub const MAGIC: &[u8] = b"PuTTY-User-Key-File-";

#[derive(Debug, PartialEq, Eq)]
pub enum PpkError {
    /// Protected with a passphrase.
    Encrypted,
    /// Not a key we can use; says why.
    Invalid(String),
}

impl std::fmt::Display for PpkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PpkError::Encrypted => f.write_str("protected with a passphrase (not supported yet)"),
            PpkError::Invalid(why) => f.write_str(why),
        }
    }
}

fn invalid(why: impl Into<String>) -> PpkError {
    PpkError::Invalid(why.into())
}

/// Parse a `.ppk` file's contents.
pub fn parse(data: &[u8]) -> Result<PrivateKey, PpkError> {
    let text = std::str::from_utf8(data).map_err(|_| invalid("not a text file"))?;
    let mut lines = text.split('\n').map(|l| l.trim_end_matches('\r'));

    let first = lines.next().unwrap_or_default();
    let (version, alg) = first
        .strip_prefix("PuTTY-User-Key-File-")
        .and_then(|rest| rest.split_once(": "))
        .ok_or_else(|| invalid("not a PuTTY key file"))?;
    let version = match version {
        "2" => 2,
        "3" => 3,
        v => return Err(invalid(format!("PuTTY key file format {v} is not supported"))),
    };

    // `Name: value` headers; `Public-Lines`/`Private-Lines` are followed by
    // that many lines of base64.
    let mut fields: HashMap<&str, &str> = HashMap::new();
    let mut public = Vec::new();
    let mut private = Zeroizing::new(Vec::new());
    while let Some(line) = lines.next() {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(": ").ok_or_else(|| invalid("malformed line"))?;
        match name {
            "Public-Lines" | "Private-Lines" => {
                let n: usize = value.parse().map_err(|_| invalid("bad line count"))?;
                let mut b64 = Zeroizing::new(String::new());
                for _ in 0..n {
                    b64.push_str(lines.next().ok_or_else(|| invalid("file is cut short"))?);
                }
                let bytes = B64.decode(b64.as_bytes()).map_err(|_| invalid("bad base64"))?;
                if name == "Public-Lines" {
                    public = bytes;
                } else {
                    *private = bytes;
                }
            }
            _ => {
                fields.insert(name, value);
            }
        }
    }
    let encryption = *fields.get("Encryption").ok_or_else(|| invalid("no Encryption line"))?;
    if encryption != "none" {
        return Err(PpkError::Encrypted);
    }
    let comment = fields.get("Comment").copied().unwrap_or_default();
    let mac = fields.get("Private-MAC").ok_or_else(|| invalid("no Private-MAC line"))?;
    let mac = hex::decode(mac).map_err(|_| invalid("bad Private-MAC"))?;
    if public.is_empty() || private.is_empty() {
        return Err(invalid("missing key data"));
    }

    // The MAC covers the algorithm, encryption, comment and both halves.
    let mut covered = Zeroizing::new(Vec::new());
    for field in [alg.as_bytes(), encryption.as_bytes(), comment.as_bytes(), &public, &private] {
        put_string(&mut covered, field);
    }
    let ok = match version {
        // Format 2: HMAC-SHA-1 keyed with SHA-1 of a fixed string (and the
        // passphrase, which is empty here).
        2 => {
            let key = Sha1::digest(b"putty-private-key-file-mac-key");
            let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(&key).expect("any key length");
            m.update(&covered);
            m.verify_slice(&mac).is_ok()
        }
        // Format 3: HMAC-SHA-256; the key comes from the passphrase's
        // Argon2 output, so it's empty for an unencrypted file.
        _ => {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&[]).expect("any key length");
            m.update(&covered);
            m.verify_slice(&mac).is_ok()
        }
    };
    if !ok {
        return Err(invalid("the file's MAC doesn't match (corrupted or edited)"));
    }

    let openssh = to_openssh_keypair(alg, &public, &private)?;
    let keypair = KeypairData::decode(&mut &openssh[..]).map_err(|e| invalid(format!("bad key: {e}")))?;
    let key = PrivateKey::new(keypair, comment).map_err(|e| invalid(format!("bad key: {e}")))?;

    let mut derived = Vec::new();
    key.public_key().key_data().encode(&mut derived).map_err(|e| invalid(format!("bad key: {e}")))?;
    if derived != public {
        return Err(invalid("the private key doesn't match the public key in the file"));
    }
    Ok(key)
}

/// Lay the key out as OpenSSH's private key format does (the algorithm,
/// then its public and private fields in OpenSSH's order). PPK fields are
/// SSH strings and mpints already, so they're copied as they are.
fn to_openssh_keypair(alg: &str, public: &[u8], private: &[u8]) -> Result<Zeroizing<Vec<u8>>, PpkError> {
    let mut pubr = public;
    let mut privr = private;
    let mut next_pub = || take_string(&mut pubr);
    if next_pub()? != alg.as_bytes() {
        return Err(invalid("the public key's algorithm doesn't match the file's"));
    }
    let mut out = Zeroizing::new(Vec::new());
    put_string(&mut out, alg.as_bytes());
    match alg {
        "ssh-ed25519" => {
            let pk = next_pub()?;
            let sk = take_string(&mut privr)?;
            if sk.len() != 32 || pk.len() != 32 {
                return Err(invalid("bad Ed25519 key length"));
            }
            put_string(&mut out, pk);
            let mut both = Zeroizing::new(sk.to_vec());
            both.extend_from_slice(pk);
            put_string(&mut out, &both);
        }
        "ssh-rsa" => {
            let (e, n) = (next_pub()?, next_pub()?);
            let (d, p, q, iqmp) =
                (take_string(&mut privr)?, take_string(&mut privr)?, take_string(&mut privr)?, take_string(&mut privr)?);
            for field in [n, e, d, iqmp, p, q] {
                put_string(&mut out, field);
            }
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let (curve, point) = (next_pub()?, next_pub()?);
            let d = take_string(&mut privr)?;
            let d = ecdsa_scalar(curve, d).ok_or_else(|| invalid("bad ECDSA private key"))?;
            for field in [curve, point, &d] {
                put_string(&mut out, field);
            }
        }
        other => return Err(invalid(format!("{other} keys are not supported"))),
    }
    Ok(out)
}

/// An ECDSA private scalar (an SSH mpint: big-endian, as short as it can
/// be, with a leading zero byte when the top bit is set) at its curve's
/// full size, the only form `ssh-key` reads. `None` for an unknown curve or
/// a number too big for it.
pub(crate) fn ecdsa_scalar(curve: &[u8], d: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let size = match curve {
        b"nistp256" => 32,
        b"nistp384" => 48,
        b"nistp521" => 66,
        _ => return None,
    };
    let start = d.iter().position(|b| *b != 0).unwrap_or(d.len());
    let digits = &d[start..];
    if digits.len() > size {
        return None;
    }
    let mut out = Zeroizing::new(vec![0u8; size - digits.len()]);
    out.extend_from_slice(digits);
    Some(out)
}

fn take_string<'a>(r: &mut &'a [u8]) -> Result<&'a [u8], PpkError> {
    let short = || invalid("key data is cut short");
    let len = r.get(..4).ok_or_else(short)?;
    let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
    let s = r.get(4..4 + len).ok_or_else(short)?;
    *r = &r[4 + len..];
    Ok(s)
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}
