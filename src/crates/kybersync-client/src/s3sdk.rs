//! An [`ObjectStore`] on top of the official AWS SDK for Rust (`aws-sdk-s3`),
//! so serverless vaults use the same storage layout code (`kybersync_store`)
//! as the server while talking to S3 through AWS's own client.
//!
//! Only what the layout needs is implemented: single-part puts (including
//! `If-None-Match: *` and `If-Match` conditional writes), whole-object gets,
//! heads, deletes and listings. Objects are at most a few MiB.
//!
//! The SDK resolves endpoints itself when none is given, including other AWS
//! partitions such as the European Sovereign Cloud (`eusc-de-east-1` →
//! `amazonaws.eu`). Addressing is path-style or virtual-hosted, as configured.

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::endpoint::{DefaultResolver, Params, ResolveEndpoint};
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::{ByteStream, DateTime as AwsDateTime};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::stream::BoxStream;
use futures::{FutureExt, StreamExt, TryStreamExt};
use object_store::path::Path;
use object_store::{
    CopyOptions, Error, GetOptions, GetResult, GetResultPayload, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMode, PutMultipartOptions, PutOptions, PutPayload, PutResult, Result,
};
use std::time::Duration;

const STORE: &str = "S3";

/// Connection settings, with the secret key in the clear (only in memory).
pub struct Connection<'a> {
    /// Empty: let the SDK pick AWS's endpoint for the region.
    pub endpoint: &'a str,
    pub region: &'a str,
    pub bucket: &'a str,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    /// `https://endpoint/bucket/key` instead of `https://bucket.endpoint/key`.
    pub path_style: bool,
}

#[derive(Debug)]
pub struct SdkStore {
    client: Client,
    bucket: String,
}

impl std::fmt::Display for SdkStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "S3(bucket={})", self.bucket)
    }
}

impl SdkStore {
    pub fn new(c: &Connection) -> Self {
        let credentials = Credentials::new(c.access_key_id, c.secret_access_key, None, None, "kybersync");
        let mut cfg = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(c.region.to_string()))
            .credentials_provider(credentials)
            .force_path_style(c.path_style)
            // Checksums only where S3 requires them: many S3-compatible
            // services reject the SDK's default extra checksum headers.
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(15))
                    .operation_attempt_timeout(Duration::from_secs(60))
                    .operation_timeout(Duration::from_secs(180))
                    .build(),
            );
        if !c.endpoint.is_empty() {
            cfg = cfg.endpoint_url(c.endpoint);
        }
        Self { client: Client::from_conf(cfg.build()), bucket: c.bucket.to_string() }
    }
}

/// The URL requests for `bucket` go to, as the SDK resolves it (shown in the
/// settings so the user can see where the vault will live).
pub fn resolved_endpoint(endpoint: &str, region: &str, bucket: &str, path_style: bool) -> Result<String, String> {
    let mut params = Params::builder().region(region.to_string()).bucket(bucket.to_string()).force_path_style(path_style);
    if !endpoint.is_empty() {
        params = params.endpoint(endpoint.to_string());
    }
    let params = params.build().map_err(|e| e.to_string())?;
    let resolved = DefaultResolver::new().resolve_endpoint(&params).now_or_never().ok_or("endpoint resolution is pending")?;
    resolved.map(|e| e.url().to_string()).map_err(|e| e.to_string())
}

/// HTTP status of a failed request, if the service answered.
fn status<E, R>(e: &SdkError<E, R>) -> Option<u16>
where
    R: HasStatus,
{
    match e {
        SdkError::ServiceError(se) => Some(se.raw().status_code()),
        SdkError::ResponseError(re) => Some(re.raw().status_code()),
        _ => None,
    }
}

trait HasStatus {
    fn status_code(&self) -> u16;
}

impl HasStatus for aws_sdk_s3::config::http::HttpResponse {
    fn status_code(&self) -> u16 {
        self.status().as_u16()
    }
}

/// Map an SDK error onto object_store's: 404 → `NotFound`, 412 →
/// `Precondition` (or `AlreadyExists` for a create), the rest → `Generic`.
fn convert<E>(e: SdkError<E, aws_sdk_s3::config::http::HttpResponse>, path: &Path, create: bool) -> Error
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    let path = path.to_string();
    let code = status(&e);
    let detail = match &e {
        SdkError::ServiceError(se) => {
            let err = se.err();
            format!("{} ({})", err.message().unwrap_or("no message"), err.code().unwrap_or("no code"))
        }
        other => format!("{}", aws_sdk_s3::error::DisplayErrorContext(other)),
    };
    let source: Box<dyn std::error::Error + Send + Sync> = format!("HTTP {code:?}: {detail}").into();
    match code {
        Some(404) => Error::NotFound { path, source },
        // 409 is S3's "conflicting conditional operation in progress": the
        // other writer wins, like a failed precondition.
        Some(412 | 409) if create => Error::AlreadyExists { path, source },
        Some(412 | 409) => Error::Precondition { path, source },
        Some(403) => Error::PermissionDenied { path, source },
        _ => Error::Generic { store: STORE, source },
    }
}

fn to_chrono(t: Option<&AwsDateTime>) -> DateTime<Utc> {
    t.and_then(|t| DateTime::from_timestamp(t.secs(), t.subsec_nanos())).unwrap_or_default()
}

#[async_trait]
impl ObjectStore for SdkStore {
    async fn put_opts(&self, location: &Path, payload: PutPayload, opts: PutOptions) -> Result<PutResult> {
        let body: Bytes = payload.into();
        let mut req = self.client.put_object().bucket(&self.bucket).key(location.as_ref()).body(ByteStream::from(body));
        let create = matches!(opts.mode, PutMode::Create);
        match opts.mode {
            PutMode::Overwrite => {}
            PutMode::Create => req = req.if_none_match("*"),
            PutMode::Update(v) => {
                let etag = v.e_tag.ok_or_else(|| Error::Generic { store: STORE, source: "update without an ETag".into() })?;
                req = req.if_match(etag);
            }
        }
        let out = req.send().await.map_err(|e| convert(e, location, create))?;
        Ok(PutResult { e_tag: out.e_tag, version: out.version_id, extensions: Default::default() })
    }

    async fn put_multipart_opts(&self, _: &Path, _: PutMultipartOptions) -> Result<Box<dyn MultipartUpload>> {
        Err(Error::NotImplemented { operation: "put_multipart".into(), implementer: STORE.into() })
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> Result<GetResult> {
        if options.range.is_some() {
            return Err(Error::NotImplemented { operation: "ranged get".into(), implementer: STORE.into() });
        }
        if options.head {
            let out = self
                .client
                .head_object()
                .bucket(&self.bucket)
                .key(location.as_ref())
                .send()
                .await
                .map_err(|e| convert(e, location, false))?;
            let size = out.content_length.unwrap_or(0).max(0) as u64;
            let meta = ObjectMeta {
                location: location.clone(),
                last_modified: to_chrono(out.last_modified.as_ref()),
                size,
                e_tag: out.e_tag,
                version: out.version_id,
            };
            return Ok(GetResult {
                payload: GetResultPayload::Stream(futures::stream::empty().boxed()),
                meta,
                range: 0..size,
                attributes: Default::default(),
                extensions: Default::default(),
            });
        }
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(location.as_ref())
            .send()
            .await
            .map_err(|e| convert(e, location, false))?;
        let meta_e_tag = out.e_tag.clone();
        let (last_modified, version) = (to_chrono(out.last_modified.as_ref()), out.version_id.clone());
        let data = out
            .body
            .collect()
            .await
            .map_err(|e| Error::Generic { store: STORE, source: Box::new(e) })?
            .into_bytes();
        let size = data.len() as u64;
        Ok(GetResult {
            payload: GetResultPayload::Stream(futures::stream::once(async move { Ok(data) }).boxed()),
            meta: ObjectMeta { location: location.clone(), last_modified, size, e_tag: meta_e_tag, version },
            range: 0..size,
            attributes: Default::default(),
            extensions: Default::default(),
        })
    }

    fn delete_stream(&self, locations: BoxStream<'static, Result<Path>>) -> BoxStream<'static, Result<Path>> {
        let (client, bucket) = (self.client.clone(), self.bucket.clone());
        locations
            .and_then(move |path| {
                let (client, bucket) = (client.clone(), bucket.clone());
                async move {
                    match client.delete_object().bucket(bucket).key(path.as_ref()).send().await {
                        Ok(_) => Ok(path),
                        Err(e) => match convert(e, &path, false) {
                            Error::NotFound { .. } => Ok(path),
                            other => Err(other),
                        },
                    }
                }
            })
            .boxed()
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, Result<ObjectMeta>> {
        self.list_pages(prefix, None)
    }

    fn list_with_offset(&self, prefix: Option<&Path>, offset: &Path) -> BoxStream<'static, Result<ObjectMeta>> {
        self.list_pages(prefix, Some(offset.to_string()))
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> Result<ListResult> {
        let mut out = ListResult { common_prefixes: vec![], objects: vec![], extensions: Default::default() };
        let mut token = None;
        loop {
            let page = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .set_prefix(dir_prefix(prefix))
                .delimiter("/")
                .set_continuation_token(token)
                .send()
                .await
                .map_err(|e| convert(e, &prefix.cloned().unwrap_or_default(), false))?;
            for p in page.common_prefixes() {
                if let Some(p) = p.prefix() {
                    out.common_prefixes.push(Path::from(p.trim_end_matches('/')));
                }
            }
            out.objects.extend(page.contents().iter().filter_map(object_meta));
            match page.next_continuation_token {
                Some(t) if page.is_truncated == Some(true) => token = Some(t),
                _ => return Ok(out),
            }
        }
    }

    async fn copy_opts(&self, _: &Path, _: &Path, _: CopyOptions) -> Result<()> {
        Err(Error::NotImplemented { operation: "copy".into(), implementer: STORE.into() })
    }
}

/// `prefix` as an S3 key prefix: path segments, so `a/b` matches `a/b/…` only.
fn dir_prefix(prefix: Option<&Path>) -> Option<String> {
    prefix.map(|p| p.to_string()).filter(|p| !p.is_empty()).map(|p| format!("{p}/"))
}

fn object_meta(o: &aws_sdk_s3::types::Object) -> Option<ObjectMeta> {
    Some(ObjectMeta {
        location: Path::from(o.key()?),
        last_modified: to_chrono(o.last_modified()),
        size: o.size().unwrap_or(0).max(0) as u64,
        e_tag: o.e_tag().map(str::to_string),
        version: None,
    })
}

impl SdkStore {
    /// All objects under `prefix` (after `start_after`), one ListObjectsV2 page at a time.
    fn list_pages(&self, prefix: Option<&Path>, start_after: Option<String>) -> BoxStream<'static, Result<ObjectMeta>> {
        let (client, bucket) = (self.client.clone(), self.bucket.clone());
        let key_prefix = dir_prefix(prefix);
        let err_path = prefix.cloned().unwrap_or_default();
        // State: the continuation token of the next page; None once done.
        futures::stream::unfold(Some(None::<String>), move |state| {
            let (client, bucket, key_prefix, start_after, err_path) =
                (client.clone(), bucket.clone(), key_prefix.clone(), start_after.clone(), err_path.clone());
            async move {
                let token = state?;
                let res = client
                    .list_objects_v2()
                    .bucket(bucket)
                    .set_prefix(key_prefix)
                    .set_start_after(if token.is_none() { start_after } else { None })
                    .set_continuation_token(token)
                    .send()
                    .await;
                match res {
                    Ok(page) => {
                        let items: Vec<Result<ObjectMeta>> = page.contents().iter().filter_map(object_meta).map(Ok).collect();
                        let next = match page.next_continuation_token {
                            Some(t) if page.is_truncated == Some(true) => Some(Some(t)),
                            _ => None,
                        };
                        Some((futures::stream::iter(items), next))
                    }
                    Err(e) => Some((futures::stream::iter(vec![Err(convert(e, &err_path, false))]), None)),
                }
            }
        })
        .flatten()
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sovereign_cloud_resolves_to_amazonaws_eu() {
        assert_eq!(
            resolved_endpoint("", "eusc-de-east-1", "my-vaults", false).unwrap(),
            "https://my-vaults.s3.eusc-de-east-1.amazonaws.eu"
        );
        assert_eq!(
            resolved_endpoint("", "eusc-de-east-1", "my-vaults", true).unwrap(),
            "https://s3.eusc-de-east-1.amazonaws.eu/my-vaults"
        );
    }

    #[test]
    fn aws_and_custom_endpoints_resolve() {
        assert_eq!(resolved_endpoint("", "eu-central-1", "my-vaults", false).unwrap(), "https://my-vaults.s3.eu-central-1.amazonaws.com");
        assert_eq!(
            resolved_endpoint("https://acc.r2.cloudflarestorage.com", "auto", "b", true).unwrap(),
            "https://acc.r2.cloudflarestorage.com/b"
        );
    }
}
