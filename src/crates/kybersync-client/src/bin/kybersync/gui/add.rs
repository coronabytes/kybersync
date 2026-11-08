//! Adding a vault to this device: create a new one (on a server or in an S3
//! bucket), join an existing one, or enroll from a recovery kit.

use super::util;
use super::{Busy, Gui};
use crate::jobs::Job;
use kybersync_client::api::Target;
use kybersync_client::config::S3Settings;
use kybersync_client::fs::free_drives;
use kybersync_client::setup::{self, KitBucket};
use kybersync_core::crypto;
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Create,
    Join,
    Recover,
}

/// Where the vault lives.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    #[default]
    Server,
    /// Serverless: an S3 bucket every device uses directly.
    S3,
}

/// Which S3 service a serverless vault uses.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Provider {
    #[default]
    Aws,
    /// The AWS European Sovereign Cloud (`aws-eusc` partition, `amazonaws.eu`).
    AwsSovereign,
    /// Cloudflare R2, MinIO, SeaweedFS and the like, at an endpoint URL.
    Compatible,
}

/// AWS commercial regions, Europe first.
const AWS_REGIONS: &[(&str, &str)] = &[
    ("eu-central-1", "Europe (Frankfurt)"),
    ("eu-central-2", "Europe (Zurich)"),
    ("eu-west-1", "Europe (Ireland)"),
    ("eu-west-2", "Europe (London)"),
    ("eu-west-3", "Europe (Paris)"),
    ("eu-north-1", "Europe (Stockholm)"),
    ("eu-south-1", "Europe (Milan)"),
    ("eu-south-2", "Europe (Spain)"),
    ("us-east-1", "US East (N. Virginia)"),
    ("us-east-2", "US East (Ohio)"),
    ("us-west-1", "US West (N. California)"),
    ("us-west-2", "US West (Oregon)"),
    ("ca-central-1", "Canada (Central)"),
    ("ca-west-1", "Canada West (Calgary)"),
    ("sa-east-1", "South America (São Paulo)"),
    ("mx-central-1", "Mexico (Central)"),
    ("ap-northeast-1", "Asia Pacific (Tokyo)"),
    ("ap-northeast-2", "Asia Pacific (Seoul)"),
    ("ap-northeast-3", "Asia Pacific (Osaka)"),
    ("ap-southeast-1", "Asia Pacific (Singapore)"),
    ("ap-southeast-2", "Asia Pacific (Sydney)"),
    ("ap-southeast-3", "Asia Pacific (Jakarta)"),
    ("ap-southeast-4", "Asia Pacific (Melbourne)"),
    ("ap-southeast-5", "Asia Pacific (Malaysia)"),
    ("ap-southeast-6", "Asia Pacific (New Zealand)"),
    ("ap-southeast-7", "Asia Pacific (Thailand)"),
    ("ap-south-1", "Asia Pacific (Mumbai)"),
    ("ap-south-2", "Asia Pacific (Hyderabad)"),
    ("ap-east-1", "Asia Pacific (Hong Kong)"),
    ("ap-east-2", "Asia Pacific (Taipei)"),
    ("me-central-1", "Middle East (UAE)"),
    ("me-south-1", "Middle East (Bahrain)"),
    ("il-central-1", "Israel (Tel Aviv)"),
    ("af-south-1", "Africa (Cape Town)"),
];

/// Regions of the AWS European Sovereign Cloud.
const SOVEREIGN_REGIONS: &[(&str, &str)] = &[("eusc-de-east-1", "Germany (Brandenburg)")];

impl Provider {
    fn label(self) -> &'static str {
        match self {
            Provider::Aws => "Amazon S3 (AWS)",
            Provider::AwsSovereign => "Amazon S3, AWS European Sovereign Cloud",
            Provider::Compatible => "Other S3-compatible service (R2, MinIO, …)",
        }
    }

    /// The regions to choose from, or `None` for a free-form region.
    fn regions(self) -> Option<&'static [(&'static str, &'static str)]> {
        match self {
            Provider::Aws => Some(AWS_REGIONS),
            Provider::AwsSovereign => Some(SOVEREIGN_REGIONS),
            Provider::Compatible => None,
        }
    }

    /// Which provider stored settings belong to.
    fn of(endpoint: &str, region: &str) -> Self {
        if !endpoint.is_empty() {
            Provider::Compatible
        } else if region.starts_with("eusc-") {
            Provider::AwsSovereign
        } else {
            Provider::Aws
        }
    }
}

/// What a loaded recovery kit says: server (or bucket description), vault, bucket.
type KitSummary = (String, String, Option<KitBucket>);

pub struct State {
    pub mode: Mode,
    pub error: Option<String>,
    // shared
    kind: Kind,
    server: String,
    s3_provider: Provider,
    s3_endpoint: String,
    s3_region: String,
    s3_path_style: bool,
    s3_bucket: String,
    s3_key_id: String,
    s3_secret: String,
    vault: String,
    name: String,
    // create
    admin_token: String,
    drive: String,
    kit_path: String,
    password: String,
    password2: String,
    // join
    code: String,
    /// Where a pasted invite lands; it is parsed and emptied right away.
    invite_paste: String,
    /// What the last imported invite said, shown under the fields.
    invite_note: Option<Result<String, String>>,
    // recover
    rkit_path: String,
    rkit: Option<Result<KitSummary, String>>,
    rpassword: String,
}

impl Default for State {
    fn default() -> Self {
        State {
            mode: Mode::Create,
            error: None,
            kind: Kind::Server,
            server: String::new(),
            s3_provider: Provider::Aws,
            s3_endpoint: String::new(),
            s3_region: "eu-central-1".into(),
            s3_path_style: false,
            s3_bucket: String::new(),
            s3_key_id: String::new(),
            s3_secret: String::new(),
            vault: String::new(),
            name: setup::default_device_name(),
            admin_token: String::new(),
            drive: String::new(),
            kit_path: String::new(),
            password: String::new(),
            password2: String::new(),
            code: String::new(),
            invite_paste: String::new(),
            invite_note: None,
            rkit_path: String::new(),
            rkit: None,
            rpassword: String::new(),
        }
    }
}

/// A finished add operation.
pub enum Done {
    Created { vault: String, fingerprint: String, kit: PathBuf, device: String },
    Joined { vault: String },
    Recovered { vault: String, name: String },
}

impl Done {
    pub fn vault(&self) -> &str {
        match self {
            Done::Created { vault, .. } | Done::Joined { vault } | Done::Recovered { vault, .. } => vault,
        }
    }

    pub fn message(&self) -> (&'static str, String) {
        match self {
            Done::Created { vault, fingerprint, kit, device } => (
                "Vault created",
                format!(
                    "'{vault}' is ready and mounts now.\n\nRecovery kit: {}\nKeep it somewhere safe and offline, together with its password: it is the only way back in if every device is lost.\n\nVault fingerprint: {fingerprint}\nThis device: {device}",
                    kit.display()
                ),
            ),
            Done::Joined { vault } => (
                "Join request sent",
                format!("Approve this device on one that already has '{vault}'. The fingerprint to compare is on the vault's page; kybersync waits for the approval in the background."),
            ),
            Done::Recovered { vault, name } => ("Device enrolled", format!("'{name}' now has the vault '{vault}' and mounts now.")),
        }
    }
}

impl State {
    /// Clear the secrets of a finished flow.
    pub fn finished(&mut self, _done: &Done) {
        self.admin_token.clear();
        self.s3_secret.clear();
        self.password.clear();
        self.password2.clear();
        self.rpassword.clear();
        self.code.clear();
        self.invite_note = None;
        self.error = None;
    }

    /// The server URL or bucket the form describes.
    fn target(&self) -> anyhow::Result<Target> {
        Ok(match self.kind {
            Kind::Server => Target::Server(self.server.trim().to_string()),
            Kind::S3 => Target::S3(S3Settings::new(
                self.s3_endpoint_value(),
                &self.s3_region,
                &self.s3_bucket,
                self.s3_path_style_value(),
                &self.s3_key_id,
                &self.s3_secret,
            )?),
        })
    }

    /// The storage fields are filled in.
    fn location_ready(&self) -> bool {
        match self.kind {
            Kind::Server => !self.server.trim().is_empty(),
            Kind::S3 => {
                (self.s3_provider != Provider::Compatible || !self.s3_endpoint.trim().is_empty())
                    && !self.s3_region.trim().is_empty()
                    && !self.s3_bucket.trim().is_empty()
                    && !self.s3_key_id.trim().is_empty()
                    && !self.s3_secret.is_empty()
            }
        }
    }

    /// Rows of a two-column grid: the server/bucket choice and its fields.
    /// `fixed` hides the choice (a recovery kit already says which it is).
    fn location_rows(&mut self, ui: &mut egui::Ui, fixed: bool) {
        if !fixed {
            ui.label("Stored on");
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.kind, Kind::Server, "kybersync server");
                ui.radio_value(&mut self.kind, Kind::S3, "S3 bucket (serverless)");
            });
            ui.end_row();
        }
        match self.kind {
            Kind::Server => {
                ui.label("Server URL");
                util::text(ui, &mut self.server);
                ui.end_row();
            }
            Kind::S3 => self.s3_rows(ui),
        }
    }

    fn s3_rows(&mut self, ui: &mut egui::Ui) {
        ui.label("Provider");
        let before = self.s3_provider;
        egui::ComboBox::from_id_salt("s3-provider")
            .width(util::FIELD_WIDTH - 20.0)
            .selected_text(self.s3_provider.label())
            .show_ui(ui, |ui| {
                for p in [Provider::Aws, Provider::AwsSovereign, Provider::Compatible] {
                    ui.selectable_value(&mut self.s3_provider, p, p.label());
                }
            });
        ui.end_row();
        if self.s3_provider != before {
            self.provider_changed();
        }

        if self.s3_provider == Provider::Compatible {
            ui.label("Endpoint");
            ui.add(
                egui::TextEdit::singleline(&mut self.s3_endpoint)
                    .hint_text("https://<account>.r2.cloudflarestorage.com")
                    .desired_width(util::FIELD_WIDTH)
                    .margin(egui::Margin::symmetric(10, 6)),
            );
            ui.end_row();
        }

        ui.label("Region");
        match self.s3_provider.regions() {
            Some(regions) => {
                let shown = regions
                    .iter()
                    .find(|(id, _)| *id == self.s3_region)
                    .map_or_else(|| self.s3_region.clone(), |(id, name)| format!("{id}  ·  {name}"));
                egui::ComboBox::from_id_salt("s3-region").width(util::FIELD_WIDTH - 20.0).selected_text(shown).show_ui(ui, |ui| {
                    for (id, name) in regions {
                        ui.selectable_value(&mut self.s3_region, id.to_string(), format!("{id}  ·  {name}"));
                    }
                });
            }
            None => {
                ui.add(
                    egui::TextEdit::singleline(&mut self.s3_region)
                        .hint_text("auto (R2), us-east-1 (MinIO, SeaweedFS)")
                        .desired_width(util::FIELD_WIDTH)
                        .margin(egui::Margin::symmetric(10, 6)),
                );
            }
        }
        ui.end_row();

        ui.label("Bucket");
        util::text(ui, &mut self.s3_bucket);
        ui.end_row();

        if self.s3_provider == Provider::Compatible {
            ui.label("Addressing");
            ui.checkbox(&mut self.s3_path_style, "Path-style requests (endpoint/bucket/key)");
            ui.end_row();
        }

        ui.label("Requests go to");
        let bucket = if self.s3_bucket.trim().is_empty() { "bucket" } else { self.s3_bucket.trim() };
        match kybersync_client::s3sdk::resolved_endpoint(
            self.s3_endpoint_value(),
            self.s3_region.trim(),
            bucket,
            self.s3_path_style_value(),
        ) {
            Ok(url) => ui.label(egui::RichText::new(url).monospace()),
            Err(e) => ui.colored_label(util::color(crate::icon::Light::Offline), e),
        };
        ui.end_row();

        ui.label("Access key ID");
        util::text(ui, &mut self.s3_key_id);
        ui.end_row();
        ui.label("Secret access key");
        util::password(ui, &mut self.s3_secret);
        ui.end_row();
        ui.label("");
        util::field_hint(
            ui,
            match self.s3_provider {
                Provider::AwsSovereign => {
                    "The AWS European Sovereign Cloud is a separate AWS partition: its keys and bucket come from your \
                     eusc account, and IAM policies there use arn:aws-eusc:s3:::… ARNs."
                }
                Provider::Aws => "Every device of the vault uses these keys; give them access to this bucket only.",
                Provider::Compatible => {
                    "The service must support conditional writes (If-None-Match and If-Match), as Cloudflare R2, \
                     MinIO and SeaweedFS do. Most need path-style requests."
                }
            },
        );
        ui.end_row();
    }

    /// The endpoint to configure: AWS's own are found by the SDK from the region.
    fn s3_endpoint_value(&self) -> &str {
        match self.s3_provider {
            Provider::Compatible => self.s3_endpoint.trim(),
            Provider::Aws | Provider::AwsSovereign => "",
        }
    }

    /// AWS always gets virtual-hosted requests; path-style is only for other services.
    fn s3_path_style_value(&self) -> bool {
        self.s3_provider == Provider::Compatible && self.s3_path_style
    }

    /// Sensible defaults for a newly picked provider.
    fn provider_changed(&mut self) {
        if let Some(regions) = self.s3_provider.regions()
            && !regions.iter().any(|(id, _)| *id == self.s3_region)
        {
            self.s3_region = regions[0].0.to_string();
        }
        if self.s3_provider == Provider::Compatible && self.s3_region.starts_with("eusc-") {
            self.s3_region.clear();
        }
        // AWS prefers virtual-hosted requests; most other services need path-style.
        self.s3_path_style = self.s3_provider == Provider::Compatible;
    }

    /// Fill the bucket fields from a recovery kit.
    fn take_kit_bucket(&mut self, b: &KitBucket) {
        self.kind = Kind::S3;
        self.s3_provider = Provider::of(&b.endpoint, &b.region);
        self.s3_endpoint = b.endpoint.clone();
        self.s3_region = b.region.clone();
        self.s3_bucket = b.bucket.clone();
        self.s3_path_style = b.path_style;
    }

    /// Fill the join form from an invite (a file or pasted text).
    fn take_invite(&mut self, parsed: anyhow::Result<setup::InviteFile>) {
        self.invite_note = Some(match parsed {
            Ok(inv) => {
                self.kind = Kind::Server;
                self.server = inv.server.clone();
                self.vault = inv.vault.clone();
                self.code = inv.code.clone();
                if inv.expired() {
                    Err(format!("The invite for '{}' has expired; ask for a new one.", inv.vault))
                } else {
                    Ok(format!("Invite for '{}' on {} loaded. Check the device name and send the request.", inv.vault, inv.server))
                }
            }
            Err(e) => Err(format!("{e:#}")),
        });
    }
}

impl Gui<'_> {
    pub(super) fn add_page(&mut self, ui: &mut egui::Ui) {
        util::page_title(
            ui,
            "Add a vault",
            Some("Create a vault on a server or in an S3 bucket, join an existing one, or recover one from a kit."),
        );
        ui.add_space(14.0);
        util::tabs(
            ui,
            &mut self.add.mode,
            &[(Mode::Create, "Create a new vault"), (Mode::Join, "Join an existing vault"), (Mode::Recover, "Recover from a kit")],
        );
        match self.add.mode {
            Mode::Create => self.create_form(ui),
            Mode::Join => self.join_form(ui),
            Mode::Recover => self.recover_form(ui),
        }
        if let Some(e) = &self.add.error {
            ui.add_space(8.0);
            util::error(ui, e);
        }
    }

    fn create_form(&mut self, ui: &mut egui::Ui) {
        let a = &mut self.add;
        ui.label("This device becomes the vault's first member and writes the recovery kit.");
        util::section(ui, "Storage", |ui| {
            egui::Grid::new("create-server").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                a.location_rows(ui, false);
                ui.label("Vault name");
                if util::text(ui, &mut a.vault).changed() && a.kit_path.is_empty() | a.kit_path.contains("-recovery-kit") {
                    a.kit_path = util::default_kit_path(a.vault.trim(), None).display().to_string();
                }
                ui.end_row();
                ui.label("");
                util::field_hint(ui, "1-64 characters: a-z, 0-9, '-' or '_'. Vault names are visible to the server or bucket.");
                ui.end_row();
                if a.kind == Kind::Server {
                    ui.label("Admin token");
                    util::password(ui, &mut a.admin_token);
                    ui.end_row();
                    ui.label("");
                    util::field_hint(ui, "The server's KYBERSYNC_ADMIN_TOKEN; only creating a vault needs it.");
                    ui.end_row();
                }
            });
            if a.kind == Kind::S3 {
                util::hint(
                    ui,
                    "Without a server, anyone with these keys can delete the vault's data (not read it). \
                     Removing a device later also means changing the bucket's keys on the devices that stay.",
                );
            }
        });
        util::section(ui, "This device", |ui| {
            egui::Grid::new("create-device").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                ui.label("Device name");
                util::text(ui, &mut a.name);
                ui.end_row();
                ui.label("Drive letter");
                drive_combo(ui, "create-drive", &mut a.drive);
                ui.end_row();
            });
        });
        util::section(ui, "Recovery kit", |ui| {
            ui.label("The kit plus its password can restore access if all devices are lost. The password cannot be reset.");
            egui::Grid::new("create-kit").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                ui.label("Kit file");
                util::path_field(ui, &mut a.kit_path, util::pick_kit_to_save);
                ui.end_row();
                ui.label("Password");
                util::password(ui, &mut a.password);
                ui.end_row();
                ui.label("Repeat");
                util::password(ui, &mut a.password2);
                ui.end_row();
            });
            if let Some(p) = util::password_problem(&a.password, &a.password2)
                && !a.password.is_empty()
            {
                util::hint(ui, p);
            }
        });
        ui.add_space(10.0);
        let ready = a.location_ready()
            && !a.vault.trim().is_empty()
            && (a.kind == Kind::S3 || !a.admin_token.is_empty())
            && !a.name.trim().is_empty()
            && !a.kit_path.trim().is_empty()
            && util::password_problem(&a.password, &a.password2).is_none();
        if ui.add_enabled_ui(ready, |ui| util::primary_button(ui, "Create vault")).inner.clicked() {
            a.error = None;
            let target = match a.target() {
                Ok(t) => t,
                Err(e) => {
                    a.error = Some(format!("{e:#}"));
                    return;
                }
            };
            let (vault, token, name, pw, kit, drive) = (
                a.vault.trim().to_string(),
                a.admin_token.clone(),
                a.name.trim().to_string(),
                a.password.clone(),
                PathBuf::from(a.kit_path.trim()),
                a.drive.clone(),
            );
            self.busy = Some(Busy::Add(Job::spawn(self.core.rt.handle(), async move {
                let out = setup::init(&target, &vault, &token, &name, &pw, &kit).await?;
                if !drive.is_empty() {
                    let mut cfg = kybersync_client::config::Config::load()?;
                    if let Some(p) = cfg.vaults.iter_mut().find(|p| p.vault == vault) {
                        p.mount_point = drive;
                    }
                    cfg.save()?;
                }
                Ok(Done::Created {
                    vault,
                    fingerprint: out.vault_fingerprint,
                    kit,
                    device: format!("{} ({})", out.profile.device_name, crypto::fingerprint(&out.profile.device_id)),
                })
            })));
        }
    }

    fn join_form(&mut self, ui: &mut egui::Ui) {
        let a = &mut self.add;
        ui.horizontal(|ui| {
            ui.radio_value(&mut a.kind, Kind::Server, "Vault on a kybersync server");
            ui.radio_value(&mut a.kind, Kind::S3, "Serverless vault (S3 bucket)");
        });
        ui.add_space(6.0);
        if a.kind == Kind::S3 {
            ui.label("Enter the same bucket and keys the vault's other devices use. Then approve this device on one of them after comparing fingerprints.");
        } else {
            ui.label("On a device that already has the vault, open its Devices tab and choose \"Invite a device\". It gives you an invite file (or text to paste) that is valid for an hour.");
        }
        if a.kind == Kind::Server {
            util::section(ui, "Invite", |ui| {
                ui.horizontal(|ui| {
                    if util::primary_button(ui, "Open invite file…").clicked()
                        && let Some(path) = util::pick_invite_to_open()
                    {
                        a.take_invite(setup::InviteFile::read(&path));
                    }
                    ui.label("or paste it:");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut a.invite_paste)
                            .hint_text("paste the copied invite here")
                            .desired_width(util::FIELD_WIDTH - 60.0)
                            .margin(egui::Margin::symmetric(10, 6)),
                    );
                    if r.changed() && a.invite_paste.trim_start().starts_with('{') {
                        let text = std::mem::take(&mut a.invite_paste);
                        a.take_invite(setup::InviteFile::parse(&text));
                    }
                });
                match &a.invite_note {
                    Some(Ok(s)) => {
                        ui.colored_label(util::color(crate::icon::Light::Ok), s);
                    }
                    Some(Err(s)) => util::error(ui, s),
                    None => util::hint(ui, "Without an invite file, type the server, vault and code in below."),
                }
            });
        }
        util::section(ui, "Vault", |ui| {
            egui::Grid::new("join").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                a.location_rows(ui, true);
                ui.label("Vault name");
                util::text(ui, &mut a.vault);
                ui.end_row();
                if a.kind == Kind::Server {
                    ui.label("Invite code");
                    ui.add(egui::TextEdit::singleline(&mut a.code).hint_text("ABCD-EFGH").desired_width(160.0));
                    ui.end_row();
                }
                ui.label("Device name");
                util::text(ui, &mut a.name);
                ui.end_row();
            });
        });
        ui.add_space(10.0);
        let ready = a.location_ready()
            && !a.vault.trim().is_empty()
            && (a.kind == Kind::S3 || !a.code.trim().is_empty())
            && !a.name.trim().is_empty();
        if ui.add_enabled_ui(ready, |ui| util::primary_button(ui, "Request to join")).inner.clicked() {
            a.error = None;
            let target = match a.target() {
                Ok(t) => t,
                Err(e) => {
                    a.error = Some(format!("{e:#}"));
                    return;
                }
            };
            // A serverless vault takes no invite code.
            let code = (a.kind == Kind::Server).then(|| a.code.trim().to_string());
            let (vault, name) = (a.vault.trim().to_string(), a.name.trim().to_string());
            self.busy = Some(Busy::Add(Job::spawn(self.core.rt.handle(), async move {
                setup::join_request(&target, &vault, &name, code.as_deref()).await?;
                Ok(Done::Joined { vault })
            })));
        }
    }

    fn recover_form(&mut self, ui: &mut egui::Ui) {
        let a = &mut self.add;
        ui.label("Enroll this device with the recovery kit and its password. It becomes an authorized device of the vault.");
        util::section(ui, "Recovery kit", |ui| {
            egui::Grid::new("recover").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                ui.label("Kit file");
                let before = a.rkit_path.clone();
                util::path_field(ui, &mut a.rkit_path, |_| util::pick_kit_to_open());
                if a.rkit_path != before {
                    a.rkit = None;
                }
                ui.end_row();
                if a.rkit.is_none() && !a.rkit_path.trim().is_empty() {
                    a.rkit = Some(
                        setup::read_kit(&PathBuf::from(a.rkit_path.trim()))
                            .map(|k| (k.server, k.vault, k.s3))
                            .map_err(|e| format!("{e:#}")),
                    );
                    // A serverless kit names its bucket; only the keys are missing.
                    if let Some(Ok((_, _, Some(b)))) = &a.rkit {
                        let b = b.clone();
                        a.take_kit_bucket(&b);
                    } else {
                        a.kind = Kind::Server;
                    }
                }
                match &a.rkit {
                    Some(Ok((server, vault, _))) => {
                        ui.label("Vault");
                        ui.label(format!("'{vault}' on {server}"));
                        ui.end_row();
                    }
                    Some(Err(e)) => {
                        ui.label("");
                        util::field_error(ui, e);
                        ui.end_row();
                    }
                    None => {}
                }
                ui.label("Password");
                util::password(ui, &mut a.rpassword);
                ui.end_row();
                if a.kind == Kind::S3 {
                    a.location_rows(ui, true);
                } else {
                    ui.label("Server URL");
                    util::text(ui, &mut a.server);
                    ui.end_row();
                    ui.label("");
                    util::field_hint(ui, "Leave empty to use the server stored in the kit.");
                    ui.end_row();
                }
                ui.label("Device name");
                util::text(ui, &mut a.name);
                ui.end_row();
            });
        });
        ui.add_space(10.0);
        let ready = matches!(a.rkit, Some(Ok(_)))
            && !a.rpassword.is_empty()
            && !a.name.trim().is_empty()
            && (a.kind == Kind::Server || a.location_ready());
        if ui.add_enabled_ui(ready, |ui| util::primary_button(ui, "Recover")).inner.clicked() {
            a.error = None;
            // A server kit uses the server it names unless another is given.
            let target = match a.kind {
                Kind::Server if a.server.trim().is_empty() => None,
                _ => match a.target() {
                    Ok(t) => Some(t),
                    Err(e) => {
                        a.error = Some(format!("{e:#}"));
                        return;
                    }
                },
            };
            let (kit, pw, name) = (PathBuf::from(a.rkit_path.trim()), a.rpassword.clone(), a.name.trim().to_string());
            self.busy = Some(Busy::Add(Job::spawn(self.core.rt.handle(), async move {
                let kit = setup::read_kit(&kit)?;
                let p = setup::recover(&kit, &pw, target.as_ref(), &name).await?;
                Ok(Done::Recovered { vault: p.vault, name: p.device_name })
            })));
        }
    }
}

fn drive_combo(ui: &mut egui::Ui, id: &str, drive: &mut String) {
    let mut letters = free_drives();
    letters.sort();
    egui::ComboBox::from_id_salt(id)
        .selected_text(if drive.is_empty() { "Next free letter".to_string() } else { drive.clone() })
        .show_ui(ui, |ui| {
            ui.selectable_value(drive, String::new(), "Next free letter");
            for l in letters {
                ui.selectable_value(drive, l.clone(), l);
            }
        });
}
