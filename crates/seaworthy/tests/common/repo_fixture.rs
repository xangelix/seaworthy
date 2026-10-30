//! The signed two-product fixture `tests/repo.rs` and `tests/publish.rs`
//! publish: packaged by `seaworthy package` with throwaway keys, built
//! into repositories by `seaworthy repo`.

use std::path::{Path, PathBuf};

use seaworthy::codesign::Pins;
use seaworthy::config::Config;
use seaworthy::repo::{Listing, Options, Plan, Signers, Tools, read_listing};
use seaworthy::sign::BuildId;

use super::{Keyring, have, nfpm};

pub(crate) const CONFIG: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
release-keys = [{ algorithm = "ml-dsa-87", public-key = "release.pub" }]
openpgp-keys = ["pgp.asc"]
maintainer = "Acme Packaging <pkg@acme.test>"
license = "MIT"

[product.agent]
display-name = "Acme Agent"
description = "Collects things for Acme."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
windows-directory = "Agent"
sidecars.windows = ["extra_*.dll"]
outputs = ["deb", "rpm", "pacman", "tar", "zip"]
linux.depends.deb = ["libc6 (>= 2.36)"]
linux.depends.rpm = ["glibc >= 2.34"]
linux.depends.pacman = ["glibc"]

[product.agent.service]
name = "AcmeAgent"
account = "virtual"
arguments = ["service"]
state-directory = "acme/agent"

[product.agent.service.sandbox]
user = "acme-agent"

[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
windows-directory = "Console"
sidecars.windows = ["extra_*.dll"]
outputs = ["deb", "rpm", "pacman"]
"#;

/// Where [`Fixture::with_repository`]'s repository package points
/// machines.
pub(crate) const REPOSITORY_URL: &str = "https://packages.acme.test/repo";

/// [`CONFIG`] with `[defaults.repository]` at `url`: `package` builds the
/// repository package too, and `repo` publishes it.
pub(crate) fn config_with_repository(url: &str) -> String {
    format!("{CONFIG}\n[defaults.repository]\nurl = \"{url}\"\n")
}

/// [`CONFIG`] with no update helper (both products `updates.default =
/// "off"`) and no release manifests (no `release-signatures` or
/// `release-keys`): packaged without a manifest signer, published on
/// the packages' own signatures.
pub(crate) fn config_without_manifests() -> String {
    let text = CONFIG
        .replacen("release-signatures = [\"ml-dsa-87\"]\n", "", 1)
        .replacen(
            "release-keys = [{ algorithm = \"ml-dsa-87\", public-key = \"release.pub\" }]\n",
            "",
            1,
        )
        .replace(
            "helper = \"AcmeToolUpdate\"\n",
            "updates.default = \"off\"\n",
        );
    assert!(
        !text.contains("release-") && !text.contains("helper"),
        "{text}"
    );
    text
}

/// The index date every test uses: 2026-10-14 12:00:00 UTC.
pub(crate) const DATE: u64 = 1_791_979_200;

pub(crate) const TOKEN: &str = "2.1.0+cafe12";

/// Every tool the tests run; `None` (announced) when one is missing.
pub(crate) fn tools() -> Option<PathBuf> {
    let nfpm = nfpm()?;
    for (tool, probe) in [
        ("gpg", "--version"),
        ("gpgv", "--version"),
        ("rpmsign", "--version"),
        ("rpmkeys", "--version"),
        ("dpkg-scanpackages", "--version"),
        ("createrepo_c", "--version"),
        ("repo-add", "--version"),
        ("bsdtar", "--version"),
        ("gzip", "--version"),
    ] {
        if !have(tool, &[probe]) {
            return None;
        }
    }
    Some(nfpm)
}

/// Both products packaged and signed (manifests with a throwaway ML-DSA
/// key; rpm and pacman with a throwaway OpenPGP key when `openpgp`) under
/// `<dir>/dist`, at sequence 9; with [`Fixture::with_repository`], the
/// repository package too.
pub(crate) struct Fixture {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) keyring: Keyring,
    pub(crate) config: Config,
    pub(crate) nfpm: PathBuf,
    pub(crate) openpgp: bool,
}

impl Fixture {
    pub(crate) fn new(nfpm: &Path, openpgp: bool) -> Self {
        Self::with_config(nfpm, openpgp, CONFIG)
    }

    /// The fixture of [`config_without_manifests`]: signed packages (rpm,
    /// pacman), no release manifests.
    pub(crate) fn without_manifests(nfpm: &Path) -> Self {
        Self::with_config(nfpm, true, &config_without_manifests())
    }

    /// The fixture with `[defaults.repository]` (signed), pointing at
    /// [`REPOSITORY_URL`].
    pub(crate) fn with_repository(nfpm: &Path) -> Self {
        Self::with_repository_at(nfpm, REPOSITORY_URL)
    }

    /// The fixture with `[defaults.repository]` (signed), pointing at
    /// `url`.
    pub(crate) fn with_repository_at(nfpm: &Path, url: &str) -> Self {
        Self::with_config(nfpm, true, &config_with_repository(url))
    }

    pub(crate) fn with_config(nfpm: &Path, openpgp: bool, text: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::new();
        keyring.export(&dir.path().join("pgp.asc"));
        let release_key =
            seaworthy::sign::generate_key(seaworthy_updater::SignatureAlgorithm::MlDsa87).unwrap();
        let secret = dir.path().join("release.key");
        std::fs::write(&secret, format!("{}\n", *release_key.secret_hex)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(
            dir.path().join("release.pub"),
            hex::encode(&release_key.public_key),
        )
        .unwrap();
        std::fs::write(dir.path().join("seaworthy.toml"), text).unwrap();
        let config = Config::load(&dir.path().join("seaworthy.toml")).unwrap();
        let fixture = Self {
            dir,
            keyring,
            config,
            nfpm: nfpm.to_path_buf(),
            openpgp,
        };
        fixture.package_into("dist", 9);
        fixture
    }

    /// Both products packaged again, the same version token at
    /// `sequence`, under `<dir>/<name>` (a retried pipeline).
    pub(crate) fn package_into(&self, name: &str, sequence: u64) -> PathBuf {
        self.package_release(name, "2.1.0", sequence)
    }

    /// The ids `package` lists: both products, and `repository` with
    /// `[defaults.repository]`.
    pub(crate) fn ids(&self) -> Vec<&'static str> {
        let mut ids = vec!["agent", "console"];
        if self.config.defaults.repository.is_some() {
            ids.push(seaworthy::config::REPOSITORY_ID);
        }
        ids
    }

    /// Both products (and the repository package, with
    /// `[defaults.repository]`) packaged as `version` (build `cafe12`) at
    /// `sequence` under `<dir>/<name>`.
    pub(crate) fn package_release(&self, name: &str, version: &str, sequence: u64) -> PathBuf {
        let signing = self.signing();
        let out = self.path().join(name);
        let options = self.options(version, sequence);
        for id in ["agent", "console"] {
            let work = self.path().join(format!("work-{name}"));
            let layouts = super::layouts(&self.config, id, &work);
            seaworthy::package::package(&self.config, id, &layouts, &out, &options, &signing)
                .unwrap();
        }
        if self.config.defaults.repository.is_some() {
            seaworthy::package::repository(&self.config, &out, &options, &signing).unwrap();
        }
        out
    }

    /// The repository package as `config` describes it (2.1.0, sequence
    /// 9, the fixture's signers) under `<dir>/<name>/repository/`.
    pub(crate) fn package_repository(&self, config: &Config, name: &str) -> PathBuf {
        let out = self.path().join(name);
        seaworthy::package::repository(config, &out, &self.options("2.1.0", 9), &self.signing())
            .unwrap();
        out.join(seaworthy::config::REPOSITORY_ID)
    }

    /// The packaging options: `version` (build `cafe12`) at `sequence`.
    fn options(&self, version: &str, sequence: u64) -> seaworthy::package::Options {
        seaworthy::package::Options {
            release: seaworthy::version::Release::new(version, sequence).unwrap(),
            mtime: 1_700_000_000,
            nfpm: self.nfpm.clone(),
            wix: None,
            build: BuildId {
                metadata: "cafe12".into(),
            },
        }
    }

    /// The fixture's signers: the ML-DSA release key (when the config signs
    /// manifests), and the OpenPGP key when `openpgp`.
    fn signing(&self) -> seaworthy::package::Signing {
        let manifest: Vec<Box<dyn seaworthy::sign::ManifestSigner>> =
            if self.config.signs_manifests() {
                vec![Box::new(
                    seaworthy::sign::LocalKey::from_file(
                        seaworthy_updater::SignatureAlgorithm::MlDsa87,
                        &self.path().join("release.key"),
                    )
                    .unwrap(),
                )]
            } else {
                Vec::new()
            };
        seaworthy::package::Signing {
            manifest,
            openpgp: self.openpgp.then(|| {
                Box::new(self.keyring.signer()) as Box<dyn seaworthy::codesign::OpenPgpSigner>
            }),
            ..seaworthy::package::Signing::default()
        }
    }

    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Every listing [`ids`](Self::ids) names, read from `packages`
    /// (default `dist`).
    pub(crate) fn listings_in(&self, packages: &Path) -> Vec<Listing> {
        self.ids()
            .iter()
            .map(|id| read_listing(&packages.join(id)).unwrap())
            .collect()
    }

    pub(crate) fn listings(&self) -> Vec<Listing> {
        self.listings_in(&self.path().join("dist"))
    }

    pub(crate) fn pins(&self) -> Pins {
        Pins::of(&self.config)
    }

    /// A build at `date`, after `previous`.
    pub(crate) fn build_after(
        &self,
        listings: &[Listing],
        out: &Path,
        date: u64,
        previous: Option<&Plan>,
    ) -> Result<Plan, seaworthy::DistError> {
        let pins = self.pins();
        seaworthy::repo::build(
            &self.config,
            listings,
            out,
            &Tools::default(),
            &Signers {
                openpgp: &self.keyring.signer(),
                pins: &pins,
            },
            &Options {
                date,
                previous,
                allow_older: false,
            },
        )
    }

    pub(crate) fn build_with(
        &self,
        config: &Config,
        listings: &[Listing],
        out: &Path,
        signer: &dyn seaworthy::codesign::OpenPgpSigner,
    ) -> Result<Plan, seaworthy::DistError> {
        let pins = Pins::of(config);
        seaworthy::repo::build(
            config,
            listings,
            out,
            &Tools::default(),
            &Signers {
                openpgp: signer,
                pins: &pins,
            },
            &Options {
                date: DATE,
                previous: None,
                allow_older: false,
            },
        )
    }

    pub(crate) fn build(
        &self,
        listings: &[Listing],
        out: &Path,
    ) -> Result<Plan, seaworthy::DistError> {
        self.build_with(&self.config, listings, out, &self.keyring.signer())
    }

    /// A build with `tools` instead of the real ones.
    pub(crate) fn build_tools(
        &self,
        out: &Path,
        tools: Tools,
    ) -> Result<Plan, seaworthy::DistError> {
        let pins = self.pins();
        seaworthy::repo::build(
            &self.config,
            &self.listings(),
            out,
            &tools,
            &Signers {
                openpgp: &self.keyring.signer(),
                pins: &pins,
            },
            &Options {
                date: DATE,
                previous: None,
                allow_older: false,
            },
        )
    }
}
