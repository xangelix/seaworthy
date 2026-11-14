//! First-paint probation, the app's side ([`FirstPaint`]), and the two small
//! formats the app and the update helper share: the helper's public
//! **notice** of the release on probation ([`Notice`],
//! `seaworthy-probation-notice:1`) and the app's **markers**
//! ([`Marker`], `seaworthy-first-paint:1`).
//!
//! A product with `updates.probation` puts every release its helper
//! installs on probation: the helper keeps the release it replaced and
//! publishes a notice naming the new one. The app, at start, reads the
//! release it runs (the installed release record beside its launcher,
//! [`crate::InstalledRelease`]) and the notice; only when the two agree is
//! it on probation. Then it leaves a `launched` marker and asks the helper
//! to run, and at its first paint a `painted` marker, asking again. The
//! helper counts the markers it finds for the pending release: a paint
//! commits the release; too many launches without one, or too long since
//! the first, put the previous release back.
//!
//! **What the app can decide:** keep or revert, nothing else. A marker
//! names a release only to be matched against the pending one; the helper
//! installs nothing but the release it kept, verified when it kept it.
//!
//! Where things are:
//!
//! | | Linux | Windows |
//! |---|---|---|
//! | The notice (helper-written, readable by everyone) | `/var/lib/<vendor>/<id>/probation`, root's, 0644 | `HKLM\SOFTWARE\<Vendor>\<Directory>\ProbationPending` (`REG_SZ`) |
//! | The markers (app-written, read and removed by the helper) | `/var/lib/<vendor>/<id>/first-paint/<uid>.<pid>.<16 hex>`: a drop box (root's, mode 1733: anyone may add a file, nobody may list it or remove another's), one file per marker, owned by its writer | `HKCU\Software\<Vendor>\<Directory>\FirstPaint`, one `REG_SZ` value per marker in the user's own hive; the helper reads the loaded hives under `HKEY_USERS` |
//!
//! Every function here is best effort for the app: it never panics, never
//! returns an error to the app, and blocks only for a few small file or
//! registry operations and the start of the helper's request.

use std::path::{Path, PathBuf};

use crate::Product;
use crate::release::{Release, Version};

#[cfg(not(windows))]
pub(crate) mod unix;
#[cfg(windows)]
pub(crate) mod windows;

/// A marker's first line.
pub const MARKER_TAG: &str = "seaworthy-first-paint:1";

/// The notice's first line.
pub const NOTICE_TAG: &str = "seaworthy-probation-notice:1";

/// The largest marker or notice a reader accepts.
pub const MAX_RECORD_BYTES: usize = 256;

/// Linux: the notice's file name in the probation directory
/// ([`Product::probation_directory`]).
pub const NOTICE_FILE: &str = "probation";

/// Linux: the drop box's name in the probation directory.
pub const DROP_BOX: &str = "first-paint";

/// Linux: the drop box's mode: anyone may add a file (`-wx` for group and
/// others), nobody may list it but root, and the sticky bit keeps each
/// file its owner's to remove or rename.
pub const DROP_BOX_MODE: u32 = 0o1733;

/// Windows: the notice's value under the product's install key
/// ([`Product::install_key`]).
pub const NOTICE_VALUE: &str = "ProbationPending";

/// Windows: the markers' key under `HKCU\<install key>` (and the helper's
/// view of it under each loaded `HKEY_USERS\<SID>`).
pub const MARKERS_KEY: &str = "FirstPaint";

/// What a marker says about one launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerState {
    /// The app started on the release (before its risky part: the browser
    /// engine, the GPU).
    Launched,
    /// The app's first window painted.
    Painted,
}

impl MarkerState {
    /// Its spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Launched => "launched",
            Self::Painted => "painted",
        }
    }
}

/// One marker: a launch, or a first paint, of a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// What happened.
    pub state: MarkerState,
    /// To which release.
    pub release: Release,
}

/// Why a marker or a notice was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a {what}: {why}")]
pub struct RecordError {
    what: &'static str,
    why: &'static str,
}

/// `<version> <sequence>`, the records' spelling of a release.
fn spell(release: &Release) -> String {
    format!("{} {}", release.version, release.sequence)
}

/// A release spelled `<version> <sequence>`, canonically: the version as it
/// displays, the sequence without a leading zero.
fn release_of(text: &str) -> Option<Release> {
    let (version, sequence) = text.split_once(' ')?;
    if sequence.is_empty()
        || (sequence.len() > 1 && sequence.starts_with('0'))
        || !sequence.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let parsed = Version::parse(version).ok()?;
    if parsed.to_string() != version {
        return None;
    }
    Release::new(version, sequence.parse().ok()?).ok()
}

/// A two-line record: `tag`, then `<key> <version> <sequence>`; returns
/// the key and the release.
fn parse_record(
    text: &str,
    tag: &str,
    what: &'static str,
) -> Result<(String, Release), RecordError> {
    let refuse = |why| RecordError { what, why };
    if text.len() > MAX_RECORD_BYTES {
        return Err(refuse("too large"));
    }
    let body = text
        .strip_prefix(tag)
        .and_then(|rest| rest.strip_prefix('\n'))
        .ok_or_else(|| refuse("another format"))?;
    let line = body
        .strip_suffix('\n')
        .filter(|line| !line.contains('\n'))
        .ok_or_else(|| refuse("not two lines"))?;
    let (key, rest) = line.split_once(' ').ok_or_else(|| refuse("no release"))?;
    let release = release_of(rest).ok_or_else(|| refuse("not a release"))?;
    Ok((key.to_owned(), release))
}

impl Marker {
    /// The marker's text: its tag, then `<state> <version> <sequence>`.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{MARKER_TAG}\n{} {}\n",
            self.state.as_str(),
            spell(&self.release)
        )
    }

    /// A marker from its text: exactly its own encoding.
    ///
    /// # Errors
    /// [`RecordError`]: too large, another tag, a state or release that
    /// isn't one, anything more or less.
    pub fn parse(text: &str) -> Result<Self, RecordError> {
        let (key, release) = parse_record(text, MARKER_TAG, "first-paint marker")?;
        let state = match key.as_str() {
            "launched" => MarkerState::Launched,
            "painted" => MarkerState::Painted,
            _ => {
                return Err(RecordError {
                    what: "first-paint marker",
                    why: "an unknown state",
                });
            }
        };
        Ok(Self { state, release })
    }
}

/// The helper's notice: the release on probation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// The release on probation.
    pub pending: Release,
}

impl Notice {
    /// The notice's text: its tag, then `pending <version> <sequence>`.
    #[must_use]
    pub fn encode(&self) -> String {
        format!("{NOTICE_TAG}\npending {}\n", spell(&self.pending))
    }

    /// A notice from its text: exactly its own encoding.
    ///
    /// # Errors
    /// [`RecordError`] for anything else.
    pub fn parse(text: &str) -> Result<Self, RecordError> {
        let (key, pending) = parse_record(text, NOTICE_TAG, "probation notice")?;
        if key != "pending" {
            return Err(RecordError {
                what: "probation notice",
                why: "no pending release",
            });
        }
        Ok(Self { pending })
    }
}

/// Where the app and the helper find a product's probation files: the
/// system's, or a test's.
#[derive(Debug, Clone)]
pub(crate) struct Locations {
    /// The install root: the installed release record's directory.
    pub(crate) install_root: Option<PathBuf>,
    /// Linux: the probation directory (`/var/lib/<vendor>/<id>`), holding the
    /// notice and the drop box.
    #[cfg_attr(windows, allow(dead_code, reason = "Linux's"))]
    pub(crate) public: PathBuf,
    /// Linux: the directory up to which the probation directory's parents
    /// must be root's and not writable by others (`/var`).
    #[cfg_attr(windows, allow(dead_code, reason = "Linux's"))]
    pub(crate) top: PathBuf,
    /// Whether files and directories must be root's (tests turn it off;
    /// modes and links are checked either way).
    #[cfg_attr(windows, allow(dead_code, reason = "Linux's"))]
    pub(crate) require_root: bool,
    /// Whether the app asks the helper to run (tests turn it off).
    pub(crate) request: bool,
}

impl Locations {
    /// The app's: its launcher's directory, the system's probation
    /// directory.
    pub(crate) fn for_app(product: &Product) -> Self {
        Self {
            install_root: std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_path_buf)),
            public: product.probation_directory(),
            top: PathBuf::from("/var"),
            require_root: true,
            request: true,
        }
    }
}

/// The installed release record in `install_root`, if it reads.
pub(crate) fn read_installed_release(install_root: &Path) -> Option<crate::InstalledRelease> {
    use std::io::Read as _;
    let path = install_root.join(crate::INSTALLED_RELEASE_FILE);
    let file = std::fs::File::open(&path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(seaworthy_formats::installed_release::MAX_INSTALLED_RELEASE_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .ok()?;
    crate::InstalledRelease::parse(&text).ok()
}

/// The app's side of first-paint probation: [`arm`](Self::arm) it when the
/// app starts, before its risky part (the browser engine, the GPU), and call
/// [`painted`](Self::painted) once, when its first window has painted:
///
/// ```no_run
/// # fn product() -> seaworthy_updater::Product { unimplemented!() }
/// # fn run_the_window(on_first_paint: impl FnOnce()) {}
/// let paint = seaworthy_updater::first_paint::FirstPaint::arm(&product());
/// run_the_window(move || paint.painted());
/// ```
///
/// Outside a probation (no product probation, another release pending, no
/// notice, no release record beside the launcher) both are no-ops. Neither
/// ever fails the app: what can't be written is logged (`tracing`) and
/// skipped, and the helper then simply sees no evidence, which never
/// reverts a release by itself before its launches or window run out.
#[derive(Debug)]
#[must_use = "call painted() at the first paint"]
pub struct FirstPaint {
    armed: Option<Armed>,
}

#[derive(Debug)]
struct Armed {
    product: Product,
    release: Release,
    at: Locations,
}

impl FirstPaint {
    /// At start: when this release is on probation, leaves a `launched`
    /// marker and asks the helper to run (see the type's docs).
    pub fn arm(product: &Product) -> Self {
        Self::arm_at(product, Locations::for_app(product))
    }

    pub(crate) fn arm_at(product: &Product, at: Locations) -> Self {
        if product.probation().is_none() {
            return Self { armed: None };
        }
        let Some(running) = at.install_root.as_deref().and_then(read_installed_release) else {
            tracing::debug!("first-paint probation: no installed release record beside the app");
            return Self { armed: None };
        };
        let pending = read_notice(product, &at);
        if pending.as_ref() != Some(&running.release) {
            return Self { armed: None };
        }
        let armed = Armed {
            product: product.clone(),
            release: running.release,
            at,
        };
        armed.mark(MarkerState::Launched);
        Self { armed: Some(armed) }
    }

    /// The release on probation this app runs, if it is on probation.
    #[must_use]
    pub fn on_probation(&self) -> Option<&Release> {
        self.armed.as_ref().map(|armed| &armed.release)
    }

    /// At the first paint: when this release is on probation, leaves a
    /// `painted` marker and asks the helper to run. Consumes the guard: a
    /// release paints once per launch.
    pub fn painted(self) {
        if let Some(armed) = &self.armed {
            armed.mark(MarkerState::Painted);
        }
    }
}

impl Armed {
    fn mark(&self, state: MarkerState) {
        let marker = Marker {
            state,
            release: self.release.clone(),
        };
        if let Err(why) = write_marker(&self.product, &self.at, &marker) {
            tracing::warn!(
                "first-paint probation: couldn't leave the {} marker: {}",
                state.as_str(),
                crate::log::line_safe(&why)
            );
            return;
        }
        if self.at.request
            && let Err(why) = crate::request_update(&self.product)
        {
            tracing::info!(
                "first-paint probation: couldn't ask the update helper to run: {}",
                crate::log::line_safe(&why.to_string())
            );
        }
    }
}

/// The release the helper's notice names, if a trusted, valid one exists.
fn read_notice(product: &Product, at: &Locations) -> Option<Release> {
    #[cfg(windows)]
    {
        let _ = at;
        let text = crate::policy::windows::read_install_value(&product.install_key(), NOTICE_VALUE)
            .ok()??;
        Notice::parse(&text).ok().map(|notice| notice.pending)
    }
    #[cfg(not(windows))]
    {
        let _ = product;
        unix::read_notice(at).map(|notice| notice.pending)
    }
}

fn write_marker(product: &Product, at: &Locations, marker: &Marker) -> Result<(), String> {
    #[cfg(windows)]
    {
        let _ = at;
        windows::write_marker(product, marker)
    }
    #[cfg(not(windows))]
    {
        let _ = product;
        unix::write_marker(at, marker)
    }
}

/// A marker's unique name part: 16 hex characters from the process's
/// randomly seeded hasher, the time and the process id.
fn nonce() -> String {
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    hasher.write_u128(now);
    hasher.write_u32(std::process::id());
    format!("{:016x}", hasher.finish())
}

/// What a helper run found in the markers for the pending release.
#[cfg(feature = "helper")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Ingested {
    /// `launched` markers for the pending release.
    pub(crate) launches: u32,
    /// Whether a `painted` marker for the pending release was found.
    pub(crate) painted: bool,
    /// More entries than a run reads ([`MAX_MARKER_ENTRIES`]): nothing was
    /// read or removed, and the run decides nothing.
    pub(crate) overflow: bool,
}

/// The most markers (Windows: values; Linux: drop box entries, temporary
/// files included) one helper run reads. Past it the run decides nothing:
/// a flood can keep a release, never revert one.
#[cfg(feature = "helper")]
pub(crate) const MAX_MARKER_ENTRIES: usize = 256;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests;
