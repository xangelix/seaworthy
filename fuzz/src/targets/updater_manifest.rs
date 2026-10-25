//! `updater_manifest` — the update path's network- and machine-input
//! parsers: the signed release manifest
//! (`seaworthy_formats::ReleaseManifest::decode_signed`, strict canonical
//! statement), the installed-version read-back
//! (`Release::from_package_version`, fed what a package manager prints),
//! the version-token gate (`seaworthy_formats::validate_version`), the
//! package format check, and in `seaworthy-updater` the policy file and
//! package-hold parsers (what an administrator or the package databases
//! hold) and, through its `__fuzz` seam, the query-preserving
//! manifest/signature URL derivation and the package URL expansion the
//! server's version token reaches. A compromised release origin controls
//! the manifest and URL bytes; the server controls the token.
//!
//! Input: `[mode][bytes]`.
//!
//! Invariants:
//! - an accepted manifest re-encodes to a file that decodes identically,
//!   and its canonical statement is a prefix of the input;
//! - the version gate accepts exactly `[A-Za-z0-9._+-]{1,128}` without
//!   `..` (an independent re-statement, both directions);
//! - an installed version is read back only when the release spells back
//!   to exactly the input, in that format;
//! - an accepted policy file names its policy, and a hold names the
//!   package;
//! - a derived URL keeps the scheme, host, port, query, and fragment byte
//!   for byte and only appends the extension to the path;
//! - a package URL expands only for a valid version, leaves no `{`, and
//!   for the fixed template is exactly the template with each placeholder
//!   replaced (the version once, where `{version}` was);
//! - the format check accepts a package only when it starts with its
//!   format's magic, and never panics on a short header.

use seaworthy_formats::release::Release;
use seaworthy_formats::{ArtifactFormat, ReleaseManifest};
use seaworthy_updater::__fuzz as upd;

/// Runs one input (see the module docs for its layout).
pub fn run(data: &[u8]) {
    let Some((&mode, bytes)) = data.split_first() else {
        return;
    };
    match mode % 7 {
        0 => manifest(bytes),
        1 => version(&crate::text(bytes)),
        2 => installed_version(bytes),
        3 => {
            let (package, text) = crate::split_at_byte(bytes, b'\n');
            policy_and_holds(&crate::text(package), &crate::text(text));
        }
        4 => metadata_url(&crate::text(bytes)),
        5 => {
            let (template, version) = crate::split_at_byte(bytes, b'\n');
            package_url(&crate::text(template), &crate::text(version));
        }
        _ => format_check(bytes),
    }
}

/// The helper's package URL: the fixed production-shaped template with a
/// fuzzed version, then a fuzzed template with that version.
fn package_url(template: &str, version: &str) {
    const FIXED: &str =
        "https://releases.example.com/{product}/{channel}/{version}/{target}/pkg.{format}";
    match upd::expand_package_url(FIXED, version) {
        Ok(url) => {
            assert!(
                version_ok(version),
                "expanded an invalid version {version:?}"
            );
            // The token's `+` travels as `%2B` (S3 decodes a literal `+`
            // in a path as a space); nothing else in the charset is encoded.
            let expected = format!(
                "https://releases.example.com/fuzz-fuzz/stable/{}/{}/pkg.deb",
                version.replace('+', "%2B"),
                seaworthy_formats::TARGET_TRIPLE
            );
            assert_eq!(url, expected);
            assert!(!url.contains('+'), "a literal + in {url:?}");
        }
        Err(_) => assert!(!version_ok(version), "refused a valid version {version:?}"),
    }
    if let Ok(url) = upd::expand_package_url(template, version) {
        assert!(version_ok(version));
        assert!(!url.contains('{'), "a placeholder survived: {url:?}");
    }
}

fn manifest(bytes: &[u8]) {
    let Ok((manifest, signatures)) = ReleaseManifest::decode_signed(bytes) else {
        return;
    };
    let statement = manifest.statement().expect("a decoded manifest validates");
    assert!(
        bytes.starts_with(&statement),
        "the canonical statement is the input's prefix"
    );
    assert_eq!(
        ReleaseManifest::from_statement(&statement).expect("the statement parses alone"),
        manifest
    );
    let encoded = manifest
        .encode_signed(&signatures)
        .expect("a decoded manifest re-encodes");
    let (again, again_signatures) =
        ReleaseManifest::decode_signed(&encoded).expect("the re-encoding decodes");
    assert_eq!(again, manifest);
    assert_eq!(again_signatures, signatures);
}

fn version_ok(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !version.contains("..")
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
}

fn version(text: &str) {
    assert_eq!(
        seaworthy_formats::validate_version(text).is_ok(),
        version_ok(text),
        "version gate"
    );
}

fn installed_version(bytes: &[u8]) {
    let Some((&which, text)) = bytes.split_first() else {
        return;
    };
    let format = [
        ArtifactFormat::Deb,
        ArtifactFormat::Rpm,
        ArtifactFormat::Pacman,
        ArtifactFormat::Pkg,
        ArtifactFormat::Msi,
    ][usize::from(which) % 5];
    let text = crate::text(text);
    let Ok(release) = Release::from_package_version(format, &text) else {
        return;
    };
    let spelled = release
        .package_versions()
        .expect("a read-back release spells");
    let back = match format {
        ArtifactFormat::Deb => spelled.deb,
        ArtifactFormat::Pkg => spelled.pkg,
        ArtifactFormat::Msi => spelled.msi_release,
        ArtifactFormat::Rpm => format!("{}-{}", spelled.rpm_version, spelled.rpm_release),
        _ => format!("{}-{}", spelled.pacman_pkgver, spelled.pacman_pkgrel),
    };
    assert_eq!(back, text, "an installed version reads back only exactly");
}

fn policy_and_holds(package: &str, text: &str) {
    if let Ok(policy) = seaworthy_updater::parse_policy_file(text) {
        assert!(text.contains("updates"));
        assert!(text.contains(policy.as_str()));
    }
    if let Ok(settings) = seaworthy_updater::parse_policy_settings(text)
        && let Some(server) = settings.server
    {
        // An accepted server is an https URL (its scheme in any case).
        assert!(
            server
                .get(..8)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://")),
            "{server:?}"
        );
        assert!(server.len() <= seaworthy_formats::MAX_SERVER_BYTES);
    }
    if !package.is_empty() {
        if seaworthy_updater::dpkg_holds(text, package) {
            assert!(text.contains(package) && text.contains("hold"));
        }
        if seaworthy_updater::versionlock_holds(text, package) {
            assert!(text.contains(package));
        }
    }
}

fn metadata_url(text: &str) {
    for extension in [".sig", ".manifest"] {
        let Ok(derived) = upd::metadata_url(text, extension) else {
            continue;
        };
        let original = url::Url::parse(text).expect("an accepted artifact URL parses");
        // Only http(s) is ever fetched (the TLS gate refuses the rest), and
        // `file:` URLs have Windows-drive-letter path rules under which a
        // set_path → re-parse is not idempotent in the url crate itself.
        if !matches!(original.scheme(), "http" | "https") {
            continue;
        }
        let derived = url::Url::parse(&derived).expect("the derived URL parses");
        assert_eq!(derived.scheme(), original.scheme());
        assert_eq!(derived.host_str(), original.host_str());
        assert_eq!(derived.port(), original.port());
        assert_eq!(derived.query(), original.query(), "query must be preserved");
        assert_eq!(
            derived.fragment(),
            original.fragment(),
            "fragment must be preserved"
        );
        assert_eq!(derived.username(), original.username());
        assert!(derived.path().ends_with(extension), "extension on the PATH");
    }
}

fn format_check(bytes: &[u8]) {
    let Some((&which, header)) = bytes.split_first() else {
        return;
    };
    let format = ArtifactFormat::ALL[usize::from(which) % ArtifactFormat::ALL.len()];
    if seaworthy_formats::format_check::check_package(header, format).is_ok() {
        let magic: &[u8] = match format {
            ArtifactFormat::Deb => b"!<arch>\n",
            ArtifactFormat::Rpm => &[0xed, 0xab, 0xee, 0xdb],
            ArtifactFormat::Pacman | ArtifactFormat::Tar => &[0x28, 0xb5, 0x2f, 0xfd],
            ArtifactFormat::Zip => b"PK\x03\x04",
            ArtifactFormat::Msi => &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1],
            ArtifactFormat::Pkg => b"xar!",
        };
        assert!(header.starts_with(magic), "{format} accepted without its magic");
    }
}
