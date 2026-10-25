//! The reproducible archives, read back by the system's own tools: GNU
//! `tar` for the ustar + zstd tarball, Info-ZIP's `unzip`/`zipinfo` for the
//! zip. Plus determinism, every refusal, and the CRC-32 and calendar
//! vectors.
//!
//! A missing tool is skipped loudly, unless
//! `SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1` turns the skip into a failure.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::process::Command;

use seaworthy::archive::{
    ArchiveError, Entry, ZIP_END, ZIP_EPOCH, civil, crc32, rfc3339, tar_zst, zip,
};

fn required() -> bool {
    std::env::var_os("SEAWORTHY_REQUIRE_PACKAGE_TOOLS").is_some_and(|v| v == "1")
}

fn have(tool: &str, probe: &str) -> bool {
    let ok = Command::new(tool)
        .arg(probe)
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        assert!(
            !required(),
            "{tool} is required (SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1) but not runnable"
        );
        eprintln!("SKIPPED: {tool} is not installed");
    }
    ok
}

/// A GNU tar: `tar` where it is one (Linux), else Homebrew's `gtar`. The
/// listing checks read GNU tar's format; macOS's `tar` is bsdtar.
fn gnu_tar() -> Option<&'static str> {
    let found = ["tar", "gtar"].into_iter().find(|tool| {
        Command::new(tool).arg("--version").output().is_ok_and(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains("GNU tar")
        })
    });
    if found.is_none() {
        assert!(
            !required(),
            "GNU tar is required (SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1) but neither tar nor gtar is one"
        );
        eprintln!("SKIPPED: no GNU tar (tar or gtar)");
    }
    found
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("runs");
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn file(path: &str, mode: u32, data: &[u8]) -> Entry {
    Entry {
        path: path.to_owned(),
        mode,
        data: Some(data.to_vec()),
    }
}

fn dir(path: &str) -> Entry {
    Entry {
        path: path.to_owned(),
        mode: 0o755,
        data: None,
    }
}

/// A long path: a 120-byte directory chain, so the name needs ustar's
/// prefix field.
fn long_dir() -> String {
    format!("top/{}", ["segment-0123456789"; 6].join("/"))
}

fn sample() -> Vec<Entry> {
    let long = long_dir();
    vec![
        dir("top"),
        dir("top/lib"),
        file("top/AcmeTool", 0o755, b"#!launcher\n"),
        file(
            "top/lib/libacme_core_x86-64-v3.so",
            0o755,
            &vec![7u8; 70_000],
        ),
        file("top/readme.txt", 0o644, b"plain\n"),
        file("top/caf\u{e9}.txt", 0o644, "non-ASCII name\n".as_bytes()),
        dir(&long),
        file(&format!("{long}/deep.bin"), 0o600, b"deep"),
    ]
}

#[test]
fn crc32_matches_the_standard_check_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
    assert_eq!(
        crc32(b"The quick brown fox jumps over the lazy dog"),
        0x414F_A339
    );
}

#[test]
fn civil_dates_match_known_timestamps() {
    assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
    assert_eq!(civil(ZIP_EPOCH), (1980, 1, 1, 0, 0, 0));
    assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0, 0)); // a leap day
    assert_eq!(civil(1_760_400_000), (2025, 10, 14, 0, 0, 0));
    assert_eq!(civil(ZIP_END), (2107, 12, 31, 23, 59, 58));
    assert_eq!(rfc3339(1_234_567_890), "2009-02-13T23:31:30Z");
}

#[test]
fn the_same_entries_give_the_same_bytes_in_any_order() {
    let a = sample();
    let mut b = sample();
    b.reverse();
    assert_eq!(
        tar_zst(&a, 1_700_000_000).unwrap(),
        tar_zst(&b, 1_700_000_000).unwrap()
    );
    assert_eq!(
        zip(&a, 1_700_000_000).unwrap(),
        zip(&b, 1_700_000_000).unwrap()
    );
    assert_ne!(
        tar_zst(&a, 1).unwrap(),
        tar_zst(&a, 2).unwrap(),
        "the timestamp is recorded"
    );
}

#[test]
fn bad_names_and_duplicates_are_refused() {
    for bad in [
        "",
        "/abs",
        "a/../b",
        "a//b",
        "./a",
        "a\\b",
        "a/",
        "tab\there",
    ] {
        let entries = [file(bad, 0o644, b"x")];
        assert!(
            matches!(tar_zst(&entries, 0), Err(ArchiveError::Name(_))),
            "tar accepted {bad:?}"
        );
        assert!(
            matches!(zip(&entries, 0), Err(ArchiveError::Name(_))),
            "zip accepted {bad:?}"
        );
    }
    let twice = [file("a", 0o644, b"1"), file("a", 0o644, b"2")];
    assert!(matches!(
        tar_zst(&twice, 0),
        Err(ArchiveError::Duplicate(_))
    ));
    assert!(matches!(zip(&twice, 0), Err(ArchiveError::Duplicate(_))));
}

#[test]
fn names_ustar_cannot_hold_are_refused_never_truncated() {
    // Over 255 bytes in all.
    let long = format!("d/{}", "x".repeat(254));
    assert!(matches!(
        tar_zst(&[file(&long, 0o644, b"x")], 0),
        Err(ArchiveError::Name(_))
    ));
    // A final segment over 100 bytes can't go in the name field.
    let segment = format!("d/{}", "y".repeat(101));
    assert!(matches!(
        tar_zst(&[file(&segment, 0o644, b"x")], 0),
        Err(ArchiveError::Name(_))
    ));
    // A prefix over 155 bytes before the last usable split.
    let prefix = format!("{}/{}", "p".repeat(160), "f");
    assert!(matches!(
        tar_zst(&[file(&prefix, 0o644, b"x")], 0),
        Err(ArchiveError::Name(_))
    ));
    // zip holds all of them.
    assert!(zip(&[file(&segment, 0o644, b"x")], 0).is_ok());
}

/// Each line's fields joined by one space: listings pad columns.
fn normalized(listing: &str) -> String {
    listing
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" ") + "\n")
        .collect()
}

fn extract_tar(tar: &str, bytes: &[u8], into: &Path) -> String {
    let archive = into.join("a.tar.zst");
    std::fs::write(&archive, bytes).unwrap();
    let out = into.join("x");
    std::fs::create_dir(&out).unwrap();
    run(Command::new(tar)
        .args(["--zstd", "-xf"])
        .arg(&archive)
        .arg("-C")
        .arg(&out));
    run(Command::new(tar)
        .args(["--zstd", "--numeric-owner", "--full-time", "-tvf"])
        .arg(&archive))
}

#[test]
fn gnu_tar_reads_the_tarball_back_exactly() {
    let Some(tar) = gnu_tar() else { return };
    if !have("zstd", "--version") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let listing = normalized(&extract_tar(
        tar,
        &tar_zst(&sample(), 1_700_000_000).unwrap(),
        tmp.path(),
    ));
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines.len(), sample().len(), "{listing}");
    for line in &lines {
        assert!(line.contains(" 0/0 "), "owned by root: {line}");
        assert!(
            line.contains("2023-11-14 22:13:20"),
            "one timestamp: {line}"
        );
    }
    assert!(
        listing.contains(
            "-rwxr-xr-x 0/0 70000 2023-11-14 22:13:20 top/lib/libacme_core_x86-64-v3.so\n"
        ),
        "{listing}"
    );
    assert!(
        listing.contains(&format!(
            "-rw------- 0/0 4 2023-11-14 22:13:20 {}/deep.bin\n",
            long_dir()
        )),
        "{listing}"
    );
    assert!(
        listing.contains("drwxr-xr-x 0/0 0 2023-11-14 22:13:20 top/lib/\n"),
        "{listing}"
    );
    assert!(
        listing.contains("-rw-r--r-- 0/0 15 2023-11-14 22:13:20 top/caf\u{e9}.txt\n"),
        "{listing}"
    );
    let x = tmp.path().join("x");
    assert_eq!(
        std::fs::read(x.join("top/AcmeTool")).unwrap(),
        b"#!launcher\n"
    );
    assert_eq!(
        std::fs::read(x.join("top/lib/libacme_core_x86-64-v3.so")).unwrap(),
        vec![7u8; 70_000]
    );
    assert_eq!(
        std::fs::read(x.join("top/caf\u{e9}.txt")).unwrap(),
        b"non-ASCII name\n"
    );
    assert_eq!(
        std::fs::read(x.join(format!("{}/deep.bin", long_dir()))).unwrap(),
        b"deep"
    );
}

#[test]
fn a_long_single_segment_directory_is_refused_not_given_an_empty_name() {
    // The only `/` is the directory's own trailing one: splitting there
    // would leave ustar's name field empty.
    let d = "y".repeat(119);
    assert!(matches!(tar_zst(&[dir(&d)], 0), Err(ArchiveError::Name(_))));
    assert!(zip(&[dir(&d)], 0).is_ok());
}

#[test]
fn a_directory_name_between_100_and_156_bytes_keeps_a_name_field() {
    let Some(tar) = gnu_tar() else { return };
    if !have("zstd", "--version") {
        return;
    }
    // 120 bytes with its trailing '/': the split must not leave an empty
    // name field.
    let d = format!("{}/{}", "a".repeat(60), "b".repeat(58));
    let tmp = tempfile::tempdir().unwrap();
    let listing = extract_tar(tar, &tar_zst(&[dir(&d)], 0).unwrap(), tmp.path());
    assert!(listing.trim_end().ends_with(&format!("{d}/")), "{listing}");
    assert!(tmp.path().join("x").join(&d).is_dir());
}

#[test]
fn unzip_reads_the_zip_back_exactly() {
    if !have("unzip", "-v") || !have("zipinfo", "-v") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("a.zip");
    std::fs::write(&archive, zip(&sample(), 1_700_000_000).unwrap()).unwrap();
    // Every CRC and size checks out.
    run(Command::new("unzip").arg("-tq").arg(&archive));
    let listing = normalized(&run(Command::new("zipinfo").arg("-T").arg(&archive)));
    assert!(
        listing.contains(
            "-rwxr-xr-x 2.0 unx 70000 b- defN 20231114.221320 top/lib/libacme_core_x86-64-v3.so\n"
        ),
        "{listing}"
    );
    assert!(
        listing.contains("-rw-r--r-- 2.0 unx 6 b- defN 20231114.221320 top/readme.txt\n"),
        "{listing}"
    );
    assert!(
        listing.contains("drwxr-xr-x 2.0 unx 0 b- stor 20231114.221320 top/lib/\n"),
        "{listing}"
    );
    let x = tmp.path().join("x");
    run(Command::new("unzip")
        .arg("-q")
        .arg(&archive)
        .arg("-d")
        .arg(&x));
    assert_eq!(
        std::fs::read(x.join("top/lib/libacme_core_x86-64-v3.so")).unwrap(),
        vec![7u8; 70_000]
    );
    assert_eq!(
        std::fs::read(x.join("top/caf\u{e9}.txt")).unwrap(),
        b"non-ASCII name\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(x.join("top/AcmeTool"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }
}

#[test]
fn zip_times_clamp_to_what_the_format_holds() {
    if !have("zipinfo", "-v") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    for (mtime, shown) in [
        (0, "19800101.000000"),
        (ZIP_END + 1_000_000, "21071231.235958"),
    ] {
        let archive = tmp.path().join("t.zip");
        std::fs::write(&archive, zip(&[file("f", 0o644, b"x")], mtime).unwrap()).unwrap();
        let listing = run(Command::new("zipinfo").arg("-T").arg(&archive));
        assert!(listing.contains(shown), "{mtime}: {listing}");
    }
}
