use super::*;

fn release(version: &str, sequence: u64) -> Release {
    Release::new(version, sequence).unwrap()
}

#[test]
fn markers_and_notices_round_trip_and_nothing_else_parses() {
    let marker = Marker {
        state: MarkerState::Painted,
        release: release("1.4.0-rc.2", 812),
    };
    let text = marker.encode();
    assert_eq!(text, "seaworthy-first-paint:1\npainted 1.4.0-rc.2 812\n");
    assert_eq!(Marker::parse(&text).unwrap(), marker);
    let launched = Marker {
        state: MarkerState::Launched,
        ..marker.clone()
    };
    assert_eq!(Marker::parse(&launched.encode()).unwrap(), launched);
    let notice = Notice {
        pending: release("2.0.0", 3),
    };
    assert_eq!(
        notice.encode(),
        "seaworthy-probation-notice:1\npending 2.0.0 3\n"
    );
    assert_eq!(Notice::parse(&notice.encode()).unwrap(), notice);
    for bad in [
        String::new(),
        "seaworthy-first-paint:1\n".to_owned(),
        "seaworthy-first-paint:2\npainted 1.0.0 1\n".to_owned(),
        "seaworthy-first-paint:1\npainted 1.0.0 1".to_owned(),
        "seaworthy-first-paint:1\npainted 1.0.0 1\n\n".to_owned(),
        "seaworthy-first-paint:1\npainted 1.0.0 1\nlaunched 1.0.0 1\n".to_owned(),
        "seaworthy-first-paint:1\nshown 1.0.0 1\n".to_owned(),
        "seaworthy-first-paint:1\npainted v1.0.0 1\n".to_owned(),
        "seaworthy-first-paint:1\npainted 1.0.0 01\n".to_owned(),
        "seaworthy-first-paint:1\npainted 1.0.0 0\n".to_owned(),
        "seaworthy-first-paint:1\npainted 1.0.0 -1\n".to_owned(),
        "seaworthy-first-paint:1\npainted 1.0.0+abc 1\n".to_owned(),
        "seaworthy-first-paint:1\npainted 1.0.0  1\n".to_owned(),
        "seaworthy-first-paint:1\npainted 1.0.0 1 \n".to_owned(),
        "seaworthy-first-paint:1\r\npainted 1.0.0 1\r\n".to_owned(),
        "seaworthy-probation-notice:1\npending 1.0.0 1\n".to_owned(),
        format!(
            "seaworthy-first-paint:1\npainted 1.0.0 {}\n",
            "9".repeat(300)
        ),
    ] {
        assert!(Marker::parse(&bad).is_err(), "{bad:?}");
    }
    for bad in [
        "seaworthy-probation-notice:1\npainted 1.0.0 1\n",
        "seaworthy-probation-notice:1\npending 1.0.0\n",
        "seaworthy-first-paint:1\npending 1.0.0 1\n",
    ] {
        assert!(Notice::parse(bad).is_err(), "{bad:?}");
    }
}

#[cfg(all(not(windows), feature = "helper"))]
mod linux {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::{InstalledRelease, ProbationSettings};

    fn product(probation: bool) -> Product {
        let product = Product::new("Acme", "console", "Console", "stable").unwrap();
        if probation {
            product.with_probation(
                ProbationSettings::new(3, std::time::Duration::from_secs(3600)).unwrap(),
            )
        } else {
            product
        }
    }

    /// A machine in a temporary directory: `<root>/opt` the install root,
    /// `<root>/var/acme/console` the probation directory, under `<root>/var`.
    struct Machine {
        root: tempfile::TempDir,
    }

    impl Machine {
        fn new(installed: Option<&Release>) -> Self {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let opt = root.path().join("opt");
            std::fs::create_dir(&opt).unwrap();
            if let Some(release) = installed {
                std::fs::write(
                    opt.join(crate::INSTALLED_RELEASE_FILE),
                    InstalledRelease::new(release.clone(), "abc")
                        .unwrap()
                        .encode(),
                )
                .unwrap();
            }
            let var = root.path().join("var");
            std::fs::create_dir(&var).unwrap();
            std::fs::set_permissions(&var, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self { root }
        }

        fn at(&self) -> Locations {
            Locations {
                install_root: Some(self.root.path().join("opt")),
                public: self.root.path().join("var").join("acme").join("console"),
                top: self.root.path().join("var"),
                require_root: false,
                request: false,
            }
        }

        fn drop_box(&self) -> std::path::PathBuf {
            self.at().public.join(DROP_BOX)
        }

        fn markers(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(self.drop_box())
                .map(|entries| {
                    entries
                        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            names.sort();
            names
        }
    }

    #[test]
    fn the_app_marks_launches_and_its_paint_only_on_probation() {
        let pending = release("2.0.0", 7);
        let machine = Machine::new(Some(&pending));
        // No notice yet: nothing written, not on probation.
        let paint = FirstPaint::arm_at(&product(true), machine.at());
        assert_eq!(paint.on_probation(), None);
        paint.painted();
        assert!(machine.markers().is_empty());
        // The helper publishes the probation of exactly this release.
        unix::publish(
            &machine.at(),
            &Notice {
                pending: pending.clone(),
            },
        )
        .unwrap();
        let mode = |path: &std::path::Path| {
            std::fs::symlink_metadata(path)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode(&machine.drop_box()), DROP_BOX_MODE);
        assert_eq!(mode(&machine.at().public), 0o755);
        assert_eq!(mode(&machine.at().public.join(NOTICE_FILE)), 0o644);
        // A product without probation never looks.
        let off = FirstPaint::arm_at(&product(false), machine.at());
        assert_eq!(off.on_probation(), None);
        assert!(machine.markers().is_empty());
        // On probation: one marker at start, one at the paint.
        let paint = FirstPaint::arm_at(&product(true), machine.at());
        assert_eq!(paint.on_probation(), Some(&pending));
        assert_eq!(machine.markers().len(), 1);
        paint.painted();
        let names = machine.markers();
        assert_eq!(names.len(), 2, "{names:?}");
        let mut states: Vec<MarkerState> = names
            .iter()
            .map(|name| {
                assert!(unix::marker_uid(name).is_some(), "{name}");
                let path = machine.drop_box().join(name);
                assert_eq!(mode(&path), 0o600);
                Marker::parse(&std::fs::read_to_string(path).unwrap())
                    .unwrap()
                    .state
            })
            .collect();
        states.sort_by_key(|s| s.as_str());
        assert_eq!(states, [MarkerState::Launched, MarkerState::Painted]);
        // The helper counts them for the pending release, and removes them.
        let found = unix::ingest(&machine.at(), &pending).unwrap();
        assert_eq!(
            found,
            Ingested {
                launches: 1,
                painted: true,
                overflow: false
            }
        );
        assert!(machine.markers().is_empty());
        // Another release running (the notice names another): nothing.
        let other = Machine::new(Some(&release("1.9.0", 6)));
        unix::publish(&other.at(), &Notice { pending }).unwrap();
        assert_eq!(
            FirstPaint::arm_at(&product(true), other.at()).on_probation(),
            None
        );
        assert!(other.markers().is_empty());
        // Withdrawn: the app is off probation again.
        unix::withdraw(&machine.at());
        assert_eq!(
            FirstPaint::arm_at(&product(true), machine.at()).on_probation(),
            None
        );
    }

    #[test]
    fn an_untrusted_notice_or_drop_box_is_ignored() {
        let pending = release("2.0.0", 7);
        let machine = Machine::new(Some(&pending));
        unix::publish(
            &machine.at(),
            &Notice {
                pending: pending.clone(),
            },
        )
        .unwrap();
        let notice = machine.at().public.join(NOTICE_FILE);
        // A notice others could write is no notice.
        std::fs::set_permissions(&notice, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            FirstPaint::arm_at(&product(true), machine.at()).on_probation(),
            None
        );
        std::fs::set_permissions(&notice, std::fs::Permissions::from_mode(0o644)).unwrap();
        // A drop box with another mode: no marker written, and the helper
        // refuses to read it.
        std::fs::set_permissions(machine.drop_box(), std::fs::Permissions::from_mode(0o1777))
            .unwrap();
        let paint = FirstPaint::arm_at(&product(true), machine.at());
        assert_eq!(
            paint.on_probation(),
            Some(&pending),
            "the notice still reads"
        );
        assert!(machine.markers().is_empty());
        assert!(unix::ingest(&machine.at(), &pending).is_err());
        // A link in its place.
        std::fs::remove_dir(machine.drop_box()).unwrap();
        let elsewhere = machine.root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(DROP_BOX_MODE))
            .unwrap();
        std::os::unix::fs::symlink(&elsewhere, machine.drop_box()).unwrap();
        assert!(unix::ingest(&machine.at(), &pending).is_err());
        assert!(unix::publish(&machine.at(), &Notice { pending }).is_err());
    }

    #[test]
    fn forged_linked_odd_and_oversized_markers_count_for_nothing_and_go() {
        use std::io::Write as _;
        let pending = release("2.0.0", 7);
        let machine = Machine::new(Some(&pending));
        unix::publish(
            &machine.at(),
            &Notice {
                pending: pending.clone(),
            },
        )
        .unwrap();
        let dir = machine.drop_box();
        let euid = unix_euid();
        let launched = Marker {
            state: MarkerState::Launched,
            release: pending.clone(),
        }
        .encode();
        let painted = Marker {
            state: MarkerState::Painted,
            release: pending.clone(),
        }
        .encode();
        let name = |pid: u32| format!("{euid}.{pid}.0123456789abcdef");
        // Counted: one launch.
        std::fs::write(dir.join(name(1)), &launched).unwrap();
        // Another uid's name on our file: a forgery.
        std::fs::write(
            dir.join(format!("{}.2.0123456789abcdef", euid.wrapping_add(1))),
            &painted,
        )
        .unwrap();
        // A link to a painted marker elsewhere.
        let outside = machine.root.path().join("painted");
        std::fs::write(&outside, &painted).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join(name(3))).unwrap();
        // A hard link to it.
        std::fs::hard_link(&outside, dir.join(name(4))).unwrap();
        // Too large.
        let mut big = std::fs::File::create(dir.join(name(5))).unwrap();
        big.write_all(painted.as_bytes()).unwrap();
        big.write_all(&[b' '; MAX_RECORD_BYTES]).unwrap();
        // A FIFO.
        let fifo = dir.join(name(6));
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        // Another release's paint, a junk name, a broken marker.
        std::fs::write(
            dir.join(name(7)),
            Marker {
                state: MarkerState::Painted,
                release: release("1.0.0", 1),
            }
            .encode(),
        )
        .unwrap();
        std::fs::write(dir.join("not-a-marker"), &painted).unwrap();
        std::fs::write(dir.join(name(8)), "garbage").unwrap();
        // A fresh temporary file stays (the app is between create and
        // rename); a stale one goes.
        std::fs::write(dir.join(format!(".{}", name(9))), &painted).unwrap();
        let stale = dir.join(format!(".{}", name(10)));
        std::fs::write(&stale, &painted).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let found = unix::ingest(&machine.at(), &pending).unwrap();
        assert_eq!(
            found,
            Ingested {
                launches: 1,
                painted: false,
                overflow: false
            }
        );
        assert_eq!(machine.markers(), [format!(".{}", name(9))]);
        assert!(outside.exists(), "a link's target is never touched");
    }

    #[test]
    fn a_flood_is_read_no_further_and_decides_nothing() {
        let pending = release("2.0.0", 7);
        let machine = Machine::new(Some(&pending));
        unix::publish(
            &machine.at(),
            &Notice {
                pending: pending.clone(),
            },
        )
        .unwrap();
        let painted = Marker {
            state: MarkerState::Painted,
            release: pending.clone(),
        }
        .encode();
        let euid = unix_euid();
        for n in 0..=MAX_MARKER_ENTRIES {
            std::fs::write(
                machine
                    .drop_box()
                    .join(format!("{euid}.{}.0123456789abcdef", n + 1)),
                &painted,
            )
            .unwrap();
        }
        let found = unix::ingest(&machine.at(), &pending).unwrap();
        assert_eq!(
            found,
            Ingested {
                launches: 0,
                painted: false,
                overflow: true
            }
        );
        assert_eq!(machine.markers().len(), MAX_MARKER_ENTRIES + 1);
    }

    #[test]
    fn marker_names_are_strict() {
        for good in ["0.1.0123456789abcdef", "1000.4242.ffffffffffffffff"] {
            assert!(unix::marker_uid(good).is_some(), "{good}");
        }
        for bad in [
            "01000.1.0123456789abcdef",
            "1000.01.0123456789abcdef",
            "1000.1.0123456789ABCDEF",
            "1000.1.0123456789abcde",
            "1000.1.0123456789abcdef.x",
            "1000.1",
            "x.1.0123456789abcdef",
            "99999999999.1.0123456789abcdef",
            ".1000.1.0123456789abcdef",
        ] {
            assert!(unix::marker_uid(bad).is_none(), "{bad}");
        }
    }

    fn unix_euid() -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        std::fs::metadata(dir.path()).unwrap().uid()
    }
}
