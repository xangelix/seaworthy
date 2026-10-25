//! `dist_pe` — seaworthy's post-link version-resource writer
//! (`pe_version::stamp_version`) over arbitrary images.
//!
//! Invariants: nothing panics. An image it accepts comes back as a PE
//! `object` parses, with the image's other resources intact (bytes and
//! code page, every data address inside a section) and exactly one version
//! resource (type 16, id 1, en-US) holding the release's blob, read back by
//! `object`'s own resource reader whenever it can read the original's
//! tree. Stamping the result again succeeds (the
//! in-place rewrite of a trailing resource section) and, with the same
//! release, gives the same bytes.

use std::collections::BTreeMap;

use seaworthy::pe_version::{VersionInfo, stamp_version, version_blob};
use seaworthy::version::Release;
use object::LittleEndian as LE;
use object::read::pe::{PeFile64, ResourceDirectoryEntryData, ResourceNameOrId};

/// (type, name, language), ids spelled `#<id>`.
type Key = (String, String, String);

/// Every resource's bytes and code page, by `object`'s reader; `None` when
/// it can't read the tree or a data address lies outside every section.
fn resources(image: &[u8]) -> Option<BTreeMap<Key, (Vec<u8>, u32)>> {
    let file = PeFile64::parse(image).ok()?;
    let sections = file.section_table();
    let directory = file
        .data_directories()
        .resource_directory(image, &sections)
        .ok()??;
    let key = |entry: &object::pe::ImageResourceDirectoryEntry| -> Option<String> {
        Some(match entry.name_or_id() {
            ResourceNameOrId::Id(id) => format!("#{id}"),
            ResourceNameOrId::Name(name) => name.to_string_lossy(directory).ok()?,
        })
    };
    let mut out = BTreeMap::new();
    for kind in directory.root().ok()?.entries {
        let ResourceDirectoryEntryData::Table(names) = kind.data(directory).ok()? else {
            return None;
        };
        for name in names.entries {
            let ResourceDirectoryEntryData::Table(languages) = name.data(directory).ok()? else {
                return None;
            };
            for language in languages.entries {
                let ResourceDirectoryEntryData::Data(entry) = language.data(directory).ok()? else {
                    return None;
                };
                let size = usize::try_from(entry.size.get(LE)).ok()?;
                let bytes = sections
                    .pe_data_at(image, entry.offset_to_data.get(LE))?
                    .get(..size)?;
                let value = (bytes.to_vec(), entry.code_page.get(LE));
                out.insert((key(kind)?, key(name)?, key(language)?), value);
            }
        }
    }
    Some(out)
}

pub fn run(data: &[u8]) {
    let release = Release::new("1.4.0-rc.2", 812).expect("a valid release");
    let info = VersionInfo {
        company: "Acme",
        product: "Acme Agent",
        description: "Acme Agent core",
        file_name: "acme_core.dll",
        dll: true,
    };
    let Ok(once) = stamp_version(data, &release, &info) else {
        return;
    };
    object::File::parse(&*once).expect("a stamped image still parses");
    if let Some(mut expected) = resources(data) {
        expected.retain(|(kind, name, _), _| !(kind == "#16" && name == "#1"));
        let blob = version_blob(&release, &info).expect("a valid blob");
        expected.insert(("#16".into(), "#1".into(), "#1033".into()), (blob, 0));
        let actual = resources(&once).expect("a stamped image's resources read back");
        assert_eq!(
            actual, expected,
            "other resources intact, one version resource"
        );
    }
    let twice = stamp_version(&once, &release, &info).expect("a stamped image stamps again");
    let thrice = stamp_version(&twice, &release, &info).expect("and again");
    assert_eq!(
        twice, thrice,
        "re-stamping with the same release is a fixed point"
    );
}
