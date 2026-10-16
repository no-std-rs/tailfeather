use std::collections::BTreeSet;
use std::path::PathBuf;

#[test]
fn every_embedded_fixture_has_complete_matching_provenance() {
    let root = std::env::var_os("TAILFEATHER_TESTKIT_FIXTURES")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_file() {
                path.parent().unwrap().to_path_buf()
            } else {
                path
            }
        })
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures"));
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("provenance.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["schema_version"], 1);

    let mut listed = BTreeSet::new();
    for entry in manifest["fixtures"].as_array().unwrap() {
        for required in [
            "path",
            "origin",
            "versions",
            "date",
            "redistribution_basis",
            "sanitization",
            "sha256",
        ] {
            assert!(!entry[required].is_null(), "missing {required} in {entry}");
        }
        let name = entry["path"].as_str().unwrap();
        let bytes = std::fs::read(root.join(name)).unwrap();
        assert_eq!(
            tailfeather_testkit::vectors::sha256(&bytes),
            entry["sha256"]
        );
        listed.insert(name.to_owned());
    }

    let embedded: BTreeSet<String> = std::fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "provenance.json")
        .collect();
    assert_eq!(embedded, listed);
}
