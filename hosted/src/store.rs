pub use tailfeather_reactor::native::store::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn state_replacement_is_private_and_corruption_is_not_reset() {
        let root = tempfile::tempdir().unwrap();
        create_directory(root.path()).unwrap();
        let store = FileStore::new(root.path());
        let mut bytes = [0; 16];
        assert_eq!(store.load(&mut bytes).unwrap(), None);
        store.save(b"previous").unwrap();
        store.save(b"replacement").unwrap();
        let n = store.load(&mut bytes).unwrap().unwrap();
        assert_eq!(&bytes[..n], b"replacement");
        assert!(crate::is_enrolled(root.path(), "https://control.invalid").is_err());
        assert_eq!(
            fs::read(root.path().join("tailfeather.state")).unwrap(),
            b"replacement"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(root.path().join("tailfeather.state"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn another_process_cannot_open_the_same_identity() {
        let root = tempfile::tempdir().unwrap();
        let lock = fs::File::create(root.path().join("lock")).unwrap();
        lock.try_lock().unwrap();
        let result = crate::Client::start(crate::Config {
            directory: root.path().into(),
            control_url: "https://control.invalid".into(),
            hostname: "fixture".into(),
            auth_key: "fixture-only".into(),
            control_ca_der: Vec::new(),
            relay_only: false,
            ephemeral: true,
        });
        assert!(result.is_err());
    }
}
