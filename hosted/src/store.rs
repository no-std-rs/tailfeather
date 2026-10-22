use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
pub fn create_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub struct FileStore(PathBuf);
impl FileStore {
    pub fn new(path: &Path) -> Self {
        Self(path.join("tailfeather.state"))
    }
    pub fn load(&self, out: &mut [u8]) -> io::Result<Option<usize>> {
        match fs::read(&self.0) {
            Ok(bytes) => {
                if bytes.len() > out.len() {
                    return Err(io::Error::other("state size"));
                }
                out[..bytes.len()].copy_from_slice(&bytes);
                Ok(Some(bytes.len()))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub fn save(&self, bytes: &[u8]) -> io::Result<()> {
        let parent = self.0.parent().unwrap();
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist(&self.0).map_err(|e| e.error)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
