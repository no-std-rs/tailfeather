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
    pub fn timestamp(path: &Path) -> Self {
        Self(path.join("tai64n.floor"))
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
