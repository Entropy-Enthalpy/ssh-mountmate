use crate::Error;
use mountmate_core::storage::{FileLock, atomic_write, restrict_private_path};
use sha2::{Digest, Sha256};
use ssh_key::{HashAlg, LineEnding, PrivateKey, private::Ed25519Keypair};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) struct LocalKey {
    pub path: PathBuf,
    pub public_key: String,
    pub fingerprint: String,
    pub request_id: String,
}
pub(crate) fn load_or_create(data_dir: &Path, context: &[u8]) -> Result<LocalKey, Error> {
    fs::create_dir_all(data_dir).map_err(|_| Error::KeyStorage)?;
    let root = data_dir.join("sai-keys");
    private_directory(&root)?;
    // Untrusted identifiers never become literal filenames.
    let directory = root.join(format!("{:x}", Sha256::digest(context)));
    private_directory(&directory)?;
    let _lock = FileLock::acquire(&directory.join("key.lock"), Duration::from_secs(5))
        .map_err(|_| Error::KeyStorage)?;
    let path = directory.join("id_ed25519");
    let private = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(Error::KeyStorage);
            }
            restrict_private_path(&path, false).map_err(|_| Error::KeyStorage)?;
            let mut content = Zeroizing::new(Vec::new());
            File::open(&path)
                .map_err(|_| Error::KeyStorage)?
                .take(16 * 1024)
                .read_to_end(&mut content)
                .map_err(|_| Error::KeyStorage)?;
            let key =
                PrivateKey::from_openssh(content.as_slice()).map_err(|_| Error::KeyStorage)?;
            if !key.algorithm().is_ed25519() || key.is_encrypted() {
                return Err(Error::KeyStorage);
            }
            key
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = PrivateKey::from(Ed25519Keypair::random(&mut rand_core::OsRng));
            let content = key
                .to_openssh(LineEnding::LF)
                .map_err(|_| Error::KeyStorage)?;
            atomic_write(&path, content.as_bytes()).map_err(|_| Error::KeyStorage)?;
            key
        }
        Err(_) => return Err(Error::KeyStorage),
    };
    let public_key = private
        .public_key()
        .to_openssh()
        .map_err(|_| Error::KeyStorage)?;
    let fingerprint = private
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    let mut digest = Sha256::new();
    digest.update(context);
    digest.update(public_key.as_bytes());
    Ok(LocalKey {
        path,
        public_key,
        fingerprint,
        request_id: format!("{:x}", digest.finalize()),
    })
}
fn private_directory(path: &Path) -> Result<(), Error> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(Error::KeyStorage),
    }
    if !fs::symlink_metadata(path)
        .map_err(|_| Error::KeyStorage)?
        .file_type()
        .is_dir()
    {
        return Err(Error::KeyStorage);
    }
    restrict_private_path(path, true).map_err(|_| Error::KeyStorage)
}
