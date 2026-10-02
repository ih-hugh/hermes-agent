//! Installation-owned refusal for the staged updater, independent of Python.

use std::path::{Path, PathBuf};

pub fn admitted_installation(root: &Path) -> Result<PathBuf, &'static str> {
    const UNAVAILABLE: &str = "Self-update protection could not be checked for this installation. Use operator-managed maintenance.";
    let physical = root.canonicalize().map_err(|_| UNAVAILABLE)?;
    if !physical.metadata().map_err(|_| UNAVAILABLE)?.is_dir() {
        return Err(UNAVAILABLE);
    }
    match std::fs::symlink_metadata(physical.join(".hermes-self-update-disabled")) {
        Ok(_) => {
            Err("Self-update is disabled for this installation. Use operator-managed maintenance.")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(physical),
        Err(_) => Err(UNAVAILABLE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installation_observation_only_admits_definite_absence() {
        let root = scratch("policy");
        std::fs::create_dir(&root).unwrap();
        let sentinel = root.join(".hermes-self-update-disabled");
        assert!(admitted_installation(&root).is_ok());
        std::fs::write(&sentinel, [0xff, 0x00]).unwrap();
        assert!(admitted_installation(&root).is_err());
        std::fs::remove_file(&sentinel).unwrap();
        std::fs::create_dir(&sentinel).unwrap();
        assert!(admitted_installation(&root).is_err());
        std::fs::remove_dir_all(&root).unwrap();
        assert!(admitted_installation(&root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn physical_alias_and_dangling_entry_keep_protection() {
        let root = scratch("alias");
        std::fs::create_dir(&root).unwrap();
        let alias = root.with_extension("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        std::os::unix::fs::symlink("missing", root.join(".hermes-self-update-disabled")).unwrap();
        assert!(admitted_installation(&alias).is_err());
        std::fs::remove_file(&alias).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hermes-update-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
}
