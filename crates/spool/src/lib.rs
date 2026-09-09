use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpoolError {
    #[error("spool capacity exceeded: current={current_bytes}, incoming={incoming_bytes}, maximum={max_bytes}")]
    CapacityExceeded {
        current_bytes: u64,
        incoming_bytes: u64,
        max_bytes: u64,
    },
    #[error("spool I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct DurableSpool {
    root: PathBuf,
    quarantine: PathBuf,
    max_bytes: u64,
    gate: Arc<Mutex<()>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingItem {
    pub id: String,
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpoolStats {
    pub items: u64,
    pub bytes: u64,
}

impl DurableSpool {
    pub fn open(root: impl Into<PathBuf>, max_bytes: u64) -> Result<Self, SpoolError> {
        let root = root.into();
        let quarantine = root.join("quarantine");
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&quarantine)?;
        let spool = Self {
            root,
            quarantine,
            max_bytes,
            gate: Arc::new(Mutex::new(())),
        };
        spool.recover_temporary_files()?;
        Ok(spool)
    }

    pub fn enqueue(&self, body: &[u8]) -> Result<String, SpoolError> {
        let _guard = self.lock();
        let id = hex::encode(Sha256::digest(body));
        let final_path = self.root.join(format!("{id}.json"));
        let quarantined_path = self.quarantine.join(format!("{id}.json"));
        if final_path.exists() || quarantined_path.exists() {
            return Ok(id);
        }
        let pending = directory_stats(&self.root)?;
        let quarantined = directory_stats(&self.quarantine)?;
        let current_bytes = pending.bytes.saturating_add(quarantined.bytes);
        let incoming_bytes = body.len() as u64;
        if current_bytes.saturating_add(incoming_bytes) > self.max_bytes {
            return Err(SpoolError::CapacityExceeded {
                current_bytes,
                incoming_bytes,
                max_bytes: self.max_bytes,
            });
        }

        let temporary_path = self.root.join(format!(".{id}.tmp"));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)?;
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&temporary_path, &final_path)?;
        File::open(&self.root)?.sync_all()?;
        Ok(id)
    }

    pub fn pending(&self) -> Result<Vec<PendingItem>, SpoolError> {
        let _guard = self.lock();
        let mut items = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            items.push(PendingItem {
                id: id.to_string(),
                bytes: entry.metadata()?.len(),
                path,
            });
        }
        items.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(items)
    }

    pub fn read(&self, item: &PendingItem) -> Result<Vec<u8>, SpoolError> {
        let _guard = self.lock();
        let mut body = Vec::with_capacity(item.bytes as usize);
        File::open(&item.path)?.read_to_end(&mut body)?;
        Ok(body)
    }

    pub fn acknowledge(&self, item: &PendingItem) -> Result<(), SpoolError> {
        let _guard = self.lock();
        self.acknowledge_unlocked(item)
    }

    fn acknowledge_unlocked(&self, item: &PendingItem) -> Result<(), SpoolError> {
        match fs::remove_file(&item.path) {
            Ok(()) => {
                File::open(&self.root)?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn quarantine(&self, item: &PendingItem) -> Result<(), SpoolError> {
        let _guard = self.lock();
        let destination = self.quarantine.join(format!("{}.json", item.id));
        if destination.exists() {
            return self.acknowledge_unlocked(item);
        }
        match fs::rename(&item.path, &destination) {
            Ok(()) => {
                File::open(&self.root)?.sync_all()?;
                File::open(&self.quarantine)?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && destination.exists() => {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn stats(&self) -> Result<SpoolStats, SpoolError> {
        let _guard = self.lock();
        directory_stats(&self.root)
    }

    pub fn quarantine_stats(&self) -> Result<SpoolStats, SpoolError> {
        let _guard = self.lock();
        directory_stats(&self.quarantine)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn lock(&self) -> MutexGuard<'_, ()> {
        self.gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn recover_temporary_files(&self) -> Result<(), SpoolError> {
        let mut changed = false;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(id) = name
                .to_str()
                .and_then(|name| name.strip_prefix('.'))
                .and_then(|name| name.strip_suffix(".tmp"))
            else {
                continue;
            };
            if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                continue;
            }

            let temporary_path = entry.path();
            let final_path = self.root.join(format!("{id}.json"));
            let quarantined_path = self.quarantine.join(format!("{id}.json"));
            if final_path.exists() || quarantined_path.exists() {
                fs::remove_file(temporary_path)?;
                changed = true;
                continue;
            }

            let body = fs::read(&temporary_path)?;
            if hex::encode(Sha256::digest(&body)) == id {
                fs::rename(temporary_path, final_path)?;
            } else {
                // The atomic write never reached its durable content boundary.
                fs::remove_file(temporary_path)?;
            }
            changed = true;
        }
        if changed {
            File::open(&self.root)?.sync_all()?;
        }
        Ok(())
    }
}

fn directory_stats(directory: &Path) -> Result<SpoolStats, SpoolError> {
    let mut stats = SpoolStats::default();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        stats.items = stats.items.saturating_add(1);
        stats.bytes = stats.bytes.saturating_add(entry.metadata()?.len());
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_is_content_idempotent_and_acknowledge_is_repeatable() {
        let directory = tempfile::tempdir().unwrap();
        let spool = DurableSpool::open(directory.path(), 1024).unwrap();
        let first = spool.enqueue(br#"{"hello":"world"}"#).unwrap();
        let second = spool.enqueue(br#"{"hello":"world"}"#).unwrap();
        assert_eq!(first, second);
        assert_eq!(spool.stats().unwrap().items, 1);

        let item = spool.pending().unwrap().pop().unwrap();
        assert_eq!(spool.read(&item).unwrap(), br#"{"hello":"world"}"#);
        spool.acknowledge(&item).unwrap();
        spool.acknowledge(&item).unwrap();
        assert_eq!(spool.stats().unwrap(), SpoolStats::default());
    }

    #[test]
    fn capacity_is_enforced_before_write() {
        let directory = tempfile::tempdir().unwrap();
        let spool = DurableSpool::open(directory.path(), 3).unwrap();
        assert!(matches!(
            spool.enqueue(b"four"),
            Err(SpoolError::CapacityExceeded { .. })
        ));
        assert_eq!(spool.stats().unwrap().items, 0);
    }

    #[test]
    fn quarantined_items_are_not_retried_and_count_toward_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let spool = DurableSpool::open(directory.path(), 20).unwrap();
        spool.enqueue(b"first").unwrap();
        let item = spool.pending().unwrap().pop().unwrap();
        spool.quarantine(&item).unwrap();

        assert_eq!(spool.stats().unwrap(), SpoolStats::default());
        assert_eq!(spool.quarantine_stats().unwrap().items, 1);
        assert!(spool.pending().unwrap().is_empty());
        assert!(matches!(
            spool.enqueue(b"a different payload"),
            Err(SpoolError::CapacityExceeded { .. })
        ));
    }

    #[test]
    fn restart_recovers_complete_temporary_writes_and_removes_partial_ones() {
        let directory = tempfile::tempdir().unwrap();
        let complete = br#"{"batch":"complete"}"#;
        let complete_id = hex::encode(Sha256::digest(complete));
        fs::write(
            directory.path().join(format!(".{complete_id}.tmp")),
            complete,
        )
        .unwrap();

        let partial_id = hex::encode(Sha256::digest(b"expected complete body"));
        let partial_path = directory.path().join(format!(".{partial_id}.tmp"));
        fs::write(&partial_path, b"partial").unwrap();

        let spool = DurableSpool::open(directory.path(), 1024).unwrap();
        let items = spool.pending().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, complete_id);
        assert_eq!(spool.read(&items[0]).unwrap(), complete);
        assert!(!partial_path.exists());
    }

    #[test]
    fn concurrent_writers_cannot_overcommit_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let spool = DurableSpool::open(directory.path(), 4).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut writers = Vec::new();
        for body in [b"aaaa".as_slice(), b"bbbb".as_slice()] {
            let spool = spool.clone();
            let barrier = barrier.clone();
            let body = body.to_vec();
            writers.push(std::thread::spawn(move || {
                barrier.wait();
                spool.enqueue(&body)
            }));
        }
        barrier.wait();
        let results: Vec<_> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(SpoolError::CapacityExceeded { .. })))
                .count(),
            1
        );
        assert_eq!(spool.stats().unwrap().bytes, 4);
    }
}
