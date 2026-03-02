//! Data package storage and retrieval.
//!
//! Implements the Marti-compatible data package API for TAK client
//! file distribution. Packages are stored on disk as `{sha256}.zip`
//! with a JSON sidecar (`{sha256}.meta.json`) containing metadata.

use std::path::PathBuf;

use sha2::{Digest, Sha256};
use tokio::fs;

use crate::error::EnrollmentError;

/// Metadata for a stored data package.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageMeta {
    pub hash: String,
    pub name: String,
    pub creator_uid: String,
    pub mime_type: String,
    pub size: u64,
    pub upload_time: u64,
}

/// On-disk data package store.
///
/// Packages are content-addressed by their SHA-256 hash:
/// - `{base_dir}/{sha256}.zip` — the raw file
/// - `{base_dir}/{sha256}.meta.json` — JSON metadata sidecar
#[derive(Debug, Clone)]
pub struct DataPackageStore {
    base_dir: PathBuf,
}

/// Maximum upload size (50 MiB). Prevents disk exhaustion from oversized uploads.
const MAX_UPLOAD_SIZE: usize = 50 * 1024 * 1024;

impl DataPackageStore {
    /// Create a new store rooted at `base_dir`. Creates the directory if it doesn't exist.
    pub async fn new(base_dir: PathBuf) -> Result<Self, EnrollmentError> {
        fs::create_dir_all(&base_dir)
            .await
            .map_err(EnrollmentError::Io)?;
        Ok(Self { base_dir })
    }

    /// Store a data package. Returns the metadata (including computed hash).
    pub async fn upload(
        &self,
        data: &[u8],
        name: &str,
        creator_uid: &str,
    ) -> Result<PackageMeta, EnrollmentError> {
        if data.is_empty() {
            return Err(EnrollmentError::Config("empty upload".to_string()));
        }
        if data.len() > MAX_UPLOAD_SIZE {
            return Err(EnrollmentError::Config(format!(
                "upload exceeds {MAX_UPLOAD_SIZE} byte limit"
            )));
        }

        let hash = hex_sha256(data);
        let pkg_path = self.package_path(&hash);
        let meta_path = self.meta_path(&hash);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let meta = PackageMeta {
            hash: hash.clone(),
            name: name.to_string(),
            creator_uid: creator_uid.to_string(),
            mime_type: "application/x-zip-compressed".to_string(),
            size: data.len() as u64,
            upload_time: now,
        };

        fs::write(&pkg_path, data)
            .await
            .map_err(EnrollmentError::Io)?;

        let meta_json =
            serde_json::to_vec(&meta).map_err(|e| EnrollmentError::Config(e.to_string()))?;
        fs::write(&meta_path, &meta_json)
            .await
            .map_err(EnrollmentError::Io)?;

        tracing::info!(hash = %hash, name = %name, size = data.len(), "data package stored");

        Ok(meta)
    }

    /// Read a data package by its SHA-256 hash. Returns `(metadata, bytes)`.
    pub async fn download(&self, hash: &str) -> Result<(PackageMeta, Vec<u8>), EnrollmentError> {
        if !is_valid_hex_hash(hash) {
            return Err(EnrollmentError::Config("invalid hash format".to_string()));
        }

        let meta = self.read_meta(hash).await?;
        let data = fs::read(self.package_path(hash))
            .await
            .map_err(EnrollmentError::Io)?;

        Ok((meta, data))
    }

    /// Search packages by keyword (matches against name and creator_uid).
    pub async fn search(&self, keyword: &str) -> Result<Vec<PackageMeta>, EnrollmentError> {
        let keyword_lower = keyword.to_lowercase();
        let mut results = Vec::new();

        let mut entries = fs::read_dir(&self.base_dir)
            .await
            .map_err(EnrollmentError::Io)?;

        while let Some(entry) = entries.next_entry().await.map_err(EnrollmentError::Io)? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            // Sidecar files are named {hash}.meta.json
            let Some(hash) = stem.strip_suffix(".meta") else {
                continue;
            };

            if let Ok(meta) = self.read_meta(hash).await {
                if meta.name.to_lowercase().contains(&keyword_lower)
                    || meta.creator_uid.to_lowercase().contains(&keyword_lower)
                {
                    results.push(meta);
                }
            }
        }

        Ok(results)
    }

    async fn read_meta(&self, hash: &str) -> Result<PackageMeta, EnrollmentError> {
        let data = fs::read(self.meta_path(hash))
            .await
            .map_err(EnrollmentError::Io)?;
        serde_json::from_slice(&data).map_err(|e| EnrollmentError::Config(e.to_string()))
    }

    fn package_path(&self, hash: &str) -> PathBuf {
        self.base_dir.join(format!("{hash}.zip"))
    }

    fn meta_path(&self, hash: &str) -> PathBuf {
        self.base_dir.join(format!("{hash}.meta.json"))
    }
}

fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Validate that a hash string is a 64-character hex string (SHA-256).
fn is_valid_hex_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Extract a multipart boundary from the Content-Type header.
pub fn extract_boundary(content_type: &str) -> Option<&str> {
    content_type.split(';').find_map(|part| {
        let trimmed = part.trim();
        trimmed
            .strip_prefix("boundary=")
            .map(|b| b.trim_matches('"'))
    })
}

/// Extract a named field value from a simple multipart body.
///
/// This is a minimal parser that handles the TAK client's multipart upload
/// format. It finds the part with the given field name and returns its value.
pub fn extract_multipart_field<'a>(
    body: &'a [u8],
    boundary: &str,
    field: &str,
) -> Option<&'a [u8]> {
    let boundary_marker = format!("--{boundary}");
    let body_str = std::str::from_utf8(body).ok()?;

    let disposition_needle = format!("name=\"{field}\"");

    for part in body_str.split(&boundary_marker) {
        if !part.contains(&disposition_needle) {
            continue;
        }
        // Content starts after the first blank line (\r\n\r\n)
        let content_start = part.find("\r\n\r\n").map(|i| i + 4)?;
        let content = &part[content_start..];
        // Trim trailing \r\n before the next boundary
        let content = content.trim_end_matches("\r\n--").trim_end_matches("\r\n");
        let start = body_str.as_ptr() as usize;
        let content_ptr = content.as_ptr() as usize;
        let offset = content_ptr - start;
        return Some(&body[offset..offset + content.len()]);
    }
    None
}

/// Extract the filename from a multipart part's Content-Disposition header.
pub fn extract_multipart_filename(body: &[u8], boundary: &str) -> Option<String> {
    let body_str = std::str::from_utf8(body).ok()?;
    let boundary_marker = format!("--{boundary}");

    for part in body_str.split(&boundary_marker) {
        if let Some(pos) = part.find("filename=\"") {
            let start = pos + "filename=\"".len();
            let end = part[start..].find('"')? + start;
            return Some(part[start..end].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_sha256() {
        let hash = hex_sha256(b"hello");
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        // Known SHA-256 of "hello"
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_valid_hex_hash() {
        let good = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(is_valid_hex_hash(good));
        assert!(!is_valid_hex_hash("tooshort"));
        assert!(!is_valid_hex_hash(
            "zzzz4dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        ));
        assert!(!is_valid_hex_hash(""));
    }

    #[test]
    fn test_extract_boundary() {
        assert_eq!(
            extract_boundary("multipart/form-data; boundary=----WebKitFormBoundary123"),
            Some("----WebKitFormBoundary123")
        );
        assert_eq!(
            extract_boundary("multipart/form-data; boundary=\"abc\""),
            Some("abc")
        );
        assert_eq!(extract_boundary("application/json"), None);
    }

    #[tokio::test]
    async fn test_upload_and_download() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let data = b"PK\x03\x04fake zip content";
        let meta = store
            .upload(data, "test.zip", "user-1")
            .await
            .expect("test");

        assert_eq!(meta.name, "test.zip");
        assert_eq!(meta.creator_uid, "user-1");
        assert_eq!(meta.size, data.len() as u64);
        assert_eq!(meta.hash.len(), 64);

        let (dl_meta, dl_data) = store.download(&meta.hash).await.expect("test");
        assert_eq!(dl_data, data);
        assert_eq!(dl_meta.name, "test.zip");
    }

    #[tokio::test]
    async fn test_upload_empty_rejected() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let result = store.upload(b"", "empty.zip", "user-1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_download_invalid_hash() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let result = store.download("not-a-hash").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_download_missing() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let result = store.download(hash).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_search() {
        let dir = tempfile::tempdir().expect("test");
        let store = DataPackageStore::new(dir.path().to_path_buf())
            .await
            .expect("test");

        let _ = store
            .upload(b"pkg1-data", "mission-alpha.zip", "team-lead")
            .await
            .expect("test");
        let _ = store
            .upload(b"pkg2-data", "mission-bravo.zip", "operator")
            .await
            .expect("test");
        let _ = store
            .upload(b"pkg3-data", "overlay.kml", "team-lead")
            .await
            .expect("test");

        let results = store.search("mission").await.expect("test");
        assert_eq!(results.len(), 2);

        let results = store.search("team-lead").await.expect("test");
        assert_eq!(results.len(), 2);

        let results = store.search("overlay").await.expect("test");
        assert_eq!(results.len(), 1);

        let results = store.search("nonexistent").await.expect("test");
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_multipart_filename() {
        let body = b"--boundary\r\nContent-Disposition: form-data; name=\"assetfile\"; filename=\"test.zip\"\r\nContent-Type: application/zip\r\n\r\ndata\r\n--boundary--";
        assert_eq!(
            extract_multipart_filename(body, "boundary"),
            Some("test.zip".to_string())
        );
    }
}
