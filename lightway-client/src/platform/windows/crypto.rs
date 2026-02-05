use anyhow::Result;
use std::fs;
use std::path::Path;
use twelf::reexports::{serde_json, serde_yaml};
use windows_dpapi::{Scope, decrypt_data};

pub fn decrypt_dpapi_config_file(encrypted_path: &Path, scope: Scope) -> Result<String> {
    let encrypted_bytes = fs::read(encrypted_path)?;
    let decrypted_bytes = decrypt_data(&encrypted_bytes, scope)?;
    Ok(String::from_utf8(decrypted_bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // test config struct
    #[derive(Debug, PartialEq, serde::Serialize)]
    struct TestConfig {
        server: String,
        username: String,
        password: String,
    }

    fn generate_mock_config() -> String {
        let config = TestConfig {
            server: "vpn.example.com".to_string(),
            username: "user1".to_string(),
            password: "securepassword".to_string(),
        };
        serde_yaml::to_string(&config).unwrap()
    }
    
    // helper function to encrypt and write DPAPI config file
    fn encrypt_dpapi_config_file(output_path: &Path, content: &str, scope: Scope) -> Result<()> {
        let encrypted = windows_dpapi::encrypt_data(content.as_bytes(), scope)?;
        fs::write(output_path, encrypted)?;
        Ok(())
    }

    #[test]
    fn test_dpapi_encrypt_decrypt_with_user_scope() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let output_path = temp_dir.path().join("config.yaml.dpapi");
        let original = generate_mock_config();
        let scope = Scope::User;

        encrypt_dpapi_config_file(&output_path, &original, scope)
            .expect("Failed to encrypt into DPAPI file");
        let decrypted = decrypt_dpapi_config_file(&output_path, scope).expect("Decryption failed");

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_dpapi_encrypt_decrypt_with_machine_scope() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let output_path = temp_dir.path().join("config.yaml.dpapi");
        let original = generate_mock_config();
        let scope = Scope::Machine;

        encrypt_dpapi_config_file(&output_path, &original, scope)
            .expect("Failed to encrypt into DPAPI file");
        let decrypted = decrypt_dpapi_config_file(&output_path, scope).expect("Decryption failed");

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_dpapi_encrypted_creates_file_at_correct_path() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let output_path = temp_dir.path().join("config.yaml.dpapi");
        let original = generate_mock_config();
        let scope = Scope::User;

        assert!(
            !output_path.exists(),
            "File should not exist before encryption"
        );

        encrypt_dpapi_config_file(&output_path, &original, scope)
            .expect("Failed to encrypt into DPAPI file");

        assert!(
            output_path.exists(),
            "Encrypted file does not exist at expected path"
        );
    }
}
