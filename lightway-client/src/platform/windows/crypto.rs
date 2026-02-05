use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use std::fs;
use std::path::Path;
#[cfg(windows)]
use windows_dpapi::{Scope, decrypt_data, encrypt_data};

#[cfg(windows)]
pub fn decrypt_dpapi_config_file(encrypted_path: &Path, scope: Scope) -> Result<String> {
    let b64_text = fs::read_to_string(encrypted_path)?;
    let encrypted_bytes = general_purpose::STANDARD.decode(b64_text.trim())?;
    let decrypted_bytes = decrypt_data(&encrypted_bytes, scope)?;
    Ok(String::from_utf8(decrypted_bytes)?)
}

#[cfg(windows)]
pub fn encrypt_dpapi_config_file(output_path: &Path, content: &str, scope: Scope) -> Result<()> {
    let encrypted = encrypt_data(content.as_bytes(), scope)?;
    let base64_text = general_purpose::STANDARD.encode(&encrypted);
    fs::write(output_path, base64_text)?;
    Ok(())
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn generate_mock_config() -> String {
        r#"
        {
            "server": "vpn.example.com",
            "username": "user1",
            "password": "securepassword"
        }
        "#
        .to_string()
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
