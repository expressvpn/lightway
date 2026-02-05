use anyhow::Result;
use std::fs;
use std::path::Path;
use twelf::Layer;
use twelf::reexports::{serde_json, serde_yaml};
use windows_dpapi::{Scope, decrypt_data};

pub fn decrypt_dpapi_config_file(encrypted_path: &Path, scope: Scope) -> Result<String> {
    let encrypted_bytes = fs::read(encrypted_path)?;
    let decrypted_bytes = decrypt_data(&encrypted_bytes, scope)?;
    Ok(String::from_utf8(decrypted_bytes)?)
}

pub fn into_config_layer_from_dpapi(decrypted_content: String) -> Result<Layer> {
    let value: serde_json::Value = serde_yaml::from_str(&decrypted_content)?;
    Ok(Layer::CustomFn({
        let value = value.clone();
        (move || value.clone()).into()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use twelf::config;

    // test config struct
    #[config]
    #[derive(Debug, PartialEq)]
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

    #[test]
    fn test_into_config_layer_from_dpapi_creates_layer() {
        let config_str = generate_mock_config();

        let result = into_config_layer_from_dpapi(config_str);
        assert!(result.is_ok(), "Failed to create Layer from config");
    }

    #[test]
    fn test_into_config_layer_loads_config_correctly() {
        let config_str = generate_mock_config();

        let layer = into_config_layer_from_dpapi(config_str).expect("Failed to create Layer");

        let config = TestConfig::with_layers(&[layer]).expect("Failed to load config from Layer");

        assert_eq!(config.server, "vpn.example.com");
        assert_eq!(config.username, "user1");
        assert_eq!(config.password, "securepassword");
    }

    #[test]
    fn test_into_config_layer_invalid_yaml() {
        let invalid_yaml = "bad: yaml: {{{".to_string();

        let result = into_config_layer_from_dpapi(invalid_yaml);
        assert!(result.is_err(), "Should error on invalid YAML");
    }
}
