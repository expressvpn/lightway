use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead as _, BufReader, Read},
    path::Path,
};

use anyhow::{Context, Result, anyhow};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use lightway_core::LightwayFeature;
use pwhash::unix;

use lightway_server::{ServerAuth, ServerAuthHandle, ServerAuthResult};

/// Validates username characters.
/// Allows alphanumeric characters, underscores, hyphens, and periods.
/// Maximum length is 50 bytes (as per wire protocol).
pub fn is_valid_username(username: &str) -> bool {
    if username.is_empty() || username.len() > 50 {
        return false;
    }
    username.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
    })
}

pub struct Auth {
    user_db: Option<HashMap<String, String>>,
    token: Option<(DecodingKey, Validation)>,
}

fn user_db_from_reader(r: impl Read) -> Result<HashMap<String, String>> {
    let f = BufReader::new(r);
    let db: HashMap<String, String> = f
        .lines()
        .enumerate()
        .map(|(nr, line)| {
            let line = match line {
                Ok(line) => line,
                Err(err) => return Err(anyhow!(err)),
            };

            let Some((user, hash)) = line.split_once(":") else {
                return Err(anyhow!("Failed to parse line {}", nr + 1));
            };

            if user.is_empty() {
                return Err(anyhow!("No user found in line {}", nr + 1));
            }
            if hash.is_empty() {
                return Err(anyhow!("No password hash found in line {}", nr + 1));
            }

            Ok((user.to_string(), hash.to_string()))
        })
        .collect::<Result<_>>()?;

    if db.is_empty() {
        return Err(anyhow!("No users found in user db"));
    }

    Ok(db)
}

fn token_from_reader(mut r: impl Read) -> Result<(DecodingKey, Validation)> {
    let mut decoding_key = Vec::new();
    r.read_to_end(&mut decoding_key)?;
    let decoding_key = DecodingKey::from_rsa_pem(&decoding_key)?;

    let validation = Validation::new(Algorithm::RS256);

    Ok((decoding_key, validation))
}

impl Auth {
    pub fn new(user_db: Option<&Path>, token_rsa_pub_key_pem: Option<&Path>) -> Result<Self> {
        let user_db = user_db
            .map(|path| -> Result<_> {
                user_db_from_reader(File::open(path)?)
                    .with_context(|| format!("Parsing {}", path.display()))
            })
            .transpose()?;

        let token = token_rsa_pub_key_pem
            .map(|path| {
                token_from_reader(File::open(path)?)
                    .with_context(|| format!("Parsing {}", path.display()))
            })
            .transpose()?;

        if user_db.is_none() && token.is_none() {
            return Err(anyhow!("Neither user db nor token public key provided"));
        }

        Ok(Self { user_db, token })
    }
}

#[derive(Debug)]
struct AuthHandle;

impl ServerAuthHandle for AuthHandle {
    fn expired(&self) -> bool {
        false
    }

    fn features(&self) -> HashSet<LightwayFeature> {
        HashSet::from([LightwayFeature::InsidePktCodec])
    }
}

impl<AS> ServerAuth<AS> for Auth {
    fn authorize_user_password(
        &self,
        user: &str,
        password: &str,
        _app_state: &mut AS,
    ) -> ServerAuthResult {
        // Validate username format before any other processing
        if !is_valid_username(user) {
            tracing::info!("Authentication failed");
            return ServerAuthResult::Denied;
        }

        let Some(user_db) = self.user_db.as_ref() else {
            return ServerAuthResult::Denied;
        };

        // Always verify password to prevent timing attacks.
        // If user not found, use a fake hash so verification takes same time.
        // This prevents attackers from determining valid usernames via timing.
        // Using a known invalid bcrypt format that still requires computation
        static FAKE_HASH: &str = "$2y$05$ffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let hash = user_db.get(user).map(|s| s.as_str()).unwrap_or(FAKE_HASH);

        if unix::verify(password, hash) {
            // User was found and password matched
            let _ = user_db.get(user); // Ensure we actually looked up the user
            ServerAuthResult::Granted {
                handle: Some(Box::new(AuthHandle)),
                tunnel_protocol_version: None,
            }
        } else {
            tracing::info!("Authentication failed");
            ServerAuthResult::Denied
        }
    }

    fn authorize_token(&self, token: &str, _app_state: &mut AS) -> ServerAuthResult {
        let Some((decoding_key, token_validation)) = self.token.as_ref() else {
            return ServerAuthResult::Denied;
        };

        match jsonwebtoken::decode::<serde_json::Value>(token, decoding_key, token_validation) {
            Ok(_) => ServerAuthResult::Granted {
                handle: Some(Box::new(AuthHandle)),
                tunnel_protocol_version: None,
            },
            Err(_) => {
                tracing::info!("Authentication failed");
                ServerAuthResult::Denied
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        ops::{Add, Sub},
    };

    use lightway_core::LightwayFeature;
    use serde_json::json;
    use test_case::test_case;

    use super::*;

    #[test_case(b"" => panics "No users found in user db")]
    #[test_case(b"xxx" => panics "Failed to parse line 1")]
    #[test_case(b":hash" => panics "No user found in line 1")]
    #[test_case(b"user:" => panics "No password hash found in line 1")]
    #[test_case(b"user:hash\n" => 1)]
    #[test_case(b"user:hash\nanother:user" => 2)]
    #[test_case(b"user:hash\nuser:hash2" => 1)]
    #[test_case(b"\xc3\x28" => panics "stream did not contain valid UTF-8")]
    fn parsing_password_files(db: &[u8]) -> usize {
        let db = user_db_from_reader(Cursor::new(db)).unwrap();
        db.len()
    }

    // Contains:
    // bcrypt_user: bcrypt_password
    // sha256_user: sha256_password
    // sha512_user: sha512_password
    // bad_hash_user: Not valid
    // apachemd5_user: apachemd5_password
    // no
    const LWPASSWD: &str = r"bcrypt_user:$2y$05$sLC0IaxaPbphGjLzmTEb8eDL9NL/tiBfA7OTVpa1CfDkUkW9CVTuO
sha256_user:$5$iossVgDQrSn1S35f$A08tsmhi863Ir5vJEbF1iHjnDOc8lpspzYxKWzY4Uy7
sha512_user:$5$Syjorkmkhi4MiC22$ssGjWYeevMgdkskpduH1nWbmC4suxQNUl82SYJ2XK42
bad_hash_user:NOT A HASH
apachemd5_user:$apr1$dzIISjZV$itIp3R9OU32h.vQ0tm9rm/";
    #[test_case("bcrypt_user", "bcrypt_password" => matches ServerAuthResult::Granted{..} )]
    #[test_case("sha256_user", "sha256_password" => matches ServerAuthResult::Granted{..} )]
    #[test_case("sha512_user", "sha512_password" => matches ServerAuthResult::Granted{..} )]
    #[test_case("bad_hash_user", "n/a" => matches ServerAuthResult::Denied )]
    #[test_case("apachemd5_user", "apachemd5_passwd" => matches ServerAuthResult::Denied )]
    fn user_pass_auth(user: &str, pass: &str) -> ServerAuthResult {
        let db = user_db_from_reader(Cursor::new(LWPASSWD)).unwrap();
        assert_eq!(db.len(), 5);
        let auth = Auth {
            user_db: Some(db),
            token: None,
        };
        auth.authorize_user_password(user, pass, &mut ())
    }

    #[test_case("bcrypt_user", "bcrypt_password")]
    fn user_pass_auth_can_use_inside_pkt_encoding(user: &str, pass: &str) {
        let db = user_db_from_reader(Cursor::new(LWPASSWD)).unwrap();
        assert_eq!(db.len(), 5);
        let auth = Auth {
            user_db: Some(db),
            token: None,
        };
        let r = auth.authorize_user_password(user, pass, &mut ());
        assert!(
            matches!(r, ServerAuthResult::Granted { handle: Some(ref handle), .. } if handle
                .features()
                .contains(&LightwayFeature::InsidePktCodec))
        );
    }

    #[test]
    fn no_user_db() {
        let auth = Auth {
            user_db: None,
            token: None,
        };
        let r = auth.authorize_user_password("user", "pass", &mut ());
        assert!(matches!(r, ServerAuthResult::Denied));
    }

    // Private half of `RSA_PUB`
    const RSA_PRIV: &[u8] = br"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCr9RWsZD9v5itr
udEFa5gVj/iX91IRxLy9a9NGiZUd6VBUo4S678RuO9hVLXNfkrzW+RKKPSFeYuvK
GMvZ6UaRrkGXX6AN46Vmql0EMZIPwvj9TxlFF62NBFpBVP/+daG+Lgx8/Rm7nghB
6O+PVTaUxzktZu1tJ/ORIR+/c0y3AST9tflhkX1VJQ5zOvTfNiwkNQiSME+SvE6p
0RPQYDBOjUY/Mfn4BlMxlYxmFHuZC/9aAzJLUlvEbJpKBOx3mdUyhJgzUNleXdIE
MeKIiT1FjLR+xpiS5dKF1ARtv0WZeHy8nYKrL/sToE2fX2/paF7bLtmTmksxhdHl
dPX9GzaFAgMBAAECggEAR4fWEjZJZUT7/v33Ayg0xZN0N9L74sRSNwGpi4gj7aNm
dS7oQdMHhUuDvDsB6VnjEBHgMn0naln/97vE4Mr3Phac1llC/UQbQ8/OjbYJKmFS
rhy/SEyHN0f+O3seWj2YoMILE9s9XxxoFvLM5HTwFYeiM07DqUqbOV3sFPnjiaRS
5FGkWMC/a6cB4qv2KMN/ebWbhXFSp7XC74fL+KZ+zOMB6xAWwZOd35J/qjPb/4Hq
9vhQxAaZ4cvlAz+i20wHEynzsI8QbcLUOCD7m67ieODDjc8GyYEwU/r8bTnQAoMm
g1+On1B4SsTXaus90k8G3H8flXYPB9wg589EfWZ4AQKBgQDmupePw9cF1KLDKm8w
BhGzaf3EYdWYwF7onmmfAISyGOE4TmHE9xzMnmIJfXXD0ohIdQPGJluv0Y7A2o5z
kFYPplqRFXRU4EqYkpgVkkeYXOQlnCRDP6hZ+BsWMmqPgag4bDmGbORmdD/8KsQO
qCupHAZv/TWf0J+o+D6ux/gBhQKBgQC+ypkQLbqKUQb79SXomZKss3tylhAUIikD
W8da9yk7R+3CuSWuB5g6pvR9jLFdgKHaYbouLv+X5+tmxLPPIrwnEIoyI3Ny7Lzy
KXPnUuWnnY++qHb7V3wbLwSE6FFgIW/pgRtqqnFyOTLPjS9KNxGdsW3mfhgm9Ne6
pZSq0HHxAQKBgCTZmklAyv/IZTJsfZOa9IrGG9yYj4e0+bOHUXEuoQLczGO0yRKv
MO9RQHEpk3xyDIgeADtOdwhOnNEaVvQIEmavd/mCBrFjnSZfC2Eumrav51RGatg+
u4GbCaBy7uf6mkZgqpNYouXmHS4GGogIvehlbHXIaB8dL9LJyyEZGPgNAoGBALGk
OXfS3AjFANe/nZhAxUx/oMVD65yTYdR6s9eCoaVMh5fyg57R+29A3Au537rLdee7
bnpp0BlEGu4I39JQ6RcGU2XzlB7BRfvDlOMhUCsMjTZb7MyA3FEDKhYFqR70gxrK
1xgtsotDroeJUSqss348IbOmXB6JggOLAC06/5wBAoGBAKxqzmiSzDgpGsHRhX7t
7uHKNcGNUhlF7JeH2rGB13FIOSFuDS0hNkgG2OSSlgYaWoEdGKzZn0S/Ng965rOg
FY/lOaZSY2SMD49txFPGDpX6Nz74vicgHjpofgOZ4KGxGvUbsJqzS37Yu5AhS2k/
Q+0W9vE88wLsQX6WvzJsMv3d
-----END PRIVATE KEY-----";
    // Public half of `RSA_PRIV`
    const RSA_PUB: &[u8] = br"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq/UVrGQ/b+Yra7nRBWuY
FY/4l/dSEcS8vWvTRomVHelQVKOEuu/EbjvYVS1zX5K81vkSij0hXmLryhjL2elG
ka5Bl1+gDeOlZqpdBDGSD8L4/U8ZRRetjQRaQVT//nWhvi4MfP0Zu54IQejvj1U2
lMc5LWbtbSfzkSEfv3NMtwEk/bX5YZF9VSUOczr03zYsJDUIkjBPkrxOqdET0GAw
To1GPzH5+AZTMZWMZhR7mQv/WgMyS1JbxGyaSgTsd5nVMoSYM1DZXl3SBDHiiIk9
RYy0fsaYkuXShdQEbb9FmXh8vJ2Cqy/7E6BNn19v6Whe2y7Zk5pLMYXR5XT1/Rs2
hQIDAQAB
-----END PUBLIC KEY-----";

    // Public key unrelated to `RSA_PRIV` or `RSA_PUB`
    const RSA_PUB_ALT: &[u8] = br"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl99/d+yh0uDxiq4HjX8C
ucICUBiRXc9lJvOisW520v5kd4Swpcw5uG9bHYYjrjCSb5+kTuDS65fSqn+C+rNF
mU+z9/dGRFMOHqR7lKs934384SCBl1Vd3whprdUqqgGMUfr2fyue8PunynEBl6jx
5asHdfX4qjF+xHq4RXGvqzY3tYPu4jZff4cVb4f3Xr7x/6NSS7QeECfPenj5/upD
6VxeAFHvK4X46Cz8PUVaWWTUZm3Zigk2j+gDuyxhNRYbwKJhasCzExbWn7vOVYIk
wRoXWMsATFfJQQuIWQR0JnrZfAVMickXuS4s75oOgIqYZ6/vlDqoMWnuQRkfvcIf
wwIDAQAB
-----END PUBLIC KEY-----";

    fn make_token<T: serde::Serialize>(alg: Algorithm, claims: T) -> String {
        use jsonwebtoken::{EncodingKey, Header};

        let header = Header::new(alg);

        let key = match alg {
            Algorithm::RS256 => EncodingKey::from_rsa_pem(RSA_PRIV).unwrap(),
            Algorithm::HS256 => EncodingKey::from_secret(b""),
            _ => panic!("Unknown alg"),
        };

        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    fn future_timestamp() -> i64 {
        time::OffsetDateTime::now_utc()
            .add(time::Duration::minutes(6))
            .unix_timestamp()
    }

    fn past_timestamp() -> i64 {
        time::OffsetDateTime::now_utc()
            .sub(time::Duration::minutes(6))
            .unix_timestamp()
    }

    #[test_case(RSA_PUB, &make_token(Algorithm::RS256, json!({"exp": future_timestamp()})) => matches ServerAuthResult::Granted{ .. })]
    #[test_case(RSA_PUB, &make_token(Algorithm::RS256, json!({"exp": past_timestamp()})) => matches ServerAuthResult::Denied)]
    #[test_case(RSA_PUB, &make_token(Algorithm::RS256, json!({})) => matches ServerAuthResult::Denied)]
    #[test_case(RSA_PUB, &make_token(Algorithm::HS256, json!({"esp": future_timestamp()})) => matches ServerAuthResult::Denied)]
    #[test_case(RSA_PUB_ALT, &make_token(Algorithm::HS256, json!({"esp": future_timestamp()})) => matches ServerAuthResult::Denied)]
    fn token_auth(pubkey: &[u8], token: &str) -> ServerAuthResult {
        let auth = Auth {
            user_db: None,
            token: Some(token_from_reader(Cursor::new(pubkey)).unwrap()),
        };
        auth.authorize_token(token, &mut ())
    }

    #[test]
    fn token_auth_can_use_inside_pkt_encoding() {
        let auth = Auth {
            user_db: None,
            token: Some(token_from_reader(Cursor::new(RSA_PUB)).unwrap()),
        };
        let token = &make_token(Algorithm::RS256, json!({"exp": future_timestamp()}));
        let r = auth.authorize_token(token, &mut ());
        assert!(
            matches!(r, ServerAuthResult::Granted { handle: Some(ref handle), .. } if handle
                .features()
                .contains(&LightwayFeature::InsidePktCodec))
        );
    }

    #[test]
    fn no_token() {
        let auth = Auth {
            user_db: None,
            token: None,
        };
        let r = auth.authorize_token(&make_token(Algorithm::RS256, json!({})), &mut ());
        assert!(matches!(r, ServerAuthResult::Denied));
    }

    #[test_case("" => false; "empty")]
    #[test_case("a" => true; "single_char")]
    #[test_case("user123" => true; "alphanumeric")]
    #[test_case("user_name" => true; "with_underscore")]
    #[test_case("user-name" => true; "with_hyphen")]
    #[test_case("user.name" => true; "with_period")]
    #[test_case("User.Name-123_test" => true; "mixed_valid_chars")]
    #[test_case("user@name" => false; "invalid_at_sign")]
    #[test_case("user/name" => false; "invalid_slash")]
    #[test_case("user name" => false; "invalid_space")]
    #[test_case("user\tname" => false; "invalid_tab")]
    #[test_case("日本語" => false; "unicode")]
    #[test_case("abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab" => true; "max_length_50")]
    #[test_case("abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc" => false; "too_long_51")]
    fn test_username_validation(username: &str) -> bool {
        is_valid_username(username)
    }
}
