//! Module d'appairage sécurisé (Pairing) entre le Relais Optique et le Terminal PRA.
//!
//! L'appairage permet au relais mobile de découvrir l'adresse locale du terminal
//! et d'échanger un jeton d'authentification (X-Token) ainsi qu'une clé éphémère
//! de chiffrement en transit (AES-256-GCM).
//!
//! Conformément au principe de moindre privilège, le relais optique ne détient
//! aucun secret de déchiffrement de la plaque.

use serde::{Deserialize, Serialize};

/// Session d'appairage active avec le terminal de déchiffrement Desktop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingSession {
    /// URL complète de destination du terminal (ex: "https://192.168.1.34:8765/api/scan")
    pub endpoint_url: String,
    /// Adresse IP ou nom d'hôte affiché à l'opérateur
    pub display_host: String,
    /// Jeton de session éphémère transmis dans le header HTTP `X-Token`
    pub token: String,
    /// Clé éphémère AES-256-GCM (32 octets) pour le chiffrement en transit sur le réseau local
    #[serde(skip_serializing)]
    pub transit_key: Option<[u8; 32]>,
    /// Clé en hexadécimal pour sérialisation sécurisée
    pub transit_key_hex: Option<String>,
    /// URL du Webhook de sécurité transmise par le Terminal PRA (verrouillée par l'entreprise)
    pub webhook_url: Option<String>,
    /// Horodatage de l'appairage (ISO 8601 UTC)
    pub paired_at: String,
}

/// Analyse une chaîne de caractères issue d'un scan de QR code d'appairage.
///
/// Prend en charge :
/// 1. Les URLs souveraines générées par le Desktop :
///    `https://192.168.1.34:8765/scanner?t=a7b8...#key=f0e1...`
/// 2. Les formats d'appairage directs en JSON :
///    `{"endpoint":"https://...","token":"...","key":"..."}`
pub fn parse_pairing_code(input: &str) -> Result<PairingSession, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Code d'appairage vide".into());
    }

    let now_utc = chrono::Utc::now().to_rfc3339();

    // 1. Décodage format JSON direct
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let endpoint = v.get("endpoint")
                .and_then(|s| s.as_str())
                .ok_or_else(|| "Champ 'endpoint' manquant dans le JSON d'appairage".to_string())?;
            let token = v.get("token")
                .and_then(|s| s.as_str())
                .ok_or_else(|| "Champ 'token' manquant dans le JSON d'appairage".to_string())?;

            let mut transit_key = None;
            let mut transit_key_hex = None;
            if let Some(key_str) = v.get("key").and_then(|s| s.as_str()) {
                if let Ok(key_bytes) = hex::decode(key_str) {
                    if key_bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key_bytes);
                        transit_key = Some(arr);
                        transit_key_hex = Some(key_str.to_string());
                    }
                }
            }

            let webhook_url = v.get("webhook").and_then(|s| s.as_str()).map(|s| s.to_string());
            let display_host = extract_display_host(endpoint);

            return Ok(PairingSession {
                endpoint_url: endpoint.to_string(),
                display_host,
                token: token.to_string(),
                transit_key,
                transit_key_hex,
                webhook_url,
                paired_at: now_utc,
            });
        }
    }

    // 2. Décodage format URL standard CipherPlate :
    // https://192.168.1.34:8765/scanner?t=token#key=keyHex
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let (url_without_frag, fragment) = match trimmed.split_once('#') {
            Some((u, f)) => (u, Some(f)),
            None => (trimmed, None),
        };

        let mut transit_key = None;
        let mut transit_key_hex = None;
        let mut webhook_url = None;

        if let Some(frag) = fragment {
            for part in frag.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    if k == "key" {
                        if let Ok(key_bytes) = hex::decode(v) {
                            if key_bytes.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&key_bytes);
                                transit_key = Some(arr);
                                transit_key_hex = Some(v.to_string());
                            }
                        }
                    } else if k == "wh" || k == "webhook" {
                        // Décodage si encodé en hexadécimal ou chaîne directe
                        if let Ok(bytes) = hex::decode(v) {
                            if let Ok(s) = String::from_utf8(bytes) {
                                if s.starts_with("https://") {
                                    webhook_url = Some(s);
                                }
                            }
                        } else if v.starts_with("https://") {
                            webhook_url = Some(v.to_string());
                        }
                    }
                }
            }
        }

        let (base_url, query_str) = match url_without_frag.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (url_without_frag, None),
        };

        let mut token = String::new();
        if let Some(q) = query_str {
            for part in q.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    if k == "t" || k == "token" {
                        token = v.to_string();
                    }
                }
            }
        }

        if token.is_empty() {
            return Err("Jeton de session éphémère (t=...) introuvable dans l'URL".into());
        }

        let host_prefix = match base_url.find("://") {
            Some(idx) => &base_url[idx + 3..],
            None => base_url,
        };

        let host_port = host_prefix.split('/').next().unwrap_or(host_prefix);
        let scheme = if base_url.starts_with("http://") { "http" } else { "https" };
        let endpoint_url = format!("{}://{}/api/scan", scheme, host_port);
        let display_host = host_port.to_string();

        return Ok(PairingSession {
            endpoint_url,
            display_host,
            token,
            transit_key,
            transit_key_hex,
            webhook_url,
            paired_at: now_utc,
        });
    }

    Err("Format de code d'appairage non reconnu (URL ou JSON attendu)".into())
}

fn extract_display_host(url: &str) -> String {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    without_scheme.split('/').next().unwrap_or(without_scheme).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url_pairing() {
        let url = "https://192.168.1.42:8765/scanner?t=abc123token#key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let session = parse_pairing_code(url).expect("Doit parser l'URL valide");
        assert_eq!(session.endpoint_url, "https://192.168.1.42:8765/api/scan");
        assert_eq!(session.display_host, "192.168.1.42:8765");
        assert_eq!(session.token, "abc123token");
        assert!(session.transit_key.is_some());
    }
}
