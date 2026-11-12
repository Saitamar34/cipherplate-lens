//! Module de notification d'alerte de sécurité vers Microsoft Teams.
//!
//! Permet de remonter immédiatement un événement d'audit vers le canal SOC / RSSI :
//! - Formatage en "Office 365 MessageCard" / "Adaptive Card" haute visibilité.
//! - Notification asynchrone sans impact sur la réactivité optique.
//! - Strict respect de la confidentialité : SEULE l'empreinte cryptographique SHA-256
//!   de la trame est transmise, JAMAIS le secret déchiffré.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Données contextuelles de l'alerte de sécurité optique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScanAlert {
    /// Horodatage UTC de la détection optique
    pub timestamp_utc: String,
    /// Terminal de déchiffrement destinataire
    pub target_terminal: String,
    /// Identifiant du relais mobile (nom de l'appareil ou OS)
    pub device_label: String,
    /// Empreinte SHA-256 de la matrice scannée (traçabilité sans fuite de secret)
    pub payload_fingerprint: String,
    /// Taille de la charge utile scannée en octets
    pub payload_bytes_len: usize,
    /// Statut de l'opération
    pub status: String,
}

/// Émet une notification d'alerte vers le Webhook Microsoft Teams spécifié.
pub async fn send_teams_alert(
    webhook_url: &str,
    alert: &SecurityScanAlert,
) -> Result<(), String> {
    let clean_url = webhook_url.trim();
    if clean_url.is_empty() {
        return Err("URL de webhook Teams vide".into());
    }

    // Formatage MessageCard Office 365 / Microsoft Teams
    let card_payload = serde_json::json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": "🚨 Alerte Sécurité PRA · Lecture Optique Déclenchée",
        "themeColor": "D83B01", // Couleur alerte rouge/orange d'entreprise
        "title": "🚨 PROCÉDURE PRA DÉCLENCHÉE · LECTURE OPTIQUE DE PLAQUE",
        "sections": [
            {
                "activityTitle": "Système de Continuité d'Activité (PCA / PRA)",
                "activitySubtitle": format!("Détection optique validée · {}", alert.timestamp_utc),
                "activityImage": "https://img.icons8.com/color/96/shield.png",
                "facts": [
                    {
                        "name": "Événement :",
                        "value": "Scan d'un QR code de plaque physique Break-Glass"
                    },
                    {
                        "name": "Horodatage UTC :",
                        "value": alert.timestamp_utc
                    },
                    {
                        "name": "Terminal Cible :",
                        "value": alert.target_terminal
                    },
                    {
                        "name": "Relais Optique :",
                        "value": alert.device_label
                    },
                    {
                        "name": "Volume Trame :",
                        "value": format!("{} octets", alert.payload_bytes_len)
                    },
                    {
                        "name": "Empreinte SHA-256 :",
                        "value": alert.payload_fingerprint
                    },
                    {
                        "name": "Statut :",
                        "value": alert.status
                    }
                ],
                "markdown": true
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenURI",
                "name": "Consulter le Registre d'Audit Local",
                "targets": [
                    { "os": "default", "uri": alert.target_terminal }
                ]
            }
        ]
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|e| format!("Impossible d'initialiser le client HTTPS Teams : {}", e))?;

    let response = client
        .post(clean_url)
        .header("Content-Type", "application/json")
        .json(&card_payload)
        .send()
        .await
        .map_err(|e| format!("Échec d'envoi vers le Webhook Teams : {}", e))?;

    if response.status().is_success() {
        Ok(())
    } else {
        let code = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        Err(format!("Teams a retourné un statut d'erreur (HTTP {}) : {}", code, body))
    }
}
