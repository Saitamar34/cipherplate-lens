//! File d'attente d'alerte mobile persistante (Store & Forward Outbox).
//!
//! Assure la résilience contre les attaques de type Rogue Admin :
//! Si le terminal Desktop est débranché du réseau WAN ou si le réseau cellulaire
//! mobile est temporairement brouillé ou coupé, l'alerte de sécurité est stockée
//! localement de manière persistante.
//! Dès restauration du réseau cellulaire (4G/5G) ou Wi-Fi, le worker d'arrière-plan
//! transmet immédiatement l'alerte rétroactive au canal SOC Teams avec l'ID d'idempotence.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Entrée d'alerte en file persistante mobile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileOutboxEntry {
    pub id: String,
    pub event_type: String,
    pub original_timestamp_utc: String,
    pub terminal_host: String,
    pub payload_fingerprint: String,
    pub payload_bytes_len: usize,
    pub webhook_url: String,
    pub status: String, // "PENDING", "FAILED_RETRYING", "DELIVERED"
    pub retry_count: u32,
    pub delivered_at: Option<String>,
}

/// Gestionnaire de la file Outbox mobile.
#[derive(Clone)]
pub struct MobileOutboxManager {
    file_path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl MobileOutboxManager {
    pub fn new() -> Self {
        let base_dir = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let dir = base_dir.join(".cipherplate_lens");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("lens_outbox.jsonl");

        Self {
            file_path,
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// Enregistre une alerte et tente un envoi immédiat.
    pub async fn enqueue_and_dispatch(
        &self,
        alert_id: &str,
        event_type: &str,
        terminal_host: &str,
        payload_fingerprint: &str,
        payload_bytes_len: usize,
        webhook_url: &str,
    ) -> bool {
        let mut entry = {
            let _guard = self.lock.lock().unwrap();
            let now = chrono::Utc::now().to_rfc3339();

            let entry = MobileOutboxEntry {
                id: alert_id.to_string(),
                event_type: event_type.to_string(),
                original_timestamp_utc: now,
                terminal_host: terminal_host.to_string(),
                payload_fingerprint: payload_fingerprint.to_string(),
                payload_bytes_len,
                webhook_url: webhook_url.to_string(),
                status: "PENDING".to_string(),
                retry_count: 0,
                delivered_at: None,
            };

            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.file_path)
            {
                if let Ok(line) = serde_json::to_string(&entry) {
                    let _ = writeln!(file, "{}", line);
                }
            }
            entry
        };

        // Tentative immédiate d'envoi en direct
        let delivered = Self::dispatch_entry(&mut entry).await;
        self.update_entry(&entry);
        delivered
    }

    /// Lit toutes les entrées enregistrées.
    pub fn read_all(&self) -> Vec<MobileOutboxEntry> {
        let _guard = self.lock.lock().unwrap();
        if !self.file_path.exists() {
            return Vec::new();
        }

        let file = match File::open(&self.file_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines().flatten() {
            if let Ok(entry) = serde_json::from_str::<MobileOutboxEntry>(&line) {
                entries.push(entry);
            }
        }
        entries
    }

    /// Met à jour une entrée dans le fichier persistant.
    pub fn update_entry(&self, updated: &MobileOutboxEntry) {
        let _guard = self.lock.lock().unwrap();
        if !self.file_path.exists() {
            return;
        }

        let mut entries = Vec::new();
        if let Ok(file) = File::open(&self.file_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if let Ok(e) = serde_json::from_str::<MobileOutboxEntry>(&line) {
                    if e.id == updated.id {
                        entries.push(updated.clone());
                    } else {
                        entries.push(e);
                    }
                }
            }
        }

        if let Ok(mut file) = File::create(&self.file_path) {
            for e in entries {
                if let Ok(line) = serde_json::to_string(&e) {
                    let _ = writeln!(file, "{}", line);
                }
            }
        }
    }

    /// Tente d'expédier une entrée vers le Webhook Microsoft Teams.
    pub async fn dispatch_entry(entry: &mut MobileOutboxEntry) -> bool {
        let now_utc = chrono::Utc::now();
        let original_dt = chrono::DateTime::parse_from_rfc3339(&entry.original_timestamp_utc)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or(now_utc);

        let delay_seconds = (now_utc - original_dt).num_seconds();
        let is_delayed = delay_seconds > 15;

        let delay_notice = if is_delayed {
            let mins = delay_seconds / 60;
            let secs = delay_seconds % 60;
            format!("⚠️ ALERTE RÉTROACTIVE ÉMISE APRÈS COUPURE CELLULAIRE (Retardée de {}m {}s)", mins, secs)
        } else {
            "⚡ Alerte temps réel (Liaison cellulaire active)".into()
        };

        let card = serde_json::json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "🚨 Alerte Sécurité PRA · Lecture Optique Déclenchée",
            "themeColor": if is_delayed { "D83B01" } else { "E81123" },
            "title": if is_delayed {
                "🚨 [RÉTROACTIF] LECTURE OPTIQUE PRA DÉTECTÉE APRÈS COUPURE"
            } else {
                "🚨 PROCÉDURE PRA DÉCLENCHÉE · LECTURE OPTIQUE DE PLAQUE"
            },
            "sections": [
                {
                    "activityTitle": "Système de Continuité d'Activité (PCA / PRA)",
                    "activitySubtitle": delay_notice,
                    "activityImage": "https://img.icons8.com/color/96/shield.png",
                    "facts": [
                        { "name": "ID Unique Quittance (Idempotence) :", "value": &entry.id },
                        { "name": "Événement :", "value": &entry.event_type },
                        { "name": "Horodatage Initial (Scan Optique) :", "value": &entry.original_timestamp_utc },
                        { "name": "Horodatage de Transmission au SOC :", "value": &now_utc.to_rfc3339() },
                        { "name": "Terminal Destinataire :", "value": &entry.terminal_host },
                        { "name": "Volume Trame :", "value": format!("{} octets", entry.payload_bytes_len) },
                        { "name": "Empreinte Trame (SHA-256) :", "value": &entry.payload_fingerprint },
                        { "name": "Canal d'Émission :", "value": "Relais Mobile CipherPlate Lens (4G/5G Cellulaire)" },
                        { "name": "Statut File Outbox :", "value": if is_delayed { "Livré après reconnexion cellulaire" } else { "Livraison directe réussie" } }
                    ],
                    "markdown": true
                }
            ]
        });

        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(6))
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        match client.post(&entry.webhook_url).json(&card).send().await {
            Ok(resp) if resp.status().is_success() => {
                entry.status = "DELIVERED".into();
                entry.delivered_at = Some(now_utc.to_rfc3339());
                true
            }
            _ => {
                entry.retry_count += 1;
                entry.status = "FAILED_RETRYING".into();
                false
            }
        }
    }

    /// Démarre le worker d'arrière-plan autonome qui draine la file d'attente mobile.
    pub fn start_background_drainer(self) {
        std::thread::spawn(move || {
            loop {
                let pending: Vec<MobileOutboxEntry> = self
                    .read_all()
                    .into_iter()
                    .filter(|e| e.status != "DELIVERED" && e.retry_count < 100)
                    .collect();

                if !pending.is_empty() {
                    for mut entry in pending {
                        let self_clone = self.clone();
                        tauri::async_runtime::block_on(async {
                            let ok = Self::dispatch_entry(&mut entry).await;
                            self_clone.update_entry(&entry);
                            if ok {
                                println!("[LENS OUTBOX] Alerte #{} délivrée avec succès vers Teams.", entry.id);
                            }
                        });
                    }
                }

                // Sommeil entre deux vérifications de connectivité (10 secondes)
                std::thread::sleep(Duration::from_secs(10));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_outbox_persistence() {
        let temp_dir = std::env::temp_dir().join(format!("test_lens_outbox_{}", hex::encode(rand::random::<[u8; 4]>())));
        let _ = std::fs::create_dir_all(&temp_dir);
        let file_path = temp_dir.join("lens_outbox.jsonl");

        let manager = MobileOutboxManager {
            file_path: file_path.clone(),
            lock: Arc::new(Mutex::new(())),
        };

        let now = chrono::Utc::now().to_rfc3339();
        let entry = MobileOutboxEntry {
            id: "test_alert_123".into(),
            event_type: "TEST_EVENT".into(),
            original_timestamp_utc: now,
            terminal_host: "192.168.1.50:8765".into(),
            payload_fingerprint: "abc123def456".into(),
            payload_bytes_len: 256,
            webhook_url: "https://example.com/webhook".into(),
            status: "PENDING".into(),
            retry_count: 0,
            delivered_at: None,
        };

        // Écriture
        {
            let mut file = OpenOptions::new().create(true).append(true).open(&file_path).unwrap();
            let line = serde_json::to_string(&entry).unwrap();
            writeln!(file, "{}", line).unwrap();
        }

        // Lecture
        let entries = manager.read_all();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "test_alert_123");
        assert_eq!(entries[0].status, "PENDING");

        // Mise à jour
        let mut updated = entries[0].clone();
        updated.status = "DELIVERED".into();
        manager.update_entry(&updated);

        let entries_after = manager.read_all();
        assert_eq!(entries_after.len(), 1);
        assert_eq!(entries_after[0].status, "DELIVERED");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

