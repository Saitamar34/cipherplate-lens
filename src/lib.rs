//! CipherPlate Lens (Relais Optique Sécurisé Mobile)
//!
//! Ce module constitue l'application mobile (iOS & Android) dédiée à la lecture
//! optique haute fidélité des matrices physiques de secrets PRA.
//!
//! Principe Zéro Trust & Cloisonnement strict :
//! - Le relais mobile n'effectue AUCUN déchiffrement de secret maître.
//! - Il n'intègre aucune fonction de partage de secret Shamir ni accès YubiKey.
//! - Il transmet la trame chiffrée brute au Terminal Desktop souverain.
//! - Il notifie en temps réel le canal SOC/RSSI via Webhook Microsoft Teams.

pub mod pairing;
pub mod transport;
pub mod outbox;
pub mod webhook;

use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

use pairing::{parse_pairing_code, PairingSession};
use transport::{send_payload_to_terminal, TransportReceipt};
use outbox::MobileOutboxManager;

/// Entrée d'historique des opérations du relais optique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeLogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

/// État global partagé en mémoire de l'application relais.
#[derive(Clone)]
pub struct BridgeState {
    pub session: Arc<Mutex<Option<PairingSession>>>,
    pub logs: Arc<Mutex<Vec<BridgeLogEntry>>>,
    pub outbox: MobileOutboxManager,
}

impl BridgeState {
    pub fn new() -> Self {
        Self {
            session: Arc::new(Mutex::new(None)),
            logs: Arc::new(Mutex::new(vec![BridgeLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                level: "INFO".into(),
                message: "Relais Optique initialisé. En attente d'appairage avec le Terminal PRA.".into(),
            }])),
            outbox: MobileOutboxManager::new(),
        }
    }

    pub fn log(&self, level: &str, message: &str) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(BridgeLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                level: level.to_string(),
                message: message.to_string(),
            });
            // Conserver au maximum les 100 derniers logs
            if logs.len() > 100 {
                logs.remove(0);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Commandes Tauri invoquées depuis l'interface mobile
// -----------------------------------------------------------------------------

#[tauri::command]
fn pair_terminal(
    state: tauri::State<'_, BridgeState>,
    pairing_input: String,
) -> Result<PairingSession, String> {
    let session = parse_pairing_code(&pairing_input)?;
    state.log(
        "SUCCESS",
        &format!("Appairage validé avec le Terminal [{}]", session.display_host),
    );
    *state.session.lock().unwrap() = Some(session.clone());
    Ok(session)
}

#[tauri::command]
fn get_pairing_status(state: tauri::State<'_, BridgeState>) -> Option<PairingSession> {
    state.session.lock().unwrap().clone()
}

#[tauri::command]
async fn transmit_scanned_payload(
    state: tauri::State<'_, BridgeState>,
    raw_payload_hex: String,
) -> Result<TransportReceipt, String> {
    let session = state
        .session
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Aucun Terminal appairé. Scannez d'abord le QR code du poste PRA.".to_string())?;

    let clean_hex = raw_payload_hex.trim().to_lowercase();
    let bytes_len = clean_hex.len() / 2;

    state.log(
        "INFO",
        &format!("Trame scannée ({} octets). Transfert sécurisé...", bytes_len),
    );

    // Transfert sécurisé vers le Terminal Desktop local
    let receipt_result = send_payload_to_terminal(&session, &clean_hex).await;

    match receipt_result {
        Ok(receipt) => {
            state.log(
                "SUCCESS",
                &format!("Matrice transmise avec succès au Terminal [{}]", session.display_host),
            );

            if !receipt.desktop_will_notify {
                // Le Desktop n'a pas de connexion WAN (Ethernet débranché ou isolé)
                // Le mobile prend la relève d'alerte immédiate via réseau cellulaire 4G/5G !
                if let Some(ref wh) = session.webhook_url {
                    state.log(
                        "WARN",
                        "Terminal PRA hors-ligne WAN : Notification SOC prise en charge par le relais mobile 4G..."
                    );
                    let outbox = state.outbox.clone();
                    let alert_id = receipt.alert_id.clone();
                    let host = session.display_host.clone();
                    let fp = receipt.payload_fingerprint.clone();
                    let wh_url = wh.clone();

                    tauri::async_runtime::spawn(async move {
                        let _ = outbox.enqueue_and_dispatch(
                            &alert_id,
                            "SCAN OPTIQUE MATRICE (RELAIS MOBILE 4G/5G - POSTE PRA ISOLÉ)",
                            &host,
                            &fp,
                            bytes_len,
                            &wh_url,
                        ).await;
                    });
                }
            } else {
                state.log(
                    "INFO",
                    "Notification SOC prise en charge par le Terminal PRA (Consensus Anti-Doublon).",
                );
            }

            Ok(receipt)
        }
        Err(err) => {
            // Le Terminal est totalement injoignable (ex: Wi-Fi coupé ou poste éteint par rogue admin)
            // Le mobile ne perd JAMAIS l'alerte !
            if let Some(ref wh) = session.webhook_url {
                state.log(
                    "WARN",
                    "Terminal PRA injoignable : Consignation d'alerte en file Outbox cellulaire..."
                );
                let fallback_alert_id = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(format!("{}:terminal_unreachable", clean_hex).as_bytes()));
                let payload_fp = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(clean_hex.as_bytes()));
                let outbox = state.outbox.clone();
                let host = session.display_host.clone();
                let wh_url = wh.clone();

                tauri::async_runtime::spawn(async move {
                    let _ = outbox.enqueue_and_dispatch(
                        &fallback_alert_id,
                        "TENTATIVE SCAN MATRICE (TERMINAL PRA INJOIGNABLE)",
                        &host,
                        &payload_fp,
                        bytes_len,
                        &wh_url,
                    ).await;
                });
            }

            state.log("ERROR", &format!("Échec transmission : {}", err));
            Err(err)
        }
    }
}

#[tauri::command]
fn get_bridge_logs(state: tauri::State<'_, BridgeState>) -> Vec<BridgeLogEntry> {
    state.logs.lock().unwrap().clone()
}

#[tauri::command]
fn clear_session(state: tauri::State<'_, BridgeState>) {
    *state.session.lock().unwrap() = None;
    state.log("INFO", "Session d'appairage réinitialisée.");
}

// -----------------------------------------------------------------------------
// Point d'entrée de l'application (Tauri v2 Mobile & Desktop)
// -----------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = BridgeState::new();
    state.outbox.clone().start_background_drainer();

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            pair_terminal,
            get_pairing_status,
            transmit_scanned_payload,
            get_bridge_logs,
            clear_session
        ])
        .run(tauri::generate_context!())
        .expect("Erreur lors de l'exécution de CipherPlate Lens");
}
