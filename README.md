# CipherPlate Lens · Relais Optique Sécurisé (Mobile Companion)

> **Application compagnon mobile souveraine (iOS & Android) en Rust natif + Tauri v2 pour la lecture optique haute fidélité des matrices physiques de secrets PRA (Disaster Recovery).**

---

## 1. Philosophie & Principe Zéro-Trust

L'application **CipherPlate Lens** agit comme un **pont optique étanche (Optical Relay / Air-Gap Bridge)** entre la plaque physique en acier/titane gravée au laser et le terminal de déchiffrement de crise (Desktop).

### Cloisonnement strict des responsabilités :
* **AUCUN secret maître sur le smartphone** : L'application mobile ne détient aucune clé privée, aucun sel PBKDF2/HKDF, et n'effectue aucun calcul de déchiffrement ChaCha20-Poly1305.
* **AUCUNE recombinaison Shamir locale** : Le quorum $k/n$ et la validation matérielle par YubiKey physique (CTAP2/USB HID) sont réservés au poste de travail souverain.
* **Sécurité en transit (E2EE)** : Les octets scannés sont encapsulés dans un conteneur chiffré **AES-256-GCM** avec une clé de session éphémère négociée lors de l'appairage.
* **Télémesure d'audit immédiate (SecOps / RSSI)** : L'application émet en temps réel une alerte de sécurité vers un **Webhook Microsoft Teams** contenant uniquement l'empreinte cryptographique SHA-256 de la trame (traçabilité certifiée sans divulgation du secret).

```
┌────────────────────────┐         ┌────────────────────────┐         ┌────────────────────────┐
│  Plaque Métallique     │  Scan   │   CipherPlate Lens     │  HTTPS  │  Terminal PRA Desktop  │
│  Physique (QR CBOR)    │ ──────> │  (Relais Optique Rust) │ ──────> │ (YubiKey USB + Crypto) │
└────────────────────────┘ 60 fps  └───────────┬────────────┘ E2EE-LAN └────────────────────────┘
                                               │
                                               │ Webhook HTTPS
                                               ▼
                                   ┌────────────────────────┐
                                   │  Canal SecOps Teams    │
                                   │ (Alerte d'Audit Réel)  │
                                   └────────────────────────┘
```

---

## 2. Arborescence du Projet

```
crates/cipherplate-optical-bridge/
├── Cargo.toml                    # Dépendances Rust (Tauri v2, reqwest-rustls, aes-gcm, sha2, chrono)
├── build.rs                      # Script de build Tauri v2
├── tauri.conf.json               # Configuration multi-plateforme (iOS, Android, Linux, macOS, Windows)
├── README.md                     # Documentation d'architecture et guides de compilation
├── src/
│   ├── lib.rs                    # Point d'entrée mobile Tauri v2 (#[tauri::mobile_entry_point]) & commandes
│   ├── main.rs                   # Point d'entrée binaire bureau / développement local
│   ├── pairing.rs                # Décodage de l'appairage éphémère (URL souveraine / JSON)
│   ├── transport.rs              # Transport HTTPS sécurisé vers le Terminal (/api/scan) avec AES-GCM
│   └── webhook.rs                # Formatage MessageCard & notification d'alerte Microsoft Teams
└── ui/
    ├── index.html                # Interface mobile épurée classe Apple / B2B (Mode sombre / clair)
    ├── css/
    │   └── style.css             # Design System exécutif, viseur optique haute précision
    ├── js/
    │   ├── app.js                # Contrôleur d'orchestration et pont IPC Tauri v2
    │   ├── scanner.js            # Pilote caméra pleine résolution, contrôle de la torche et flip
    │   └── jsqr.min.js           # Moteur autonome d'analyse optique QR (128 Ko)
    └── icons/                    # Actifs graphiques de l'application
```

---

## 3. Développement et Compilation iOS sans Mac

Apple exigeant la suite Xcode sur macOS pour l'assemblage et la signature finale des paquets `.ipa`, le projet intègre un pipeline **GitHub Actions CI/CD** s'exécutant sur des serveurs virtuels officiels Apple Silicon (`macos-14`).

### Workflow de déploiement automatique sur iPhone :

1. **Développement local sous Linux** :
   Modifiez le code Rust ou l'interface UI, puis testez immédiatement le rendu :
   ```bash
   cargo run -p cipherplate-optical-bridge
   ```

2. **Génération du paquet `.ipa` via GitHub Actions** :
   Un simple `git push` déclenche le workflow `.github/workflows/build-ios.yml` sur les runners macOS gratuits de GitHub.

3. **Installation sur votre iPhone physique** :
   * **Méthode 1 — Apple TestFlight (Recommandé avec compte Apple Developer)** :
     L'action pousse automatiquement la version sur TestFlight. Vous recevez une notification sur votre iPhone et installez l'application en 1 clic.
   * **Méthode 2 — Sideloadly / AltServer (Gratuit, sans compte payant)** :
     Téléchargez le fichier `CipherPlate-Lens.ipa` produit dans les *Artifacts* du build GitHub, branchez l'iPhone en USB ou Wi-Fi sur votre PC, et installez l'app en 30 secondes.

---

## 4. Compilation Android en Local sous Linux

Pour tester instantanément sur un appareil Android sans passer par le cloud :
```bash
# Installation des composants requis (une seule fois)
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install tauri-cli --version "^2.0"

# Initialisation et compilation du paquet APK
cargo tauri android init
cargo tauri android build --apk
```
L'APK généré se trouvera dans `src-tauri/gen/android/app/build/outputs/apk/release/`.

---

## 5. Configuration de l'Alerte Microsoft Teams

1. Dans Microsoft Teams, ouvrez le canal souhaité (ex: `SecOps-PRA-Alerts`).
2. Cliquez sur `···` (Options du canal) > **Connecteurs** > **Webhook entrant (Incoming Webhook)**.
3. Donnez le nom *"CipherPlate Security Monitor"* et copiez l'URL HTTPS générée.
4. Dans l'application **CipherPlate Lens**, touchez l'icône d'engrenage en haut à droite, collez l'URL et touchez **Enregistrer**.
5. Désormais, chaque lecture optique d'une plaque PRA envoie instantanément une fiche d'audit certifiée sur votre canal Teams avec l'empreinte SHA-256 de la plaque.

---

## 6. Conformité & Audit de Sécurité

| Critère | Implémentation CipherPlate Lens |
|---|---|
| **Stockage persistant** | Zéro stockage de secret sur disque. Clés en RAM uniquement pendant la trame. |
| **Résistance aux écoutes Wi-Fi** | Chiffrement en transit AES-256-GCM avec clé éphémère régénérée à chaque session. |
| **Intégrité de l'audit** | Horodatage UTC RFC 3339, empreinte cryptographique SHA-256 transmise au SOC. |
| **Supply-Chain** | Dépendances réduites au strict minimum, compilation native Rust sans pont JS non vérifié. |
