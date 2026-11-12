/**
 * CipherPlate Lens · Application Mobile Compagnon
 * 
 * Simple, factuel, zéro jargon :
 * - Scanner le QR code d'appairage -> Appairer -> Connecté
 * - Scanner le QR code chiffré -> Transmettre pour déchiffrer
 */

(function () {
    let pairedSession = null;
    let opticalScanner = null;
    let pendingDetection = null;

    // DOM
    const video = document.getElementById('cameraVideo');
    const reticle = document.getElementById('viewfinderReticle');
    const camOverlay = document.getElementById('camClickOverlay');
    const btnActivateCam = document.getElementById('btnActivateCam');
    const instructionLabel = document.getElementById('instructionLabel');
    const terminalHostLabel = document.getElementById('terminalHostLabel');
    const statusIndicator = document.getElementById('statusIndicator');
    const btnTorch = document.getElementById('btnTorch');
    const btnFlipCam = document.getElementById('btnFlipCam');

    // Action simple
    const actionBarContainer = document.getElementById('actionBarContainer');
    const btnConfirmAction = document.getElementById('btnConfirmAction');
    const btnConfirmActionText = document.getElementById('btnConfirmActionText');
    const btnDismissDetection = document.getElementById('btnDismissDetection');

    // Feedback & modal
    const feedbackOverlay = document.getElementById('feedbackOverlay');
    const btnDismissFeedback = document.getElementById('btnDismissFeedback');

    const modalLogs = document.getElementById('modalLogs');
    const dockBtnScan = document.getElementById('dockBtnScan');
    const dockBtnLogs = document.getElementById('dockBtnLogs');
    const btnCloseLogs = document.getElementById('btnCloseLogs');
    const logContainer = document.getElementById('logContainer');
    const dockBtnReset = document.getElementById('dockBtnReset');
    const btnToggleTheme = document.getElementById('btnToggleTheme');

    // -------------------------------------------------------------------------
    // IPC Tauri
    // -------------------------------------------------------------------------
    async function invokeTauri(cmd, args = {}) {
        if (window.__TAURI__ && window.__TAURI__.core && typeof window.__TAURI__.core.invoke === 'function') {
            return await window.__TAURI__.core.invoke(cmd, args);
        } else if (window.__TAURI__ && typeof window.__TAURI__.invoke === 'function') {
            return await window.__TAURI__.invoke(cmd, args);
        } else {
            console.warn(`[Dev Fallback] Tauri "${cmd}" :`, args);
            if (cmd === 'pair_terminal') {
                return {
                    endpoint_url: 'https://127.0.0.1:8765/api/scan',
                    display_host: '127.0.0.1:8765',
                    token: 'dev_token',
                    paired_at: new Date().toISOString()
                };
            }
            if (cmd === 'get_pairing_status') return pairedSession;
            if (cmd === 'transmit_scanned_payload') {
                return {
                    success: true,
                    message: "Transmis",
                    http_status: 200,
                    timestamp: new Date().toISOString(),
                    payload_fingerprint: "abc123456",
                    desktop_will_notify: true,
                    alert_id: "alert_1"
                };
            }
            if (cmd === 'get_bridge_logs') {
                return [{ timestamp: new Date().toISOString(), level: 'INFO', message: 'Démarré' }];
            }
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Guidage simple et factuel
    // -------------------------------------------------------------------------
    function updateGuidance() {
        if (!pairedSession) {
            if (instructionLabel) instructionLabel.innerText = "Scanner le QR code d'appairage";
            if (terminalHostLabel) terminalHostLabel.innerText = "Non connecté";
            if (statusIndicator) statusIndicator.classList.remove('connected');
        } else {
            if (instructionLabel) instructionLabel.innerText = "Scanner le QR code chiffré";
            if (terminalHostLabel) terminalHostLabel.innerText = "Connecté";
            if (statusIndicator) statusIndicator.classList.add('connected');
        }
    }

    // -------------------------------------------------------------------------
    // Initialisation Caméra
    // -------------------------------------------------------------------------
    function initScanner() {
        if (typeof OpticalScanner !== 'function') return;
        opticalScanner = new OpticalScanner(video, reticle, onCodeDetected);
        opticalScanner.initCamera().then(res => {
            if (!res.success) {
                if (camOverlay) camOverlay.style.display = 'flex';
            } else {
                if (camOverlay) camOverlay.style.display = 'none';
                if (btnFlipCam) btnFlipCam.style.display = opticalScanner.videoDevices.length > 1 ? 'flex' : 'none';
                if (btnTorch) btnTorch.style.display = 'flex';
            }
        });
    }

    // -------------------------------------------------------------------------
    // Détection sans erreur & discrimination stricte
    // -------------------------------------------------------------------------
    function classifyQRCode(payload) {
        const text = (payload.text || '').trim();
        const rawHex = (payload.rawHex || '').trim().toLowerCase();

        // 1. QR Appairage du Terminal PRA
        const isUrl = (text.startsWith('http://') || text.startsWith('https://')) &&
                      (text.includes('/scanner') || text.includes('/api/scan') || text.includes('?t='));
        let isJsonPairing = false;
        if (text.startsWith('{') && text.endsWith('}')) {
            try {
                const parsed = JSON.parse(text);
                if (parsed.endpoint && parsed.token) isJsonPairing = true;
            } catch(e) {}
        }

        if (isUrl || isJsonPairing) {
            return { type: 'PAIRING', rawInput: text };
        }

        // Rejet formel des formats non-plaque (réseaux Wi-Fi, sites web, contacts, etc.)
        const lowerText = text.toLowerCase();
        if (lowerText.startsWith('http://') || lowerText.startsWith('https://') ||
            lowerText.startsWith('wifi:') || lowerText.startsWith('begin:vcard') ||
            lowerText.startsWith('mailto:') || lowerText.startsWith('tel:') || lowerText.startsWith('sms:')) {
            return { type: 'UNKNOWN' };
        }

        // 2. QR Plaque Chiffrée (Break-Glass PRA)
        // Vérification de l'empreinte cryptographique souveraine CipherPlate :
        // a) En-tête binaire natif 'CP20' (hex 43503230), 'CP10' (hex 43503130) ou 'CP' (hex 4350)
        const hasMagicHeader = rawHex.slice(0, 64).includes('43503230') || 
                               rawHex.slice(0, 64).includes('43503130') ||
                               rawHex.slice(0, 32).includes('4350');

        // b) Format JSON de plaque de secret (champs cryptographiques m, d, i, k)
        let isPlateJson = false;
        if (text.startsWith('{') && text.endsWith('}')) {
            try {
                const p = JSON.parse(text);
                if ((p.m && typeof p.m === 'string' && p.m.startsWith('CP')) ||
                    (p.d && p.i && Array.isArray(p.k))) {
                    isPlateJson = true;
                }
            } catch(e) {}
        }

        // c) Trame hexadécimale brute >= 64 caractères (32 octets min)
        const isCandidate = /^[0-9a-f]+$/.test(rawHex) && rawHex.length >= 64;

        if (hasMagicHeader || isPlateJson || isCandidate) {
            return { type: 'PLATE', rawHex: rawHex };
        }

        return { type: 'UNKNOWN' };
    }

    // -------------------------------------------------------------------------
    // Affichage des boutons d'action simples
    // -------------------------------------------------------------------------
    function onCodeDetected(payload) {
        const item = classifyQRCode(payload);

        if (item.type === 'PAIRING') {
            pendingDetection = item;
            if (reticle) reticle.className = 'reticle-box detected-pairing';
            if (btnConfirmActionText) btnConfirmActionText.innerText = "Appairer";
            if (btnConfirmAction) btnConfirmAction.className = 'action-btn-pill pairing';
            if (actionBarContainer) actionBarContainer.style.display = 'flex';
        } else if (item.type === 'PLATE') {
            if (!pairedSession) {
                if (reticle) reticle.className = 'reticle-box';
                if (instructionLabel) instructionLabel.innerText = "Veuillez d'abord scanner le QR d'appairage";
                setTimeout(() => {
                    updateGuidance();
                    if (opticalScanner) opticalScanner.resume();
                }, 1500);
                return;
            }

            pendingDetection = item;
            if (reticle) reticle.className = 'reticle-box detected-plate';
            if (btnConfirmActionText) btnConfirmActionText.innerText = "Transmettre pour déchiffrer";
            if (btnConfirmAction) btnConfirmAction.className = 'action-btn-pill plate';
            if (actionBarContainer) actionBarContainer.style.display = 'flex';
        } else {
            if (reticle) reticle.className = 'reticle-box';
            if (instructionLabel) instructionLabel.innerText = "Code non reconnu";
            setTimeout(() => {
                updateGuidance();
                if (opticalScanner) opticalScanner.resume();
            }, 1200);
        }
    }

    function dismissDetection() {
        pendingDetection = null;
        if (actionBarContainer) actionBarContainer.style.display = 'none';
        if (reticle) reticle.className = 'reticle-box';
        updateGuidance();
        if (opticalScanner) opticalScanner.resume();
    }

    // -------------------------------------------------------------------------
    // Clic sur bouton d'action
    // -------------------------------------------------------------------------
    async function executeAction() {
        if (!pendingDetection) return;

        if (pendingDetection.type === 'PAIRING') {
            if (btnConfirmActionText) btnConfirmActionText.innerText = "Appairé...";
            try {
                const session = await invokeTauri('pair_terminal', { pairingInput: pendingDetection.rawInput });
                pairedSession = session;
                dismissDetection();
                if (navigator.vibrate) navigator.vibrate(50);
            } catch (err) {
                console.error(err);
                if (instructionLabel) instructionLabel.innerText = "Échec d'appairage";
                setTimeout(dismissDetection, 1500);
            }
        } else if (pendingDetection.type === 'PLATE') {
            if (btnConfirmActionText) btnConfirmActionText.innerText = "Transmission...";
            try {
                await invokeTauri('transmit_scanned_payload', { rawPayloadHex: pendingDetection.rawHex });
                dismissDetection();
                if (feedbackOverlay) feedbackOverlay.style.display = 'flex';
                if (navigator.vibrate) navigator.vibrate([40, 60]);
            } catch (err) {
                console.error(err);
                if (instructionLabel) instructionLabel.innerText = "Échec de transmission";
                setTimeout(dismissDetection, 1500);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Événements
    // -------------------------------------------------------------------------
    if (btnConfirmAction) btnConfirmAction.addEventListener('click', executeAction);
    if (btnDismissDetection) btnDismissDetection.addEventListener('click', dismissDetection);

    if (btnActivateCam) {
        btnActivateCam.addEventListener('click', () => {
            if (opticalScanner) {
                opticalScanner.initCamera().then(() => {
                    if (camOverlay) camOverlay.style.display = 'none';
                });
            }
        });
    }

    if (btnTorch) {
        btnTorch.addEventListener('click', async () => {
            if (!opticalScanner) return;
            const active = await opticalScanner.toggleTorch();
            btnTorch.classList.toggle('active', active);
        });
    }

    if (btnFlipCam) {
        btnFlipCam.addEventListener('click', async () => {
            if (opticalScanner) await opticalScanner.switchCamera();
        });
    }

    if (btnDismissFeedback) {
        btnDismissFeedback.addEventListener('click', () => {
            if (feedbackOverlay) feedbackOverlay.style.display = 'none';
            updateGuidance();
            if (opticalScanner) opticalScanner.resume();
        });
    }

    if (dockBtnLogs) {
        dockBtnLogs.addEventListener('click', async () => {
            if (modalLogs) modalLogs.style.display = 'flex';
            if (logContainer) logContainer.innerHTML = '<div style="color:var(--text-secondary);padding:8px;">Chargement...</div>';
            try {
                const logs = await invokeTauri('get_bridge_logs');
                if (!logs || logs.length === 0) {
                    if (logContainer) logContainer.innerHTML = '<div style="color:var(--text-secondary);padding:8px;">Aucun événement.</div>';
                    return;
                }
                if (logContainer) {
                    logContainer.innerHTML = logs.slice().reverse().map(l => {
                        const time = l.timestamp ? l.timestamp.split('T')[1].split('.')[0] : '--:--:--';
                        return `<div class="log-item ${l.level}">
                            <span class="time">[${time}]</span>
                            <strong>${l.level}</strong>: ${l.message}
                        </div>`;
                    }).join('');
                }
            } catch (e) {
                if (logContainer) logContainer.innerHTML = `<div style="color:var(--danger);padding:8px;">Erreur</div>`;
            }
        });
    }

    if (dockBtnScan) {
        dockBtnScan.addEventListener('click', () => {
            if (modalLogs) modalLogs.style.display = 'none';
            if (feedbackOverlay) feedbackOverlay.style.display = 'none';
            dismissDetection();
        });
    }

    if (btnCloseLogs) {
        btnCloseLogs.addEventListener('click', () => {
            if (modalLogs) modalLogs.style.display = 'none';
        });
    }

    if (dockBtnReset) {
        dockBtnReset.addEventListener('click', async () => {
            if (confirm("Déconnecter ?")) {
                await invokeTauri('clear_session');
                pairedSession = null;
                dismissDetection();
            }
        });
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        try {
            localStorage.setItem('cipherplate_theme', theme);
        } catch(e) {}
    }

    if (btnToggleTheme) {
        btnToggleTheme.addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme') || 'dark';
            applyTheme(current === 'dark' ? 'light' : 'dark');
        });
    }

    window.addEventListener('DOMContentLoaded', async () => {
        try {
            let saved = localStorage.getItem('cipherplate_theme');
            if (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
                saved = 'light';
            }
            applyTheme(saved || 'dark');
        } catch(e) {}

        initScanner();
        try {
            const session = await invokeTauri('get_pairing_status');
            if (session) pairedSession = session;
        } catch (e) {}
        updateGuidance();
    });
})();
