/**
 * CipherPlate Lens · Module de capture optique haute fidélité
 * 
 * Exploite jsQR pour décoder les matrices physiques en plein ratio d'aspect (1280px max)
 * sans distorsion ni compression destructive de pixels.
 */

class OpticalScanner {
    constructor(videoElement, reticleElement, onDetected) {
        this.video = videoElement;
        this.reticle = reticleElement;
        this.onDetected = onDetected;
        this.activeStream = null;
        this.isScanning = false;
        this.isPaused = false;
        this.currentDeviceId = null;
        this.videoDevices = [];
        this.torchActive = false;

        this.canvas = document.createElement('canvas');
        this.ctx = this.canvas.getContext('2d', { willReadFrequently: true });
        this.animFrameId = null;
    }

    async initCamera(preferredDeviceId = null) {
        if (this.activeStream) {
            this.stopCamera();
        }

        const constraints = {
            audio: false,
            video: preferredDeviceId ? { deviceId: { exact: preferredDeviceId } } : {
                facingMode: { ideal: "environment" },
                width: { ideal: 1920, min: 1280 },
                height: { ideal: 1080, min: 720 },
                focusMode: { ideal: "continuous" }
            }
        };

        try {
            const stream = await navigator.mediaDevices.getUserMedia(constraints);
            this.activeStream = stream;
            this.video.srcObject = stream;
            await this.video.play();

            this.isScanning = true;
            this.isPaused = false;

            // Découverte des caméras disponibles pour switcher
            try {
                const devs = await navigator.mediaDevices.enumerateDevices();
                this.videoDevices = devs.filter(d => d.kind === 'videoinput');
            } catch(e) {}

            this.startFrameLoop();
            return { success: true };
        } catch(err) {
            console.error("Échec initialisation caméra :", err);
            return { success: false, error: err.message || err.name };
        }
    }

    stopCamera() {
        this.isScanning = false;
        if (this.animFrameId) {
            cancelAnimationFrame(this.animFrameId);
            this.animFrameId = null;
        }
        if (this.activeStream) {
            this.activeStream.getTracks().forEach(t => t.stop());
            this.activeStream = null;
        }
        this.video.srcObject = null;
    }

    startFrameLoop() {
        const scan = () => {
            if (!this.isScanning) return;
            if (!this.isPaused && this.video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && this.video.videoWidth > 0) {
                this.processVideoFrame();
            }
            this.animFrameId = requestAnimationFrame(scan);
        };
        this.animFrameId = requestAnimationFrame(scan);
    }

    processVideoFrame() {
        const vw = this.video.videoWidth;
        const vh = this.video.videoHeight;

        // Préserver le ratio d'aspect strict de la caméra
        let scale = 1;
        const maxDim = 1280;
        if (vw > maxDim || vh > maxDim) {
            scale = maxDim / Math.max(vw, vh);
        }

        const targetW = Math.round(vw * scale);
        const targetH = Math.round(vh * scale);

        if (this.canvas.width !== targetW || this.canvas.height !== targetH) {
            this.canvas.width = targetW;
            this.canvas.height = targetH;
        }

        this.ctx.drawImage(this.video, 0, 0, targetW, targetH);
        const imgData = this.ctx.getImageData(0, 0, targetW, targetH);

        // Analyse par le moteur jsQR
        if (typeof jsQR === 'function') {
            const code = jsQR(imgData.data, targetW, targetH, {
                inversionAttempts: "attemptBoth"
            });

            if (code) {
                const rawPayload = this.extractCodeData(code);
                if (rawPayload) {
                    this.isPaused = true;
                    if (this.reticle) this.reticle.classList.add('scanned');
                    if (navigator.vibrate) navigator.vibrate(50);
                    this.onDetected(rawPayload);
                }
            }
        }
    }

    extractCodeData(code) {
        if (!code) return null;

        // 1. Données binaires brutes transmises directement par jsQR
        if (code.binaryData && code.binaryData.length > 0) {
            const hex = Array.from(code.binaryData)
                .map(b => (b & 0xff).toString(16).padStart(2, '0'))
                .join('');
            return {
                type: 'binary',
                rawHex: hex,
                text: code.data || ''
            };
        }

        // 2. Données texte (ex: URL d'appairage ou JSON)
        if (code.data && code.data.length > 0) {
            const trimmed = code.data.trim();
            // Si c'est déjà une chaîne hexadécimale pure
            if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0 && trimmed.length > 32) {
                return {
                    type: 'hex_string',
                    rawHex: trimmed.toLowerCase(),
                    text: trimmed
                };
            }
            // Sinon texte standard (ex: URL https://...)
            return {
                type: 'text',
                rawHex: Array.from(trimmed).map(c => (c.charCodeAt(0) & 0xff).toString(16).padStart(2, '0')).join(''),
                text: trimmed
            };
        }

        return null;
    }

    async toggleTorch() {
        if (!this.activeStream) return false;
        const track = this.activeStream.getVideoTracks()[0];
        if (track && typeof track.getCapabilities === 'function') {
            const caps = track.getCapabilities();
            if (caps.torch) {
                this.torchActive = !this.torchActive;
                await track.applyConstraints({ advanced: [{ torch: this.torchActive }] });
                return this.torchActive;
            }
        }
        return false;
    }

    async switchCamera() {
        if (this.videoDevices.length <= 1) return;
        const currentTrack = this.activeStream ? this.activeStream.getVideoTracks()[0] : null;
        const curId = currentTrack ? currentTrack.getSettings().deviceId : null;
        const nextDev = this.videoDevices.find(d => d.deviceId !== curId) || this.videoDevices[0];
        if (nextDev) {
            this.currentDeviceId = nextDev.deviceId;
            await this.initCamera(this.currentDeviceId);
        }
    }

    resume() {
        this.isPaused = false;
        if (this.reticle) {
            this.reticle.classList.remove('scanned', 'detected-pairing', 'detected-plate');
        }
    }
}

window.OpticalScanner = OpticalScanner;
