async function registerBiometric() {
    try {
        const res = await fetch('/user/biometric/register-options', { method: 'POST' });
        const options = await res.json();
        
        // Convert base64/array buffers for WebAuthn API
        options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
        options.user.id = Uint8Array.from(options.user.id);

        const credential = await navigator.credentials.create({ publicKey: options });
        
        const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
        const publicKey = "webauthn_passkey_stored";

        const verifyRes = await fetch('/user/biometric/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credentialId, publicKey })
        });
        
        const result = await verifyRes.json();
        if (result.success) {
            alert("Face / Fingerprint successfully registered!");
            location.reload();
        } else {
            alert("Registration failed: " + result.message);
        }
    } catch (err) {
        console.error(err);
        alert("Biometric registration was cancelled or is not supported on this device.");
    }
}

async function authenticateBiometric(userId, identifier) {
    try {
        const res = await fetch('/auth/biometric/auth-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ identifier })
        });
        const options = await res.json();
        
        if (!options.allowCredentials || options.allowCredentials.length === 0) {
            alert("No biometrics registered for this account.");
            return;
        }

        options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
        options.allowCredentials.forEach(cred => {
            cred.id = Uint8Array.from(atob(cred.id), c => c.charCodeAt(0));
        });

        const credential = await navigator.credentials.get({ publicKey: options });

        const verifyRes = await fetch('/auth/biometric/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId })
        });
        const result = await verifyRes.json();
        if (result.success) {
            window.location.href = result.redirect;
        } else {
            alert("Biometric verification failed.");
        }
    } catch (err) {
        console.error(err);
        alert("Biometric sign-in was cancelled or failed.");
    }
}


