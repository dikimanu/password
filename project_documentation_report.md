# Project Report: AI-Based Adaptive Authentication and Intelligent Attack Detection System

---

## 1. Brief Explanation of the Project Topic
Traditional authentication systems rely on static security rules—asking for a password and occasionally a fixed two-factor authentication (2FA) prompt regardless of context. This project introduces an **AI-Based Adaptive Authentication and Intelligent Attack Detection System**. Instead of treating every login attempt identically, the system continuously evaluates contextual signals (such as login velocity, device fingerprints, and behavioral patterns) using machine learning to calculate a real-time risk score. Based on this threat level, the system dynamically adapts its security posture—allowing seamless access for trusted sessions, demanding step-up biometric/OTP verification for suspicious behavior, or blocking malicious attacks outright.

---

## 2. Necessity and Implementation Strategy

### Why It Is Necessary for Humans
* **Combating Modern Cyber Threats:** Automated credential stuffing, brute-force attacks, and password spraying compromise millions of accounts daily. Static passwords alone are no longer sufficient to protect personal data, financial assets, and digital identities.
* **Balancing Security with User Experience (UX):** Constant multi-factor prompts cause "security fatigue," leading users to adopt weak habits. Adaptive authentication protects users silently in the background, intervening with extra verification *only* when genuine anomalies occur.
* **Proactive Defense Over Reactive Recovery:** Rather than notifying users after an account has already been breached, real-time threat classification stops unauthorized access before damage occurs.

### How We Implemented It
We built a full-stack, cloud-backed security application integrating machine learning, cryptographic authentication standards, and generative AI:
1. **Risk & Threat Pipeline:** Every login request is intercepted and evaluated by dual scikit-learn models (`RandomForestClassifier` and `IsolationForest`) alongside rule-based velocity checks.
2. **Adaptive Policy Engine:** The resulting risk score routes the user through an appropriate authentication tier (Allow, Step-Up Verification, or Account Lockdown).
3. **Cloud Relational Persistence:** All user profiles, session telemetry, trusted devices, and security audit logs are stored securely in a serverless PostgreSQL database (Neon).
4. **AI-Assisted User Guidance:** The Gemini API synthesizes complex audit logs into plain-English security insights so everyday users can understand and manage their account health.

---

## 3. Comprehensive System Features

### 3.1. Intelligent Threat Detection & Risk Scoring Engine
* **Supervised Attack Classification (`RandomForestClassifier`):** Analyzes request features—such as failure rates, IP/device shifts, and attempt frequency—to classify specific attack vectors including **Brute-Force**, **Password Spraying**, and **Credential Stuffing**.
* **Unsupervised Anomaly Detection (`IsolationForest`):** Establishes a baseline of normal user behavior and flags zero-day deviations or unusual login contexts without requiring pre-labeled attack signatures.
* **Dynamic Risk Calculation:** Combines ML probabilities with real-time velocity metrics to assign a granular risk score to every authentication attempt.

### 3.2. Adaptive Multi-Layered Authentication
* **Context-Aware Step-Up Verification:** Low-risk logins from recognized devices proceed smoothly, while medium-to-high-risk logins automatically trigger secondary verification challenges.
* **WebAuthn Biometric Passkeys:** Implements passwordless and step-up authentication using platform authenticators (Face ID, Touch ID, Windows Hello) backed by asymmetric public-key cryptography.
* **Time-Based One-Time Passwords (TOTP):** Integrates standard authenticator app support via `pyotp` for reliable offline verification codes.
* **Cryptographic Backup Codes:** Generates single-use recovery codes to ensure users retain account access if their primary authenticator device is lost.

### 3.3. Automated Account Defense & Monitoring
* **Critical Risk Lockdown:** Automatically freezes login access when risk thresholds reach critical levels, neutralizing ongoing automated attacks.
* **Keystroke & Behavioral Telemetry Alerts:** Captures suspicious interaction patterns during login attempts and logs detailed forensic events.
* **Trusted Device Management:** Tracks and verifies known device fingerprints, allowing users to review and revoke device trust at any time.

### 3.4. Generative AI Security Advisor & Notifications
* **Gemini-Powered Account Analysis (`google-genai`):** Evaluates recent login attempts and security events to generate personalized, human-readable health summaries and actionable recommendations.
* **Transactional Email Alerts (Brevo):** Dispatches instant email notifications for OTP delivery, unrecognized device logins, and critical security lockdowns.

### 3.5. Cloud Architecture & Responsive Interface
* **Serverless PostgreSQL Database (Neon):** Engineered with normalized relational tables (`users`, `login_attempts`, `security_events`, `otp_codes`, `known_devices`, `backup_codes`, `webauthn_credentials`) utilizing pooled connections for high concurrency.
* **Threat-Aware UI/UX:** A responsive, mobile-first frontend featuring dynamic visual themes that reflect the user's current security posture, alongside real-time security dashboards.

---

## 4. Limitations of the Project
1. **Cold-Start Problem for Behavioral Baselines:** For newly registered users with minimal login history, the unsupervised `IsolationForest` model has limited behavioral data, requiring initial reliance on global heuristics and supervised rules until sufficient user patterns are collected.
2. **Synthetic / Simulated Training Data Constraints:** Because real-world enterprise attack datasets are sensitive and proprietary, initial model training relies on simulated attack distributions, which may require periodic retraining on live production traffic to prevent model drift.
3. **Device Fingerprinting Volatility:** Browser updates, VPN usage, or privacy extensions can alter client fingerprints, occasionally causing legitimate users to be flagged as unrecognized devices and triggering extra step-up prompts.
4. **External API Dependencies:** Real-time email alerting (Brevo) and AI advisory summaries (Gemini API) depend on third-party service availability and network latency, requiring graceful fallback mechanisms during outages.

---

## 5. Conclusion
The **AI-Based Adaptive Authentication and Intelligent Attack Detection System** successfully bridges the gap between high-grade cybersecurity and frictionless usability. By combining supervised attack classification, unsupervised anomaly detection, modern cryptographic standards (WebAuthn and TOTP), and generative AI insights on a scalable PostgreSQL architecture, the project demonstrates how intelligent systems can proactively defend human users against evolving digital threats without sacrificing everyday convenience.