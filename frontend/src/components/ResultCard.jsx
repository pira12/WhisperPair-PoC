import { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Key,
  Link,
  Fingerprint,
  MapPin,
  ExternalLink,
  Smartphone,
  CheckCircle,
  AlertTriangle,
  Loader,
  Info,
  X,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

function TrackingInfoModal({ onClose }) {
  return (
    <div className="info-overlay" onClick={onClose}>
      <div className="info-modal" onClick={(e) => e.stopPropagation()}>
        <div className="info-modal-header">
          <div className="info-modal-title">
            <MapPin size={16} />
            <h3>How Find My Device Tracking Works</h3>
          </div>
          <button className="info-close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div className="info-modal-body">
          <div className="info-section">
            <h4>1. Account Key Injection</h4>
            <p>
              WhisperPair wrote a random Account Key to the target device. When your Android phone
              pairs with the device, it registers its own Account Key with your Google Account,
              linking the device to you.
            </p>
          </div>
          <div className="info-section">
            <h4>2. FMDN Beacons</h4>
            <p>
              The hijacked device now periodically broadcasts Find My Device Network (FMDN)
              advertisement frames over BLE, derived from the registered Account Key.
            </p>
          </div>
          <div className="info-section">
            <h4>3. Crowd-Sourced Location</h4>
            <p>
              Any nearby Android device participating in the Find Hub network detects these beacons
              and reports them to Google's servers along with its own GPS coordinates.
            </p>
          </div>
          <div className="info-section">
            <h4>4. Location Query</h4>
            <p>
              As the Account Key owner, you can query Google's Find My Device to see the last
              reported location of the hijacked device.
            </p>
          </div>
          <div className="info-section">
            <h4>5. Security Implications</h4>
            <p>
              This demonstrates that CVE-2025-36911 escalates from a one-time pairing bypass to
              persistent location surveillance. The victim's device is trackable anywhere there
              are nearby Android phones, with no indication to the victim.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function ResultCard({
  result,
  trackingStatus,
  trackingMessage,
  onTrack,
  adbConnected,
}) {
  const [showInfoModal, setShowInfoModal] = useState(false);
  const [learnMoreOpen, setLearnMoreOpen] = useState(false);

  if (!result) return null;

  const isVulnerable = result.vulnerable;
  const isTestOnly = result.test_only;
  const canTrack = isVulnerable && result.br_edr_address && result.success && !isTestOnly;

  return (
    <div className={`result-card ${isVulnerable ? 'result-vulnerable' : 'result-safe'}`}>
      <div className="result-header">
        {isVulnerable ? (
          <>
            <ShieldAlert size={22} className="result-icon-vuln" />
            <h3>{isTestOnly ? 'VULNERABLE (Test Only)' : 'VULNERABLE'} - CVE-2025-36911</h3>
          </>
        ) : (
          <>
            <ShieldCheck size={22} className="result-icon-safe" />
            <h3>Device Appears Patched</h3>
          </>
        )}
      </div>

      {isVulnerable && (
        <div className="result-details">
          <div className="result-row">
            <Fingerprint size={14} />
            <span className="result-label">Model ID</span>
            <span className="result-value">{result.model_id || 'Unknown'}</span>
          </div>
          <div className="result-row">
            <Link size={14} />
            <span className="result-label">BR/EDR Address</span>
            <span className="result-value mono">{result.br_edr_address || 'N/A'}</span>
          </div>
          <div className="result-row">
            <Key size={14} />
            <span className="result-label">Account Key Written</span>
            <span className={`result-value ${result.account_key_written ? 'text-success' : 'text-muted'}`}>
              {result.account_key_written ? 'YES' : 'NO'}
            </span>
          </div>
          <div className="result-row">
            <Link size={14} />
            <span className="result-label">Classic BT Paired</span>
            <span className={`result-value ${result.paired ? 'text-success' : 'text-muted'}`}>
              {result.paired ? 'YES' : 'NO'}
            </span>
          </div>
          {result.strategies_tried && (
            <div className="result-row">
              <ShieldAlert size={14} />
              <span className="result-label">Strategies Tried</span>
              <span className="result-value">{result.strategies_tried.join(', ')}</span>
            </div>
          )}
          {result.notifications && result.notifications.length > 0 && (
            <div className="result-notifications">
              <h4>Notifications ({result.notifications.length})</h4>
              {result.notifications.map((n, i) => (
                <div key={i} className="notification-entry">
                  <code>{n.hex}</code>
                  <span className="notif-entropy">entropy: {n.entropy}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="result-message">{result.message}</div>

      {canTrack && (
        <div className="tracking-section">
          <div className="tracking-header">
            <MapPin size={16} />
            <h4>Find My Device Tracking</h4>
            <button
              className="info-btn"
              onClick={() => setShowInfoModal(true)}
              title="How tracking works"
            >
              <Info size={15} />
            </button>
          </div>

          {!trackingStatus && (
            <div className="tracking-actions">
              <button
                className="btn btn-track"
                onClick={onTrack}
                disabled={!adbConnected}
              >
                <Smartphone size={16} />
                Track via Find My Device
              </button>
              {!adbConnected && (
                <p className="tracking-hint">Connect an Android phone via USB with ADB debugging enabled</p>
              )}
            </div>
          )}

          {trackingStatus === 'pairing' && (
            <div className="tracking-progress">
              <Loader size={16} className="spin" />
              <span>Pairing with Android phone...</span>
            </div>
          )}

          {trackingStatus === 'success' && (
            <div className="tracking-confirmed">
              <div className="tracking-confirmed-header">
                <CheckCircle size={16} />
                <span>Device registered to Find My Device</span>
              </div>
              <p className="tracking-confirmed-detail">
                Your Android phone has paired with the target device and registered it with your
                Google Account. The device will now broadcast FMDN beacons that the Find My Device
                network can locate.
              </p>
              <a
                href="https://www.google.com/android/find"
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-findmy"
              >
                <ExternalLink size={14} />
                Open Find My Device
              </a>
              <button
                className="tracking-learn-more"
                onClick={() => setLearnMoreOpen(!learnMoreOpen)}
              >
                {learnMoreOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                {learnMoreOpen ? 'Hide details' : 'Learn more about how this works'}
              </button>
              {learnMoreOpen && (
                <div className="tracking-learn-content">
                  <p>
                    <strong>What happened:</strong> WhisperPair exploited CVE-2025-36911 to force-pair
                    with the target device. Your Android phone then paired via ADB, causing Google's
                    Fast Pair service to register the device with your Google Account.
                  </p>
                  <p>
                    <strong>What happens next:</strong> The target device broadcasts FMDN beacons.
                    Any nearby Android device in the Find Hub network reports these beacons to Google
                    with GPS coordinates. You can view the location on Find My Device.
                  </p>
                  <p>
                    <strong>Security impact:</strong> This turns a BLE pairing vulnerability into
                    persistent, crowd-sourced location surveillance with no indication to the victim.
                  </p>
                </div>
              )}
            </div>
          )}

          {trackingStatus === 'warning' && (
            <div className="tracking-warning">
              <AlertTriangle size={16} />
              <span>{trackingMessage}</span>
              <a
                href="https://www.google.com/android/find"
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-findmy"
              >
                <ExternalLink size={14} />
                Check Find My Device
              </a>
            </div>
          )}

          {trackingStatus === 'error' && (
            <div className="tracking-error">
              <AlertTriangle size={16} />
              <span>{trackingMessage}</span>
              <button className="btn btn-track-retry" onClick={onTrack}>
                Retry
              </button>
            </div>
          )}
        </div>
      )}

      {showInfoModal && <TrackingInfoModal onClose={() => setShowInfoModal(false)} />}
    </div>
  );
}
