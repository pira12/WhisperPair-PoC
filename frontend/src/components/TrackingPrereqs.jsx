import {
  MapPin,
  CheckCircle,
  Circle,
  Radio,
  ExternalLink,
  Loader,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { useState } from 'react';

const PREREQS_PHONE = [
  { key: 'vulnerable', label: 'Device is vulnerable' },
  { key: 'success', label: 'Exploit succeeded' },
  { key: 'br_edr', label: 'BR/EDR address found' },
  { key: 'full_mode', label: 'Full exploit mode' },
  { key: 'adb', label: 'ADB phone connected' },
];

const PREREQS_LAPTOP = [
  { key: 'vulnerable', label: 'Device is vulnerable' },
  { key: 'success', label: 'Exploit succeeded' },
  { key: 'br_edr', label: 'BR/EDR address found' },
  { key: 'full_mode', label: 'Full exploit mode' },
];

export default function TrackingPrereqs({
  result,
  vulnTestMode,
  attackMode,
  adbConnected,
  onTrack,
  trackingStatus,
  trackingMessage,
  bredrAddress,
  onBredrAddressChange,
}) {
  const [learnMoreOpen, setLearnMoreOpen] = useState(false);

  const isLaptop = attackMode === 'laptop';
  const prereqs = isLaptop ? PREREQS_LAPTOP : PREREQS_PHONE;

  const checks = {
    vulnerable: !!result?.vulnerable,
    success: !!result?.success,
    br_edr: !!result?.br_edr_address,
    full_mode: !vulnTestMode,
    adb: !!adbConnected,
  };

  const passCount = prereqs.filter(p => checks[p.key]).length;
  const allReady = passCount === prereqs.length;

  return (
    <div className="tracking-prereqs-card">
      <div className="prereqs-header">
        <MapPin size={14} />
        <h3>Tracking Readiness</h3>
        <span className="prereqs-count">{passCount}/{prereqs.length}</span>
      </div>
      <div className="prereqs-list">
        {prereqs.map(({ key, label }) => (
          <div key={key} className={`prereq-item ${checks[key] ? 'prereq-pass' : 'prereq-fail'}`}>
            {checks[key] ? <CheckCircle size={13} /> : <Circle size={13} />}
            <span>{label}</span>
          </div>
        ))}
      </div>

      {allReady && !trackingStatus && (
        <div className="tracking-actions-col">
          <input
            type="text"
            className="bredr-input"
            placeholder={result?.br_edr_address
              ? `Auto: ${result.br_edr_address} (override below)`
              : 'BR/EDR address (e.g. AA:BB:CC:DD:EE:FF)'}
            value={bredrAddress}
            onChange={(e) => onBredrAddressChange(e.target.value.toUpperCase())}
            maxLength={17}
          />
          <button
            className="btn btn-track"
            onClick={() => onTrack(bredrAddress || null)}
            disabled={!bredrAddress && !result?.br_edr_address}
          >
            <Radio size={16} />
            {isLaptop ? 'Force Pair via Laptop' : 'Force Pair via Phone'}
          </button>
          <p className="bredr-hint">
            {result?.br_edr_address_needs_override
              ? 'Auto-discovery failed — replace the BLE address above with the real Classic BT address (check paired phone settings)'
              : 'Optional override — leave blank to use the auto-discovered address'}
          </p>
        </div>
      )}

      {allReady && trackingStatus === 'scanning' && (
        <div className="tracking-progress">
          <Loader size={16} className="spin" />
          <span>{trackingMessage || 'Launching companion app...'}</span>
        </div>
      )}

      {allReady && trackingStatus === 'success' && (
        <div className="tracking-confirmed">
          <div className="tracking-confirmed-header">
            <CheckCircle size={16} />
            <span>Device force-paired!</span>
          </div>
          <p className="tracking-confirmed-detail">
            {trackingMessage}
          </p>
          <button
            className="tracking-learn-more"
            onClick={() => setLearnMoreOpen(!learnMoreOpen)}
          >
            {learnMoreOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {learnMoreOpen ? 'Hide details' : 'Learn more'}
          </button>
          {learnMoreOpen && (
            <div className="tracking-learn-content">
              <p>
                <strong>What happened:</strong> WhisperPair exploited CVE-2025-36911 to bypass
                Fast Pair authentication. The companion app on the phone performed KBP, wrote an
                Account Key, and created a Classic BT bond — all without the device being in
                pairing mode.
              </p>
              <p>
                <strong>Impact:</strong> The attacker's phone now has full audio access to the
                victim's earbuds via HFP (microphone) and A2DP (speaker). The victim has no
                indication that a second device has paired.
              </p>
            </div>
          )}
        </div>
      )}

      {allReady && trackingStatus === 'warning' && (
        <div className="tracking-warning">
          <AlertTriangle size={16} />
          <span>{trackingMessage}</span>
          <button className="btn btn-track-retry" onClick={() => onTrack(bredrAddress || null)}>
            Retry
          </button>
        </div>
      )}

      {allReady && trackingStatus === 'error' && (
        <div className="tracking-error">
          <AlertTriangle size={16} />
          <span>{trackingMessage}</span>
          <button className="btn btn-track-retry" onClick={() => onTrack(bredrAddress || null)}>
            Retry
          </button>
        </div>
      )}
    </div>
  );
}
