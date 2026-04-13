import { MapPin, CheckCircle, Circle, Smartphone } from 'lucide-react';

const PREREQS = [
  { key: 'vulnerable', label: 'Device is vulnerable' },
  { key: 'success', label: 'Exploit succeeded' },
  { key: 'br_edr', label: 'BR/EDR address found' },
  { key: 'full_mode', label: 'Full exploit mode' },
  { key: 'adb', label: 'ADB phone connected' },
];

export default function TrackingPrereqs({ result, vulnTestMode, adbConnected }) {
  const checks = {
    vulnerable: !!result?.vulnerable,
    success: !!result?.success,
    br_edr: !!result?.br_edr_address,
    full_mode: !vulnTestMode,
    adb: !!adbConnected,
  };

  const passCount = Object.values(checks).filter(Boolean).length;

  return (
    <div className="tracking-prereqs-card">
      <div className="prereqs-header">
        <MapPin size={14} />
        <h3>Tracking Readiness</h3>
        <span className="prereqs-count">{passCount}/{PREREQS.length}</span>
      </div>
      <div className="prereqs-list">
        {PREREQS.map(({ key, label }) => (
          <div key={key} className={`prereq-item ${checks[key] ? 'prereq-pass' : 'prereq-fail'}`}>
            {checks[key] ? <CheckCircle size={13} /> : <Circle size={13} />}
            <span>{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
