import { Crosshair, Signal, Bluetooth, Building2, Tag } from 'lucide-react';

function rssiToPercent(rssi) {
  const min = -100;
  const max = -30;
  return Math.max(0, Math.min(100, ((rssi - min) / (max - min)) * 100));
}

function rssiLabel(rssi) {
  if (rssi > -50) return 'Excellent';
  if (rssi > -65) return 'Good';
  if (rssi > -80) return 'Fair';
  return 'Weak';
}

const typeIcons = {
  earbuds: '🎧',
  headphones: '🎧',
  speaker: '🔊',
};

export default function DeviceCard({ device, status, selected, onTarget }) {
  const percent = rssiToPercent(device.rssi);

  let borderClass = 'status-untested';
  if (status === 'in_progress') borderClass = 'status-progress';
  else if (status === 'vulnerable') borderClass = 'status-vulnerable';
  else if (status === 'patched') borderClass = 'status-patched';

  return (
    <div className={`device-card ${borderClass} ${selected ? 'selected' : ''}`}>
      <div className="device-header">
        <Bluetooth size={16} className="device-bt-icon" />
        <span className="device-name">{device.known_name || device.name || 'Unknown Device'}</span>
        {status === 'vulnerable' && (
          <span className="vuln-badge">VULN</span>
        )}
        {status === 'patched' && (
          <span className="patched-badge">SAFE</span>
        )}
      </div>
      <div className="device-address">{device.address}</div>

      {device.manufacturer && (
        <div className="device-meta">
          <span className="device-manufacturer">
            <Building2 size={11} />
            {device.manufacturer}
          </span>
          {device.device_type && (
            <span className="device-type">
              <Tag size={11} />
              {typeIcons[device.device_type] || ''} {device.device_type}
            </span>
          )}
        </div>
      )}

      <div className="device-rssi">
        <Signal size={14} />
        <div className="rssi-bar-container">
          <div className="rssi-bar" style={{ width: `${percent}%` }} />
        </div>
        <span className="rssi-value">{device.rssi} dBm</span>
        <span className="rssi-label">{rssiLabel(device.rssi)}</span>
      </div>
      {device.model_id && (
        <div className="device-model">Model: {device.model_id}</div>
      )}
      <button
        className={`btn btn-target ${selected ? 'btn-targeted' : ''}`}
        onClick={() => onTarget(selected ? null : device)}
      >
        <Crosshair size={14} />
        {selected ? 'Untarget' : 'Target'}
      </button>
    </div>
  );
}
