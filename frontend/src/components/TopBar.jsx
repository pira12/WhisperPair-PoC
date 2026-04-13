import { useState } from 'react';
import { Bluetooth, Radar, Wifi, WifiOff, Smartphone, ChevronDown } from 'lucide-react';

export default function TopBar({
  connected,
  scanning,
  onScan,
  adbDevices,
  selectedAdbDevice,
  onSelectAdbDevice,
}) {
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const connectedPhones = (adbDevices || []).filter((d) => d.status === 'device');
  const selectedPhone = connectedPhones.find((d) => d.id === selectedAdbDevice);
  const hasPhone = connectedPhones.length > 0;

  return (
    <header className="topbar">
      <div className="topbar-left">
        <Bluetooth size={22} className="topbar-icon" />
        <h1 className="topbar-title">WhisperPair</h1>
        <span className="topbar-cve">CVE-2025-36911</span>
      </div>
      <div className="topbar-right">
        <div className="adb-indicator-wrapper">
          <div
            className={`adb-indicator ${hasPhone ? 'adb-connected' : 'adb-disconnected'}`}
            onClick={() => connectedPhones.length > 1 && setDropdownOpen(!dropdownOpen)}
            role={connectedPhones.length > 1 ? 'button' : undefined}
          >
            <Smartphone size={14} />
            <span>
              {hasPhone
                ? selectedPhone?.model || selectedPhone?.id || 'Phone connected'
                : 'No phone'}
            </span>
            {connectedPhones.length > 1 && <ChevronDown size={12} />}
          </div>
          {dropdownOpen && connectedPhones.length > 1 && (
            <div className="adb-dropdown">
              {connectedPhones.map((phone) => (
                <button
                  key={phone.id}
                  className={`adb-dropdown-item ${phone.id === selectedAdbDevice ? 'active' : ''}`}
                  onClick={() => {
                    onSelectAdbDevice(phone.id);
                    setDropdownOpen(false);
                  }}
                >
                  <Smartphone size={12} />
                  <span>{phone.model || phone.id}</span>
                  {phone.android_version && (
                    <span className="adb-android-ver">Android {phone.android_version}</span>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>
        <div className={`connection-status ${connected ? 'online' : 'offline'}`}>
          {connected ? <Wifi size={14} /> : <WifiOff size={14} />}
          <span>{connected ? 'Connected' : 'Disconnected'}</span>
        </div>
        <button
          className="btn btn-scan"
          onClick={onScan}
          disabled={scanning || !connected}
        >
          <Radar size={16} className={scanning ? 'spin' : ''} />
          {scanning ? 'Scanning...' : 'Scan Devices'}
        </button>
      </div>
    </header>
  );
}
