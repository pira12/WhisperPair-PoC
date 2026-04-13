import { Bluetooth } from 'lucide-react';
import DeviceCard from './DeviceCard';

export default function DevicePanel({ devices, deviceStatuses, selectedDevice, onTarget }) {
  return (
    <div className="panel device-panel">
      <div className="panel-header">
        <Bluetooth size={16} />
        <h2>Devices</h2>
        {devices.length > 0 && (
          <span className="badge">{devices.length}</span>
        )}
      </div>
      <div className="panel-content">
        {devices.length === 0 ? (
          <div className="empty-state">
            <Bluetooth size={40} strokeWidth={1} />
            <p>No devices found</p>
            <p className="empty-hint">Click "Scan Devices" to discover nearby Fast Pair devices</p>
          </div>
        ) : (
          <div className="device-list">
            {devices.map((device) => (
              <DeviceCard
                key={device.address}
                device={device}
                status={deviceStatuses[device.address] || 'untested'}
                selected={selectedDevice?.address === device.address}
                onTarget={onTarget}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
