import { useState, useEffect, useCallback } from 'react';
import socket from './socket';
import TopBar from './components/TopBar';
import DevicePanel from './components/DevicePanel';
import ExploitPanel from './components/ExploitPanel';

function App() {
  const [connected, setConnected] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [devices, setDevices] = useState([]);
  const [deviceStatuses, setDeviceStatuses] = useState({});
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [exploitRunning, setExploitRunning] = useState(false);
  const [logEntries, setLogEntries] = useState([]);
  const [result, setResult] = useState(null);
  const [adbDevices, setAdbDevices] = useState([]);
  const [selectedAdbDevice, setSelectedAdbDevice] = useState(null);
  const [trackingStatus, setTrackingStatus] = useState(null); // null | 'pairing' | 'success' | 'warning' | 'error'
  const [trackingMessage, setTrackingMessage] = useState('');
  const [vulnTestMode, setVulnTestMode] = useState(false);

  useEffect(() => {
    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));

    socket.on('scan:device_found', (device) => {
      setDevices((prev) => {
        if (prev.some((d) => d.address === device.address)) return prev;
        return [...prev, device];
      });
    });

    socket.on('scan:status', () => setScanning(true));

    socket.on('scan:complete', () => setScanning(false));

    socket.on('scan:error', (data) => {
      setScanning(false);
      console.error('Scan error:', data.message);
    });

    socket.on('exploit:stage', (entry) => {
      setLogEntries((prev) => [...prev, entry]);
    });

    socket.on('exploit:notification', (entry) => {
      setLogEntries((prev) => [
        ...prev,
        {
          stage: 'notification',
          message: `Received ${entry.length}B: ${entry.hex} (entropy: ${entry.entropy})`,
          status: 'success',
          timestamp: entry.timestamp,
        },
      ]);
    });

    socket.on('exploit:result', (res) => {
      setResult(res);
      setExploitRunning(false);
      setDeviceStatuses((prev) => ({
        ...prev,
        [res.br_edr_address || selectedDevice?.address]: res.vulnerable
          ? 'vulnerable'
          : 'patched',
      }));
    });

    socket.on('exploit:error', (data) => {
      setLogEntries((prev) => [
        ...prev,
        {
          stage: 'error',
          message: data.message,
          status: 'error',
          timestamp: new Date().toISOString(),
        },
      ]);
      setExploitRunning(false);
    });

    socket.on('adb:devices', (data) => {
      setAdbDevices(data.devices || []);
      if (data.devices.length === 1 && !selectedAdbDevice) {
        setSelectedAdbDevice(data.devices[0].id);
      }
    });

    socket.on('adb:status', (entry) => {
      if (entry.stage === 'complete') {
        setTrackingStatus(entry.status === 'success' ? 'success' : 'warning');
        setTrackingMessage(entry.message);
      } else if (entry.status === 'error') {
        setTrackingStatus('error');
        setTrackingMessage(entry.message);
      }
      setLogEntries((prev) => [...prev, {
        stage: `adb:${entry.stage}`,
        message: entry.message,
        status: entry.status,
        timestamp: new Date().toISOString(),
      }]);
    });

    return () => {
      socket.off('connect');
      socket.off('disconnect');
      socket.off('scan:device_found');
      socket.off('scan:status');
      socket.off('scan:complete');
      socket.off('scan:error');
      socket.off('exploit:stage');
      socket.off('exploit:notification');
      socket.off('exploit:result');
      socket.off('exploit:error');
      socket.off('adb:devices');
      socket.off('adb:status');
    };
  }, [selectedDevice]);

  useEffect(() => {
    if (!connected) return;
    socket.emit('adb:scan');
    const interval = setInterval(() => socket.emit('adb:scan'), 10000);
    return () => clearInterval(interval);
  }, [connected]);

  const handleScan = useCallback(() => {
    setDevices([]);
    setScanning(true);
    socket.emit('scan:start', { duration: 10 });
  }, []);

  const handleTarget = useCallback((device) => {
    setSelectedDevice(device || null);
    setLogEntries([]);
    setResult(null);
  }, []);

  const handleExecute = useCallback((address, strategies) => {
    setLogEntries([]);
    setResult(null);
    setExploitRunning(true);
    setDeviceStatuses((prev) => ({ ...prev, [address]: 'in_progress' }));
    socket.emit('exploit:start', { address, strategies });
  }, []);

  const handleStop = useCallback(() => {
    socket.emit('exploit:stop');
    setExploitRunning(false);
  }, []);

  const handleVulnTest = useCallback((address, strategies) => {
    setLogEntries([]);
    setResult(null);
    setExploitRunning(true);
    setDeviceStatuses((prev) => ({ ...prev, [address]: 'in_progress' }));
    socket.emit('vuln_test:start', { address, strategies });
  }, []);

  const handleSelectAdbDevice = useCallback((deviceId) => {
    setSelectedAdbDevice(deviceId);
    socket.emit('adb:select', { device_id: deviceId });
  }, []);

  const handleTrack = useCallback(() => {
    if (!result?.br_edr_address) return;
    setTrackingStatus('pairing');
    setTrackingMessage('');
    socket.emit('adb:pair', {
      device_id: selectedAdbDevice,
      br_edr_address: result.br_edr_address,
    });
  }, [selectedAdbDevice, result]);

  return (
    <div className="app">
      <TopBar
        connected={connected}
        scanning={scanning}
        onScan={handleScan}
        adbDevices={adbDevices}
        selectedAdbDevice={selectedAdbDevice}
        onSelectAdbDevice={handleSelectAdbDevice}
      />
      <main className="main-layout">
        <DevicePanel
          devices={devices}
          deviceStatuses={deviceStatuses}
          selectedDevice={selectedDevice}
          onTarget={handleTarget}
        />
        <ExploitPanel
          device={selectedDevice}
          exploitRunning={exploitRunning}
          logEntries={logEntries}
          result={result}
          onExecute={handleExecute}
          onStop={handleStop}
          onVulnTest={handleVulnTest}
          vulnTestMode={vulnTestMode}
          onToggleMode={() => setVulnTestMode((prev) => !prev)}
          trackingStatus={trackingStatus}
          trackingMessage={trackingMessage}
          onTrack={handleTrack}
          adbConnected={adbDevices.some((d) => d.status === 'device')}
        />
      </main>
    </div>
  );
}

export default App;
