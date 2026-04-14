import { useState, useEffect, useCallback, useRef } from 'react';
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
  const [trackingStatus, setTrackingStatus] = useState(null);
  const [trackingMessage, setTrackingMessage] = useState('');
  const [vulnTestMode, setVulnTestMode] = useState(false);
  const [attackMode, setAttackMode] = useState('phone'); // 'phone' | 'laptop'
  const [eavesdropStatus, setEavesdropStatus] = useState(null);
  const [eavesdropMessage, setEavesdropMessage] = useState('');
  const [eavesdropDownload, setEavesdropDownload] = useState(null);
  const [bredrAddress, setBredrAddress] = useState('');
  const audioCtxRef = useRef(null);
  const nextPlayTimeRef = useRef(0);

  // Web Audio API: play raw PCM chunks from earbuds mic
  useEffect(() => {
    socket.on('eavesdrop:audio', (data) => {
      // Decode base64 PCM
      const raw = atob(data.pcm);
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);

      // Create AudioContext on first chunk
      if (!audioCtxRef.current) {
        audioCtxRef.current = new (window.AudioContext || window.webkitAudioContext)({
          sampleRate: data.rate || 8000,
        });
        nextPlayTimeRef.current = audioCtxRef.current.currentTime;
      }
      const ctx = audioCtxRef.current;

      // Convert 16-bit PCM to float32
      const view = new DataView(bytes.buffer);
      const numSamples = Math.floor(bytes.length / 2);
      const audioBuffer = ctx.createBuffer(1, numSamples, data.rate || 8000);
      const channel = audioBuffer.getChannelData(0);
      for (let i = 0; i < numSamples; i++) {
        channel[i] = view.getInt16(i * 2, true) / 32768;
      }

      // Schedule playback
      const source = ctx.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(ctx.destination);

      const now = ctx.currentTime;
      if (nextPlayTimeRef.current < now) {
        nextPlayTimeRef.current = now;
      }
      source.start(nextPlayTimeRef.current);
      nextPlayTimeRef.current += audioBuffer.duration;
    });

    return () => {
      socket.off('eavesdrop:audio');
    };
  }, []);

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
        { stage: 'error', message: data.message, status: 'error', timestamp: new Date().toISOString() },
      ]);
      setExploitRunning(false);
    });

    socket.on('adb:devices', (data) => {
      setAdbDevices(data.devices || []);
      if (data.devices.length === 1 && !selectedAdbDevice) {
        setSelectedAdbDevice(data.devices[0].id);
      }
    });

    socket.on('track:status', (entry) => {
      if (entry.stage === 'complete') {
        setTrackingStatus(entry.status === 'success' ? 'success' : 'warning');
        setTrackingMessage(entry.message);
      } else if (entry.status === 'error') {
        setTrackingStatus('error');
        setTrackingMessage(entry.message);
      } else {
        setTrackingMessage(entry.message);
      }
      setLogEntries((prev) => [...prev, {
        stage: `track:${entry.stage}`,
        message: entry.message,
        status: entry.status,
        timestamp: new Date().toISOString(),
      }]);
    });

    socket.on('eavesdrop:status', (entry) => {
      if (entry.stage === 'complete') {
        setEavesdropStatus(entry.status === 'success' ? 'success' : 'warning');
        setEavesdropMessage(entry.message);
        if (entry.download_url) {
          setEavesdropDownload(entry.download_url);
        }
      } else if (entry.stage === 'stopping') {
        setEavesdropStatus('stopping');
        setEavesdropMessage(entry.message);
      } else if (entry.status === 'error') {
        setEavesdropStatus('error');
        setEavesdropMessage(entry.message);
      } else {
        setEavesdropStatus('recording');
        setEavesdropMessage(entry.message);
      }
      setLogEntries((prev) => [...prev, {
        stage: `eavesdrop:${entry.stage}`,
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
      socket.off('track:status');
      socket.off('eavesdrop:status');
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
    setTrackingStatus(null);
    setTrackingMessage('');
    setEavesdropStatus(null);
    setEavesdropMessage('');
    setEavesdropDownload(null);
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
    setTrackingStatus(null);
    setTrackingMessage('');
    setEavesdropStatus(null);
    setEavesdropMessage('');
    setEavesdropDownload(null);
    setExploitRunning(true);
    setDeviceStatuses((prev) => ({ ...prev, [address]: 'in_progress' }));
    socket.emit('vuln_test:start', { address, strategies });
  }, []);

  const handleSelectAdbDevice = useCallback((deviceId) => {
    setSelectedAdbDevice(deviceId);
    socket.emit('adb:select', { device_id: deviceId });
  }, []);

  const handleTrack = useCallback((inputBredr) => {
    if (!result?.br_edr_address) return;
    if (inputBredr) setBredrAddress(inputBredr);
    setTrackingStatus('scanning');
    setTrackingMessage('');
    socket.emit('track:start', {
      mode: attackMode,
      device_id: selectedAdbDevice,
      ble_address: selectedDevice?.address,
      bredr_address: inputBredr || result.br_edr_address,
      device_name: selectedDevice?.name,
      model_id: result.model_id,
    });
  }, [selectedAdbDevice, selectedDevice, result, attackMode]);

  const handleEavesdrop = useCallback(() => {
    const addr = bredrAddress || result?.br_edr_address;
    if (!addr) return;
    setEavesdropStatus('recording');
    setEavesdropMessage('');
    setEavesdropDownload(null);
    socket.emit('eavesdrop:start', {
      mode: attackMode,
      device_id: selectedAdbDevice,
      address: addr,
    });
  }, [selectedAdbDevice, result, bredrAddress, attackMode]);

  const handleEavesdropStop = useCallback(() => {
    socket.emit('eavesdrop:stop');
    if (audioCtxRef.current) {
      audioCtxRef.current.close();
      audioCtxRef.current = null;
      nextPlayTimeRef.current = 0;
    }
  }, []);

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
          attackMode={attackMode}
          onAttackModeChange={setAttackMode}
          trackingStatus={trackingStatus}
          trackingMessage={trackingMessage}
          onTrack={handleTrack}
          adbConnected={adbDevices.some((d) => d.status === 'device')}
          bredrAddress={bredrAddress}
          onBredrAddressChange={setBredrAddress}
          eavesdropStatus={eavesdropStatus}
          eavesdropMessage={eavesdropMessage}
          eavesdropDownload={eavesdropDownload}
          onEavesdrop={handleEavesdrop}
          onEavesdropStop={handleEavesdropStop}
        />
      </main>
    </div>
  );
}

export default App;
