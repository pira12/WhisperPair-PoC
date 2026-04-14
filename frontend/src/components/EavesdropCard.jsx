import {
  Mic,
  Square,
  Download,
  Loader,
  CheckCircle,
  AlertTriangle,
} from 'lucide-react';

export default function EavesdropCard({
  eavesdropStatus,
  eavesdropMessage,
  eavesdropDownload,
  onEavesdrop,
  onEavesdropStop,
}) {
  return (
    <div className="eavesdrop-card">
      <div className="eavesdrop-header">
        <Mic size={14} />
        <h3>Audio Surveillance</h3>
      </div>

      <p className="eavesdrop-desc">
        Live audio from the target earbuds' microphone via force-paired HFP. Plays through phone speaker.
      </p>

      {!eavesdropStatus && (
        <button className="btn btn-eavesdrop" onClick={onEavesdrop}>
          <Mic size={14} />
          Start Live Eavesdrop
        </button>
      )}

      {eavesdropStatus === 'recording' && (
        <div className="eavesdrop-recording">
          <div className="eavesdrop-recording-header">
            <Loader size={13} className="spin" />
            <span>Recording...</span>
            <button className="btn btn-eavesdrop-stop" onClick={onEavesdropStop}>
              <Square size={11} />
              Stop
            </button>
          </div>
          {eavesdropMessage && (
            <div className="eavesdrop-vu">
              <code>{eavesdropMessage}</code>
            </div>
          )}
        </div>
      )}

      {eavesdropStatus === 'stopping' && (
        <div className="eavesdrop-recording">
          <div className="eavesdrop-recording-header">
            <Loader size={13} className="spin" />
            <span>Stopping and saving recording...</span>
          </div>
        </div>
      )}

      {eavesdropStatus === 'success' && (
        <div className="eavesdrop-done">
          <div className="eavesdrop-done-header">
            <CheckCircle size={13} />
            <span>{eavesdropMessage}</span>
          </div>
          {eavesdropDownload && (
            <a
              href={eavesdropDownload}
              download="eavesdrop_recording.wav"
              className="btn btn-eavesdrop-download"
            >
              <Download size={13} />
              Download .wav
            </a>
          )}
          <button className="btn btn-eavesdrop-again" onClick={onEavesdrop}>
            <Mic size={13} />
            Start Again
          </button>
        </div>
      )}

      {(eavesdropStatus === 'warning' || eavesdropStatus === 'error') && (
        <div className="eavesdrop-warning">
          <AlertTriangle size={13} />
          <span>{eavesdropMessage}</span>
          <button className="btn btn-eavesdrop-again" onClick={onEavesdrop}>
            Retry
          </button>
        </div>
      )}
    </div>
  );
}
