import { useEffect, useRef } from 'react';
import { CheckCircle, XCircle, AlertTriangle, Loader, Terminal } from 'lucide-react';

function StatusIcon({ status }) {
  switch (status) {
    case 'success':
      return <CheckCircle size={14} className="log-icon icon-success" />;
    case 'error':
      return <XCircle size={14} className="log-icon icon-error" />;
    case 'warning':
      return <AlertTriangle size={14} className="log-icon icon-warning" />;
    case 'running':
      return <Loader size={14} className="log-icon icon-running spin" />;
    default:
      return <Loader size={14} className="log-icon icon-running" />;
  }
}

export default function LiveLog({ entries }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [entries]);

  return (
    <div className="live-log">
      <div className="log-header">
        <Terminal size={16} />
        <h3>Live Log</h3>
      </div>
      <div className="log-entries">
        {entries.length === 0 ? (
          <div className="log-empty">Waiting for exploit execution...</div>
        ) : (
          entries.map((entry, i) => (
            <div key={i} className={`log-entry log-${entry.status}`}>
              <StatusIcon status={entry.status} />
              <span className="log-time">
                {entry.timestamp
                  ? new Date(entry.timestamp).toLocaleTimeString()
                  : ''}
              </span>
              <span className="log-stage">[{entry.stage}]</span>
              <span className="log-message">{entry.message}</span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
