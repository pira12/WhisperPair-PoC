import {
  ShieldAlert,
  ShieldCheck,
  Key,
  Link,
  Fingerprint,
} from 'lucide-react';

export default function ResultCard({ result }) {
  if (!result) return null;

  const isVulnerable = result.vulnerable;
  const isTestOnly = result.test_only;

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
            <span className="result-label">Account Key</span>
            <span className={`result-value mono ${result.account_key_written ? 'text-success' : 'text-muted'}`}>
              {result.account_key ? result.account_key : 'N/A'}
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
    </div>
  );
}
