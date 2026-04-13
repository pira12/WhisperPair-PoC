import { useState } from 'react';
import { Shield, Info, X } from 'lucide-react';

const STRATEGIES = [
  {
    name: 'RAW_KBP',
    label: 'Raw KBP',
    description: 'Raw unencrypted Key-Based Pairing request. Most common for vulnerable devices.',
    flags: '0x11',
    detail: {
      how: 'Sends a 16-byte Key-Based Pairing request in plaintext directly to the device\'s GFPS characteristic. The request contains the target\'s BLE MAC address and a random 8-byte salt. The salt becomes the shared secret for decrypting the device\'s response.',
      why: 'Vulnerable devices skip Anti-Spoofing Public Key validation and accept raw unencrypted requests even when NOT in pairing mode. This is the core of CVE-2025-36911.',
      flags_detail: 'Bit 0 (INITIATE_BONDING) + Bit 4 (EXTENDED_RESPONSE) = 0x11. Tells the device to start bonding and respond with extended info including the BR/EDR address.',
      payload: '[0x00 Type] [0x11 Flags] [6B Target MAC] [8B Random Salt]',
    },
  },
  {
    name: 'RAW_WITH_SEEKER',
    label: 'Raw + Seeker Address',
    description: 'Raw KBP with seeker address included for bonding initiation.',
    flags: '0x01',
    detail: {
      how: 'Similar to Raw KBP but includes the attacker\'s (seeker) BLE address in the request. This provides the device with a return address for bonding, which some firmware versions require to proceed.',
      why: 'Some devices reject requests without a seeker address. Including it makes the request appear more legitimate and can bypass additional validation checks.',
      flags_detail: 'Bit 0 only (INITIATE_BONDING) = 0x01. Basic bonding request without extended response.',
      payload: '[0x00 Type] [0x01 Flags] [6B Target MAC] [6B Seeker MAC] [2B Salt]',
    },
  },
  {
    name: 'RETROACTIVE',
    label: 'Retroactive Pairing',
    description: 'Retroactive pairing flag bypass. Sets bonding + retroactive bits.',
    flags: '0x0A',
    detail: {
      how: 'Sends a KBP request with the retroactive pairing flag set. This flag is normally used when a device was already paired via classic Bluetooth and the Fast Pair service needs to catch up. The exploit abuses this to skip the normal pairing mode check.',
      why: 'The retroactive flag tells the device "we\'re already bonded, just register the account key." Some firmware trusts this flag without verifying that bonding actually occurred.',
      flags_detail: 'Bit 1 (bonding) + Bit 3 (retroactive pairing) = 0x0A. The retroactive bit bypasses pairing-mode-only restrictions.',
      payload: '[0x00 Type] [0x0A Flags] [6B Target MAC] [6B Seeker MAC] [2B Salt]',
    },
  },
  {
    name: 'EXTENDED_RESPONSE',
    label: 'Extended Response',
    description: 'Requests extended response format from the device.',
    flags: '0x10',
    detail: {
      how: 'Sends a KBP request with only the extended response flag set, without initiating bonding. This asks the device to respond with additional information including the BR/EDR Classic Bluetooth address and supported features.',
      why: 'By requesting only extended info without bonding, some devices respond without full security checks. Even if pairing fails, the BR/EDR address leak is valuable for tracking and follow-up attacks.',
      flags_detail: 'Bit 4 only (EXTENDED_RESPONSE) = 0x10. Requests the device reveal its Classic Bluetooth address and capabilities.',
      payload: '[0x00 Type] [0x10 Flags] [6B Target MAC] [8B Random Salt]',
    },
  },
];

function InfoModal({ strategy, onClose }) {
  return (
    <div className="info-overlay" onClick={onClose}>
      <div className="info-modal" onClick={(e) => e.stopPropagation()}>
        <div className="info-modal-header">
          <div className="info-modal-title">
            <Shield size={16} />
            <h3>{strategy.label}</h3>
            <code className="strategy-flags">{strategy.flags}</code>
          </div>
          <button className="info-close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div className="info-modal-body">
          <div className="info-section">
            <h4>How it works</h4>
            <p>{strategy.detail.how}</p>
          </div>
          <div className="info-section">
            <h4>Why it works</h4>
            <p>{strategy.detail.why}</p>
          </div>
          <div className="info-section">
            <h4>Flags breakdown</h4>
            <p>{strategy.detail.flags_detail}</p>
          </div>
          <div className="info-section">
            <h4>Payload format</h4>
            <code className="info-payload">{strategy.detail.payload}</code>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function StrategySelector({ selected, onChange, disabled }) {
  const [infoStrategy, setInfoStrategy] = useState(null);

  const toggle = (name) => {
    if (disabled) return;
    if (selected.includes(name)) {
      onChange(selected.filter((s) => s !== name));
    } else {
      onChange([...selected, name]);
    }
  };

  return (
    <div className="strategy-selector">
      <div className="strategy-header">
        <Shield size={16} />
        <h3>Exploit Strategies</h3>
      </div>
      <div className="strategy-list">
        {STRATEGIES.map((strat) => (
          <div key={strat.name} className={`strategy-item ${selected.includes(strat.name) ? 'active' : ''} ${disabled ? 'disabled' : ''}`}>
            <label className="strategy-check-area">
              <input
                type="checkbox"
                checked={selected.includes(strat.name)}
                onChange={() => toggle(strat.name)}
                disabled={disabled}
              />
              <div className="strategy-info">
                <div className="strategy-label">
                  <span className="strategy-name">{strat.label}</span>
                  <code className="strategy-flags">{strat.flags}</code>
                </div>
                <span className="strategy-desc">{strat.description}</span>
              </div>
            </label>
            <button
              className="info-btn"
              onClick={() => setInfoStrategy(strat)}
              title={`Info: ${strat.label}`}
            >
              <Info size={15} />
            </button>
          </div>
        ))}
      </div>

      {infoStrategy && (
        <InfoModal
          strategy={infoStrategy}
          onClose={() => setInfoStrategy(null)}
        />
      )}
    </div>
  );
}
