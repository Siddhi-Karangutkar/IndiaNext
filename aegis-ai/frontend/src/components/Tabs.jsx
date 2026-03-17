import React from 'react';

const TABS = [
  { id: 'phishing',  label: 'PHISHING',        emoji: '🎣' },
  { id: 'injection', label: 'PROMPT INJECTION', emoji: '💉' },
  { id: 'behaviour', label: 'USER BEHAVIOUR',   emoji: '👁' },
  { id: 'url',       label: 'MALICIOUS URL',    emoji: '🔗' },
  { id: 'admin',     label: 'ADMIN MONITOR',    emoji: '🛡' },
];

const Tabs = ({ activeTab, onTabSelect }) => {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: '6px', marginBottom: '24px' }}>
      {TABS.map(tab => {
        const isActive = activeTab === tab.id;
        const isAdmin = tab.id === 'admin';
        return (
          <button
            key={tab.id}
            onClick={() => onTabSelect(tab.id)}
            style={{
              position: 'relative',
              display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center',
              padding: '12px 4px',
              background: isActive
                ? isAdmin ? 'rgba(139,92,246,0.08)' : 'rgba(0,212,255,0.06)'
                : 'var(--s1)',
              border: `0.5px solid ${isActive
                ? isAdmin ? 'var(--purple)' : 'var(--cyan)'
                : 'var(--border)'}`,
              borderRadius: '8px',
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}
          >
            <span style={{ fontSize: '15px', marginBottom: '5px' }}>{tab.emoji}</span>
            <span style={{
              fontSize: '8px', textTransform: 'uppercase',
              letterSpacing: '0.5px',
              fontFamily: 'JetBrains Mono, monospace',
              color: isActive
                ? isAdmin ? 'var(--purple)' : 'var(--cyan)'
                : 'var(--text)',
              fontWeight: isActive ? 700 : 400,
              textAlign: 'center',
              lineHeight: 1.3,
            }}>{tab.label}</span>
          </button>
        );
      })}
    </div>
  );
};

export default Tabs;