'use client';

import { useState } from 'react';
import { renderMarkdown } from '@/lib/markdown';
import { downloadReportDocx } from '@/lib/api';

interface Props {
  reportText: string;
  onClose: () => void;
}

export default function ReportModal({ reportText, onClose }: Props) {
  const [isDownloading, setIsDownloading] = useState(false);
  const [isCopied, setIsCopied] = useState(false);

  const handleCopy = async () => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(reportText);
      } else {
        // Fallback for non-secure contexts like accessing via local IP
        const textArea = document.createElement("textarea");
        textArea.value = reportText;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        textArea.style.top = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
          document.execCommand('copy');
        } finally {
          textArea.remove();
        }
      }
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy text: ', err);
      alert('Failed to copy report.');
    }
  };

  const handleDownloadDocx = async () => {
    setIsDownloading(true);
    try {
      await downloadReportDocx(reportText);
    } catch (err) {
      console.error('Failed to download DOCX: ', err);
      alert('Failed to download DOCX.');
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <div
      className="drawer-overlay"
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
        backdropFilter: 'blur(4px)', zIndex: 9998,
        display: 'flex', alignItems: 'center', justifyContent: 'center'
      }}
    >
      <div
        className="report-modal"
        onClick={e => e.stopPropagation()}
        style={{
          background: 'var(--bg-surface)', border: '1px solid var(--border)',
          width: '90%', maxWidth: '800px', height: '85vh',
          display: 'flex', flexDirection: 'column', zIndex: 9999,
          boxShadow: '0 24px 48px rgba(0,0,0,0.4)', borderRadius: '8px'
        }}
      >
        <div className="section-header" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 className="section-title">
            <span className="dot" style={{ background: 'var(--primary)' }} />
            Intelligence Report
          </h2>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={handleDownloadDocx}
              disabled={isDownloading}
              style={{
                background: 'var(--primary)', border: '1px solid var(--primary)',
                color: '#ffffff', padding: '6px 12px', cursor: isDownloading ? 'not-allowed' : 'pointer',
                fontSize: 12, borderRadius: '4px', opacity: isDownloading ? 0.7 : 1
              }}
            >
              {isDownloading ? 'Downloading...' : 'Download DOCX'}
            </button>
            <button
              onClick={handleCopy}
              style={{
                background: isCopied ? 'var(--success, #2e7d32)' : 'var(--bg-elevated)', border: '1px solid var(--border)',
                color: isCopied ? '#ffffff' : 'var(--text-primary)', padding: '6px 12px', cursor: 'pointer',
                fontSize: 12, borderRadius: '4px', transition: 'all 0.2s ease'
              }}
            >
              {isCopied ? 'Copied!' : 'Copy Text'}
            </button>
            <button
              onClick={onClose}
              style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', fontSize: 20, cursor: 'pointer' }}
            >
              ✕
            </button>
          </div>
        </div>

        <div
          className="chat-markdown"
          style={{ padding: '24px', overflowY: 'auto', flex: 1, color: 'var(--text-primary)', fontSize: 14, lineHeight: 1.6 }}
          dangerouslySetInnerHTML={{ __html: renderMarkdown(reportText) }}
        />
      </div>
    </div>
  );
}
