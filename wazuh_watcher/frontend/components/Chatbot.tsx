'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { sendChatMessage, ChatMessage } from '@/lib/api';
import { PipelineResult } from '@/types';

interface Props {
  data: PipelineResult | null;
}

// Very lightweight markdown → HTML converter (no external deps)
function renderMarkdown(text: string): string {
  return text
    // Code blocks (``` ... ```)
    .replace(/```[\w]*\n?([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
    // Inline code
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Bold **text**
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    // Italic *text*
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    // H3 ###
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    // H2 ##
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    // H1 #
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    // Bullet points - item
    .replace(/^[-•] (.+)$/gm, '<li>$1</li>')
    // Wrap consecutive <li> in <ul>
    .replace(/(<li>.*<\/li>\n?)+/g, (m) => `<ul>${m}</ul>`)
    // Line breaks → <br> (except inside pre/ul/h*)
    .replace(/\n(?!<\/?(ul|li|pre|h[123]|code))/g, '<br/>');
}

interface DisplayMessage {
  role: 'user' | 'model';
  content: string;
  id: string;
}

const SUGGESTED_QUESTIONS = [
  'Summarise all anomalies detected',
  'Why was the top anomaly flagged?',
  'What MITRE ATT&CK tactics are active?',
  'Compare anomalies to normal baseline logs',
  'Are there any attack campaigns (clusters)?',
];

export default function Chatbot({ data }: Props) {
  const [open, setOpen]           = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [messages, setMessages]   = useState<DisplayMessage[]>([]);
  const [history, setHistory]     = useState<ChatMessage[]>([]);
  const [input, setInput]         = useState('');
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState<string | null>(null);

  const bottomRef  = useRef<HTMLDivElement>(null);
  const inputRef   = useRef<HTMLTextAreaElement>(null);
  const messageIdCounter = useRef(0);

  const nextId = () => `msg-${++messageIdCounter.current}`;

  // Auto-scroll to latest message
  useEffect(() => {
    if (open && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, loading, open]);

  // Focus input when panel opens
  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [open]);

  const sendMessage = useCallback(async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || loading) return;

    setInput('');
    setError(null);

    const userMsg: DisplayMessage = { role: 'user', content: trimmed, id: nextId() };
    setMessages(prev => [...prev, userMsg]);
    setLoading(true);

    // Build history for API (previous messages)
    const newHistory: ChatMessage[] = [...history, { role: 'user', content: trimmed }];

    try {
      const resp = await sendChatMessage(trimmed, history);

      const assistantMsg: DisplayMessage = {
        role: 'model',
        content: resp.reply,
        id: nextId(),
      };
      setMessages(prev => [...prev, assistantMsg]);

      // Update history with both user and model turns
      setHistory([...newHistory, { role: 'model', content: resp.reply }]);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      // Remove the user message we optimistically added
      setMessages(prev => prev.filter(m => m.id !== userMsg.id));
    } finally {
      setLoading(false);
    }
  }, [loading, history]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  const clearChat = () => {
    setMessages([]);
    setHistory([]);
    setError(null);
  };

  const anomalyCount  = data?.anomaly_count ?? 0;
  const totalAlerts   = data?.total_alerts  ?? 0;
  const contextLoaded = data !== null;

  return (
    <>
      {/* ── Floating Action Button ─────────────────────────────────────────── */}
      <button
        id="chatbot-fab"
        className="chatbot-fab"
        onClick={() => setOpen(v => !v)}
        aria-label="Toggle ATHEA AI Chatbot"
        title="Ask ATHEA — AI Security Analyst"
      >
        {open ? (
          <span className="chatbot-fab-icon">✕</span>
        ) : (
          <>
            <span className="chatbot-fab-icon">🛡</span>
            <span className="chatbot-fab-label">Ask ATHEA</span>
            {anomalyCount > 0 && (
              <span className="chatbot-fab-badge">{anomalyCount}</span>
            )}
          </>
        )}
      </button>

      {/* ── Chat Panel ────────────────────────────────────────────────────── */}
      {open && (
        <div className={`chatbot-panel ${isExpanded ? 'chatbot-expanded' : ''}`} role="dialog" aria-label="ATHEA AI Chatbot">

          {/* Header */}
          <div className="chatbot-header">
            <div className="chatbot-header-left">
              <div>
                <div className="chatbot-title">ATHEA AI Analyst</div>
                <div className="chatbot-subtitle">
                  {contextLoaded
                    ? `${anomalyCount} anomalies · ${totalAlerts} total alerts loaded`
                    : 'Waiting for pipeline data…'}
                </div>
              </div>
            </div>
            <div className="chatbot-header-actions">
              <button
                className="chatbot-action-btn"
                onClick={() => setIsExpanded(v => !v)}
                title={isExpanded ? "Collapse" : "Expand"}
                aria-label={isExpanded ? "Collapse" : "Expand"}
              >
                {isExpanded ? "Collapse" : "Expand"}
              </button>
              {messages.length > 0 && (
                <button
                  className="chatbot-action-btn"
                  onClick={clearChat}
                  title="Clear conversation"
                  aria-label="Clear conversation"
                >
                  Clear
                </button>
              )}
              <button
                className="chatbot-close-btn"
                onClick={() => setOpen(false)}
                aria-label="Close chatbot"
              >
                ✕
              </button>
            </div>
          </div>

          {/* Context indicator */}
          <div className={`chatbot-context-bar ${contextLoaded ? 'loaded' : 'pending'}`}>
            <span className="chatbot-context-dot" />
            {contextLoaded
              ? `Context: ${anomalyCount} anomalies · ${data?.model_used} model · last ${data?.minutes_back}m`
              : 'Pipeline context not yet available — pipeline may still be running'}
          </div>

          {/* Messages */}
          <div className="chatbot-messages" id="chatbot-messages">
            {messages.length === 0 && !loading && (
              <div className="chatbot-welcome">
                <div className="chatbot-welcome-title">ATHEA Security Analyst</div>
                <div className="chatbot-welcome-desc">
                  Ask me about detected anomalies, SHAP explanations, MITRE ATT&amp;CK tactics,
                  or how flagged events compare to normal baseline activity.
                </div>

                {/* Suggested questions */}
                <div className="chatbot-suggestions">
                  {SUGGESTED_QUESTIONS.map((q, i) => (
                    <button
                      key={i}
                      className="chatbot-suggestion-btn"
                      onClick={() => sendMessage(q)}
                      disabled={loading}
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map(msg => (
              <div
                key={msg.id}
                className={`chat-bubble-wrap ${msg.role === 'user' ? 'user' : 'assistant'}`}
              >
                {msg.role === 'model' && (
                  <div className="chat-bubble-avatar">🛡</div>
                )}
                <div className={`chat-bubble ${msg.role === 'user' ? 'chat-bubble-user' : 'chat-bubble-assistant'}`}>
                  {msg.role === 'model' ? (
                    <div
                      className="chat-markdown"
                      dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }}
                    />
                  ) : (
                    <span>{msg.content}</span>
                  )}
                </div>
              </div>
            ))}

            {/* Thinking indicator */}
            {loading && (
              <div className="chat-bubble-wrap assistant">
                <div className="chat-bubble-avatar">🛡</div>
                <div className="chat-bubble chat-bubble-assistant chat-thinking">
                  <span className="thinking-dot" />
                  <span className="thinking-dot" />
                  <span className="thinking-dot" />
                </div>
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="chatbot-error">
                ⚠ {error}
              </div>
            )}

            <div ref={bottomRef} />
          </div>

          {/* Input bar */}
          <div className="chatbot-input-bar">
            <textarea
              ref={inputRef}
              id="chatbot-input"
              className="chatbot-textarea"
              placeholder="Ask about anomalies, SHAP features, MITRE tactics…"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              rows={2}
              disabled={loading}
              aria-label="Chat message input"
            />
            <button
              id="chatbot-send-btn"
              className="chatbot-send-btn"
              onClick={() => sendMessage(input)}
              disabled={loading || !input.trim()}
              aria-label="Send message"
            >
              {loading ? (
                <span className="send-spinner" />
              ) : (
                '↑'
              )}
            </button>
          </div>

          <div className="chatbot-footer">
            Powered by Google Gemini · Press Enter to send · Shift+Enter for newline
          </div>
        </div>
      )}
    </>
  );
}
