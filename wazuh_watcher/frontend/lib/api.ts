import { PipelineResult, ApiStatus } from '@/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL;

export async function fetchLatest(): Promise<PipelineResult> {
  const res = await fetch(`${API_BASE}/api/latest`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
  return res.json();
}

export async function fetchStatus(): Promise<ApiStatus> {
  const res = await fetch(`${API_BASE}/api/status`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

export async function triggerAnalysis(minutesBack = 60): Promise<PipelineResult> {
  const res = await fetch(`${API_BASE}/api/analyze?minutes_back=${minutesBack}`, {
    method: 'POST',
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ── Chatbot ──────────────────────────────────────────────────────────────────

export interface ChatMessage {
  role: 'user' | 'model';
  content: string;
}

export interface ChatResponse {
  reply: string;
  model: string;
  context_loaded: boolean;
}

export async function sendChatMessage(
  message: string,
  history: ChatMessage[],
): Promise<ChatResponse> {
  const res = await fetch(`${API_BASE}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, history }),
    cache: 'no-store',
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Chat API ${res.status}: ${text}`);
  }
  return res.json();
}
