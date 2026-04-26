import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Wazuh-ATHEA | XAI Anomaly Detection',
  description:
    'Real-time Wazuh alert anomaly detection dashboard powered by Ensemble ML and SHAP explainability',
  keywords: ['Wazuh', 'SIEM', 'SOC', 'anomaly detection', 'XAI', 'SHAP'],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
