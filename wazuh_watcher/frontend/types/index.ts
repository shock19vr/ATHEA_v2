export interface ShapValue {
  feature: string;
  shap_value: number;
  alert_value: number;
  abs_impact: number;
  direction: string;
}

export interface Alert {
  doc_id: string;
  timestamp: string;
  rule_id: string;
  rule_level: number;
  rule_description: string;
  rule_groups: string[];
  mitre_ids: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  agent_id: string;
  agent_name: string;
  agent_ip: string;
  manager_name: string;
  event_id: string;
  computer: string;
  channel: string;
  process_id: string;
  provider_name: string;
  target_user: string;
  subject_user: string;
  command_line: string;
  parent_cmd: string;
  src_ip: string;
  src_port: string;
  full_log: string;
  location: string;
  decoder_name: string;
  // ML outputs
  anomaly: number | null;
  anomaly_score: number | null;
  confidence: 'High' | 'Medium' | 'Low' | null;
  cluster_id: number | null;
  mitre_stage: string | null;
  shap_values: ShapValue[];
}

export interface PipelineResult {
  pipeline_version: string;
  minutes_back: number;
  total_alerts: number;
  anomaly_count: number;
  normal_count: number;
  model_used: string;
  contamination_used: number;
  confidence_distribution: Record<string, number>;
  top_mitre_stages: [string, number][];
  feature_columns: string[];
  alerts: Alert[];
}

export interface ApiStatus {
  poll_running: boolean;
  poll_interval_sec: number;
  last_poll_time: string | null;
  last_alert_count: number;
  last_anomaly_count: number;
  has_cached_results: boolean;
}
