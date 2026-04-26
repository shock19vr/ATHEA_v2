import pandas as pd
import sys
import os
import matplotlib.pyplot as plt
from unittest.mock import patch

# Add root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

try:
    from cicflowmeter3 import extract_flows_from_pcap
    from train_model4 import detect_anomalies
except ImportError:
    print("Could not import analysis modules. Ensure paths are correct.")

def analyze_pcap_file(pcap_path, output_csv_path):
    print(f"Analyzing {pcap_path} -> {output_csv_path}")
    
    # 1. Extract flows
    try:
        extract_flows_from_pcap(pcap_path, output_csv_path)
    except Exception as e:
        print(f"Error extracting flows: {e}")
        return {"error": str(e)}

    # 2. Run anomaly detection
    # We patch plt.show to avoid blocking
    anomalies_data = []
    try:
        with patch('matplotlib.pyplot.show'):
            # detect_anomalies expects the CSV path
            anomalies_df = detect_anomalies(output_csv_path)
            
            if anomalies_df is not None and not anomalies_df.empty:
                # Replace NaN with null for JSON compatibility
                anomalies_df = anomalies_df.where(pd.notnull(anomalies_df), None)
                anomalies_data = anomalies_df.to_dict(orient='records')
    except Exception as e:
        print(f"Error in anomaly detection: {e}")
        return {"error": str(e)}

    return anomalies_data
