import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

# Load the time series data
def load_data(file_path):
    return pd.read_csv(file_path, parse_dates=True, index_col='timestamp')

# Detect anomalies using Isolation Forest
def detect_anomalies(data):
    model = IsolationForest(contamination=0.01)
    data['anomaly'] = model.fit_predict(data[['value']])
    return data

# Plot the results
def plot_anomalies(data):
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(data.index, data['value'], label='Time Series Data')
    ax.scatter(data[data['anomaly'] == -1].index, data[data['anomaly'] == -1]['value'], color='red', label='Anomalies')
    plt.legend()
    plt.show()

if __name__ == "__main__":
    file_path = 'path_to_your_timeseries_data.csv'  # Update this path
    data = load_data(file_path)
    data = detect_anomalies(data)
    plot_anomalies(data)
