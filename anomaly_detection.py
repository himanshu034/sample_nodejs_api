import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

# Function to detect anomalies in time series data
def detect_anomalies(data, contamination=0.01):
    # Reshape data for model
    data = data.values.reshape(-1, 1)
    
    # Initialize the model
    model = IsolationForest(contamination=contamination)
    
    # Fit the model
    model.fit(data)
    
    # Predict anomalies
    anomalies = model.predict(data)
    
    # Create a DataFrame with the results
    results = pd.DataFrame(data, columns=['value'])
    results['anomaly'] = anomalies
    results['anomaly'] = results['anomaly'].apply(lambda x: 1 if x == -1 else 0)
    
    return results

# Example usage
if __name__ == "__main__":
    # Generate sample data
    np.random.seed(42)
    normal_data = np.random.normal(0, 1, 1000)
    anomaly_data = np.random.normal(0, 10, 20)
    data = np.concatenate([normal_data, anomaly_data])
    data = pd.Series(data)
    
    # Detect anomalies
    results = detect_anomalies(data)
    
    # Plot results
    plt.figure(figsize=(10, 6))
    plt.plot(data, label='Data')
    plt.scatter(results[results['anomaly'] == 1].index, data[results['anomaly'] == 1], color='red', label='Anomalies')
    plt.legend()
    plt.show()