import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

# Function to read and preprocess the dataset
def preprocess_data(file_path):
    # Read the dataset
    data = pd.read_csv(file_path)
    
    # Ensure the data is sorted by time
    data = data.sort_values(by='timestamp')
    
    # Fill missing values if any
    data = data.fillna(method='ffill').fillna(method='bfill')
    
    return data

# Function to detect anomalies using Isolation Forest
def detect_anomalies(data):
    # Initialize the Isolation Forest model
    model = IsolationForest(contamination=0.01)
    
    # Fit the model
    data['anomaly'] = model.fit_predict(data[['value']])
    
    return data

# Main function to execute the anomaly detection workflow
def main(input_file, output_file):
    # Preprocess the data
    data = preprocess_data(input_file)
    
    # Detect anomalies
    data = detect_anomalies(data)
    
    # Save the results to a new CSV file
    data.to_csv(output_file, index=False)
    
    print(f'Anomaly detection complete. Results saved to {output_file}')

if __name__ == "__main__":
    input_file = 'path_to_your_input_file.csv'
    output_file = 'path_to_your_output_file.csv'
    main(input_file, output_file)
