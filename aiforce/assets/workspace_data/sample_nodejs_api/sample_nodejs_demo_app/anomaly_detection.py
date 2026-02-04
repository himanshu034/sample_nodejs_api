# Anomaly Detection in Time Series Data

This code demonstrates how to detect anomalies in time series data using Python. It includes necessary libraries and functions for anomaly detection.

## Requirements

- pandas
- numpy
- matplotlib
- scikit-learn
- statsmodels

You can install these libraries using pip:

```bash
pip install pandas numpy matplotlib scikit-learn statsmodels
```

## Code

```python
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from statsmodels.tsa.seasonal import seasonal_decompose

# Generate synthetic time series data
np.random.seed(42)
dates = pd.date_range(start='2020-01-01', periods=365, freq='D')
data = np.sin(np.linspace(0, 50, 365)) + np.random.normal(scale=0.5, size=365)
df = pd.DataFrame({'date': dates, 'value': data})
df.set_index('date', inplace=True)

# Plot the time series data
plt.figure(figsize=(12, 6))
plt.plot(df['value'], label='Value')
plt.title('Time Series Data')
plt.xlabel('Date')
plt.ylabel('Value')
plt.legend()
plt.show()

# Decompose the time series data
decomposition = seasonal_decompose(df['value'], model='additive', period=30)
trend = decomposition.trend
seasonal = decomposition.seasonal
residual = decomposition.resid

# Plot the decomposed components
plt.figure(figsize=(12, 8))
plt.subplot(411)
plt.plot(df['value'], label='Original')
plt.legend(loc='best')
plt.subplot(412)
plt.plot(trend, label='Trend')
plt.legend(loc='best')
plt.subplot(413)
plt.plot(seasonal, label='Seasonal')
plt.legend(loc='best')
plt.subplot(414)
plt.plot(residual, label='Residual')
plt.legend(loc='best')
plt.tight_layout()
plt.show()

# Detect anomalies using Isolation Forest
model = IsolationForest(contamination=0.05)
df['anomaly'] = model.fit_predict(df[['value']])
df['anomaly'] = df['anomaly'].map({1: 0, -1: 1})

# Plot the anomalies
plt.figure(figsize=(12, 6))
plt.plot(df['value'], label='Value')
plt.scatter(df.index, df['value'], c=df['anomaly'], cmap='coolwarm', label='Anomaly')
plt.title('Anomaly Detection in Time Series Data')
plt.xlabel('Date')
plt.ylabel('Value')
plt.legend()
plt.show()
```
