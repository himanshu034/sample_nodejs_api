const express = require('express');
const bodyParser = require('body-parser');
const anomalyDetection = require('./anomalyDetection');

const app = express();
const port = 3000;

app.use(bodyParser.json());

app.post('/detect-anomaly', (req, res) => {
  const { data } = req.body;
  const anomalies = anomalyDetection.detectAnomalies(data);
  res.json({ anomalies });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});
