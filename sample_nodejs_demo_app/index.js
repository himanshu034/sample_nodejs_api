const express = require('express');
const bodyParser = require('body-parser');
const { anomalyDetection } = require('./anomalyDetection');

const app = express();
const port = 3000;

app.use(bodyParser.json());

app.post('/detect-anomaly', (req, res) => {
    const { timeSeriesData } = req.body;
    if (!timeSeriesData) {
        return res.status(400).send('Time series data is required');
    }
    const anomalies = anomalyDetection(timeSeriesData);
    res.json({ anomalies });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
