# Phishing Detection API

A Flask-based REST API for detecting phishing URLs using an XGBoost machine learning model.

## 🚀 Features

- **Single URL Prediction**: Analyze individual URLs for phishing detection
- **Batch Prediction**: Process multiple URLs at once (up to 100)
- **Real-time Feature Extraction**: Uses your original feature extraction logic
- **RESTful API**: Easy integration with any framework or application
- **CORS Enabled**: Can be called from web applications
- **Health Monitoring**: Built-in health check and model status endpoints

## 📋 Prerequisites

1. **Python 3.8+**
2. **Model Files**: Make sure you have the following files in your project directory:
   - `phishing_detection_model.pkl` (trained XGBoost model)
   - `scaler.pkl` (StandardScaler)
   - `selected_features.pkl` (feature list)
   - `model_info.pkl` (model metadata)
   - `feature_extractor.py` (your feature extraction module)

## 🛠️ Installation

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Save your model** (if not already done):
   ```bash
   python save_model.py
   ```

3. **Start the API**:
   ```bash
   python phishing_api.py
   ```

The API will start on `http://localhost:5000`

## 📡 API Endpoints

### 1. Health Check
```http
GET /health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00",
  "model_loaded": true
}
```

### 2. Single URL Prediction
```http
POST /predict
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Response**:
```json
{
  "url": "https://example.com",
  "prediction": "legitimate",
  "confidence": 0.9234,
  "phishing_probability": 0.0766,
  "timestamp": "2024-01-01T12:00:00",
  "features": {
    "length_url": 22,
    "ip_address": false,
    "nb_dots": 1,
    "phish_hints": 0,
    "nb_hyperlinks": 15,
    "empty_title": false
  },
  "status": "success"
}
```

### 3. Batch URL Prediction
```http
POST /predict/batch
Content-Type: application/json

{
  "urls": [
    "https://example1.com",
    "https://example2.com",
    "https://suspicious-site.com"
  ]
}
```

**Response**:
```json
{
  "results": [
    {
      "url": "https://example1.com",
      "prediction": "legitimate",
      "confidence": 0.9234,
      "phishing_probability": 0.0766,
      "status": "success"
    },
    {
      "url": "https://suspicious-site.com",
      "prediction": "phishing",
      "confidence": 0.8567,
      "phishing_probability": 0.8567,
      "status": "success"
    }
  ],
  "total_urls": 3,
  "timestamp": "2024-01-01T12:00:00",
  "status": "success"
}
```

### 4. Model Information
```http
GET /model/info
```

**Response**:
```json
{
  "model_type": "XGBoost",
  "feature_count": 24,
  "features": ["length_url", "ip", "nb_dots", ...],
  "accuracy": 0.9663,
  "training_samples": 9144,
  "test_samples": 2286,
  "model_parameters": {
    "gamma": 0.1302,
    "learning_rate": 0.0180,
    "max_depth": 19,
    "n_estimators": 499
  },
  "status": "success"
}
```

### 5. API Documentation
```http
GET /
```

Returns API documentation and usage examples.

## 🔧 Integration Examples

### JavaScript (Frontend)
```javascript
// Single URL prediction
async function checkURL(url) {
  const response = await fetch('http://localhost:5000/predict', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url: url })
  });
  
  const result = await response.json();
  console.log(`URL: ${result.url}`);
  console.log(`Prediction: ${result.prediction}`);
  console.log(`Confidence: ${result.confidence}`);
}

// Batch prediction
async function checkMultipleURLs(urls) {
  const response = await fetch('http://localhost:5000/predict/batch', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ urls: urls })
  });
  
  const result = await response.json();
  result.results.forEach(item => {
    console.log(`${item.url}: ${item.prediction} (${item.confidence})`);
  });
}
```

### Python (Backend)
```python
import requests

# Single URL prediction
def check_url(url):
    response = requests.post('http://localhost:5000/predict', 
                           json={'url': url})
    return response.json()

# Batch prediction
def check_multiple_urls(urls):
    response = requests.post('http://localhost:5000/predict/batch', 
                           json={'urls': urls})
    return response.json()

# Example usage
result = check_url('https://example.com')
print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['confidence']}")
```

### cURL
```bash
# Single prediction
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Batch prediction
curl -X POST http://localhost:5000/predict/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example1.com", "https://example2.com"]}'

# Health check
curl http://localhost:5000/health
```

## 🧪 Testing

Run the test suite to verify the API is working:

```bash
python test_api.py
```

This will test all endpoints with sample URLs.

## ⚙️ Configuration

### Environment Variables
- `PORT`: API port (default: 5000)
- `HOST`: API host (default: 0.0.0.0)

### Production Deployment

For production deployment, consider:

1. **WSGI Server**: Use Gunicorn or uWSGI
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 phishing_api:app
   ```

2. **Reverse Proxy**: Use Nginx or Apache

3. **Environment Variables**: Set production environment variables

4. **SSL/TLS**: Enable HTTPS for security

## 🔒 Security Considerations

- The API is designed for internal use or behind a reverse proxy
- Consider adding authentication for production use
- Rate limiting may be needed for public APIs
- Input validation is implemented but can be enhanced

## 📊 Response Codes

- `200`: Success
- `400`: Bad Request (missing URL, invalid input)
- `500`: Internal Server Error (model not loaded, prediction failed)

## 🐛 Troubleshooting

1. **Model not loaded**: Ensure all `.pkl` files are in the project directory
2. **Import errors**: Check that `feature_extractor.py` is present
3. **Port already in use**: Change the port in `phishing_api.py`
4. **CORS issues**: The API has CORS enabled, but check your frontend configuration

## 📝 License

This API is part of your phishing detection project. Use responsibly and ensure compliance with relevant regulations. 