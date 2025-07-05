from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pickle
import pandas as pd
import numpy as np
import re
import urllib
import requests
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import logging
from datetime import datetime

from nameserver_scrape import get_nameservers

from feature_extractor import (
    url_length as fe_url_length, 
    get_domain as fe_get_domain, 
    having_ip_address as fe_having_ip_address, 
    count_dots as fe_count_dots, 
    count_exclamination as fe_count_exclamination,
    count_equal as fe_count_equal, 
    count_slash as fe_count_slash, 
    check_www as fe_check_www, 
    ratio_digits as fe_ratio_digits, 
    tld_in_subdomain as fe_tld_in_subdomain,
    prefix_suffix as fe_prefix_suffix, 
    shortest_word_length as fe_shortest_word_length, 
    longest_word_length as fe_longest_word_length, 
    phish_hints as fe_phish_hints,
    is_URL_accessible as fe_is_URL_accessible, 
    extract_data_from_URL_selenium as fe_extract_data_from_URL_selenium,
    extract_data_from_URL_fallback as fe_extract_data_from_URL_fallback,
    h_total as fe_h_total, 
    internal_hyperlinks as fe_internal_hyperlinks,
    empty_title as fe_empty_title, 
    domain_in_title as fe_domain_in_title, 
    domain_age as fe_domain_age, 
    google_index as fe_google_index, 
    page_rank as fe_page_rank,
    words_raw_extraction as fe_words_raw_extraction, 
    HINTS as FE_HINTS
)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables for model and components
model = None
scaler = None
features = None
model_info = None

def convert_numpy_types(obj):
    """Convert numpy types to Python native types for JSON serialization"""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    else:
        return obj

def load_model():
    """Load the saved model and related components"""
    global model, scaler, features, model_info
    
    try:
        # Load the model
        model = joblib.load('model/phishing_detection_model.pkl')
        logger.info("✓ Model loaded successfully")
        
        # Load the scaler
        scaler = joblib.load('model/scaler.pkl')
        logger.info("✓ Scaler loaded successfully")
        
        # Load the features
        with open('model/selected_features.pkl', 'rb') as f:
            features = pickle.load(f)
        logger.info("✓ Features loaded successfully")
        
        # Load model info
        with open('model/model_info.pkl', 'rb') as f:
            model_info = pickle.load(f)
        logger.info("✓ Model info loaded successfully")
        
        return True
        
    except FileNotFoundError as e:
        logger.error(f"❌ Error: {e}")
        logger.error("Make sure you have the following files:")
        logger.error("- phishing_detection_model.pkl")
        logger.error("- scaler.pkl")
        logger.error("- selected_features.pkl")
        logger.error("- model_info.pkl")
        return False

def extract_features_from_url(url):
    """Extract features from a URL using functions from feature_extractor.py"""
    logger.info(f"Extracting features from: {url}")
    
    try:
        # Basic URL parsing using feature_extractor functions
        hostname, domain, path = fe_get_domain(url)
        extracted_domain = tldextract.extract(url)
        domain_name = extracted_domain.domain + '.' + extracted_domain.suffix
        subdomain = extracted_domain.subdomain
        tld = extracted_domain.suffix
        
        # Handle cases where domain extraction fails
        if not domain_name or domain_name == '.':
            # Fallback to hostname from URL parsing
            parsed = urlparse(url)
            domain_name = parsed.hostname or 'unknown'
            subdomain = ''
            tld = ''
        
        # Extract words using feature_extractor function
        words_raw, words_raw_host, words_raw_path = fe_words_raw_extraction(
            extracted_domain.domain, subdomain, path
        )
        
        # Initialize features dictionary
        features_dict = {}
        
        # Extract basic features using feature_extractor functions
        features_dict['length_url'] = fe_url_length(url)
        features_dict['length_hostname'] = len(hostname) if hostname else 0
        features_dict['ip'] = fe_having_ip_address(url)
        features_dict['nb_dots'] = fe_count_dots(hostname) if hostname else 0
        features_dict['nb_qm'] = fe_count_exclamination(url)
        features_dict['nb_eq'] = fe_count_equal(url)
        features_dict['nb_slash'] = fe_count_slash(url)
        features_dict['nb_www'] = fe_check_www(words_raw)
        features_dict['ratio_digits_url'] = fe_ratio_digits(url)
        features_dict['ratio_digits_host'] = fe_ratio_digits(hostname) if hostname else 0
        features_dict['tld_in_subdomain'] = fe_tld_in_subdomain(tld, subdomain)
        features_dict['prefix_suffix'] = fe_prefix_suffix(hostname) if hostname else 0
        features_dict['shortest_word_host'] = fe_shortest_word_length(words_raw_host)
        features_dict['longest_words_raw'] = fe_longest_word_length(words_raw)
        features_dict['longest_word_path'] = fe_longest_word_length(words_raw_path)
        features_dict['phish_hints'] = fe_phish_hints(url)

        # Initialize extracted_content
        extracted_content = {}
        
        # Initialize data structures for extract_data_from_URL
        Href = {'internals': [], 'externals': [], 'null': []}
        Link = {'internals': [], 'externals': [], 'null': []}
        Anchor = {'safe': [], 'unsafe': [], 'null': []}
        Media = {'internals': [], 'externals': [], 'null': []}
        Form = {'internals': [], 'externals': [], 'null': []}
        CSS = {'internals': [], 'externals': [], 'null': []}
        Favicon = {'internals': [], 'externals': [], 'null': []}
        IFrame = {'visible': [], 'invisible': [], 'null': []}
        Title = ''
        Text = ''
        
        # Extract data using feature_extractor function with Selenium fallback
        try:
            Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text = fe_extract_data_from_URL_selenium(
                hostname, url, domain_name, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text
            )
            logger.info("Successfully used Selenium for data extraction")
            
            # Extract content using requests for additional features
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                response = requests.get(url, headers=headers, timeout=30, verify=False)
                response.raise_for_status()
                content = response.content
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract content
                extracted_content['forms'] = [str(form) for form in soup.find_all('form')]
                extracted_content['heads'] = [str(head) for head in soup.find_all('head')]
                extracted_content['titles'] = [title.get_text() for title in soup.find_all('title')]
                extracted_content['scripts'] = [script.get_text() for script in soup.find_all('script')]
                    
            except Exception as e:
                logger.warning(f"Failed to extract additional content: {e}")
                # Keep extracted_content as empty dict, don't reassign
                
        except Exception as e:
            logger.warning(f"Selenium failed: {e}, falling back to requests method")
            Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text = fe_extract_data_from_URL_fallback(
                hostname, url, domain_name, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text
            )
            
            # Extract content using requests for additional features
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                response = requests.get(url, headers=headers, timeout=30, verify=False)
                response.raise_for_status()
                content = response.content
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract content
                extracted_content['forms'] = [str(form) for form in soup.find_all('form')]
                extracted_content['heads'] = [str(head) for head in soup.find_all('head')]
                extracted_content['titles'] = [title.get_text() for title in soup.find_all('title')]
                extracted_content['scripts'] = [script.get_text() for script in soup.find_all('script')]
                    
            except Exception as e:
                logger.warning(f"Failed to extract additional content: {e}")
                # Keep extracted_content as empty dict, don't reassign
        
        # Calculate features from extracted data
        features_dict['nb_hyperlinks'] = fe_h_total(Href, Link, Media, Form, CSS, Favicon)
        features_dict['ratio_intHyperlinks'] = fe_internal_hyperlinks(Href, Link, Media, Form, CSS, Favicon)
        features_dict['empty_title'] = fe_empty_title(Title)
        features_dict['domain_in_title'] = fe_domain_in_title(domain_name, Title)
        
        # Additional features using feature_extractor functions
        features_dict['domain_age'] = fe_domain_age(domain_name)
        features_dict['google_index'] = fe_google_index(url)
        features_dict['page_rank'] = fe_page_rank('g08gow00ok4c4o0wocko8kkkok040okcsg0k0oso', domain_name)
        
        return features_dict, extracted_content, domain_name
        
    except Exception as e:
        logger.error(f"Error extracting features from {url}: {str(e)}")
        # Return default values if feature extraction fails
        default_features = {
            'length_url': len(url),
            'length_hostname': 0,
            'ip': 0,
            'nb_dots': 0,
            'nb_qm': 0,
            'nb_eq': 0,
            'nb_slash': 0,
            'nb_www': 0,
            'ratio_digits_url': 0,
            'ratio_digits_host': 0,
            'tld_in_subdomain': 0,
            'prefix_suffix': 0,
            'shortest_word_host': 0,
            'longest_words_raw': 0,
            'longest_word_path': 0,
            'phish_hints': 0,
            'nb_hyperlinks': 0,
            'ratio_intHyperlinks': 0,
            'empty_title': 1,
            'domain_in_title': 1,
            'domain_age': -1,
            'google_index': -1,
            'page_rank': -1
        }
        return default_features, {}, 'unknown'

def predict_phishing(url_features):
    """
    Predict if a URL is phishing or legitimate
    
    Args:
        url_features: Dictionary with extracted features
    
    Returns:
        prediction: 1 for phishing, 0 for legitimate
        probability: Probability of being phishing
    """
    global model, scaler, features
    
    if model is None:
        raise Exception("Model not loaded")
    
    # Create DataFrame with only the required features
    feature_df = pd.DataFrame([url_features])
    
    # Select only the features used by the model
    X = feature_df[features]
    
    # Scale the features
    X_scaled = scaler.transform(X)
    
    # Make prediction
    prediction = model.predict(X_scaled)[0]
    probability = model.predict_proba(X_scaled)[0][1]  # Probability of phishing
    
    return prediction, probability

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'model_loaded': model is not None
    })

@app.route('/predict', methods=['POST'])
def predict():
    """Main prediction endpoint"""
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required',
                'status': 'error'
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({
                'error': 'URL cannot be empty',
                'status': 'error'
            }), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Parse URL and ensure proper format
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        # If no hostname, the URL is invalid
        if not hostname:
            return jsonify({
                'error': 'Invalid URL format',
                'status': 'error',
                'timestamp': datetime.now().isoformat()
            }), 400

        # Add www if missing for common TLDs
        if not hostname.startswith('www.'):
            parts = hostname.split('.')
            if len(parts) == 2 or (len(parts) == 3 and parts[1] in ['co', 'com', 'net', 'org', 'gov', 'edu']):
                url = parsed._replace(netloc='www.' + hostname).geturl()
        
        # Extract features
        url_features, extracted_content, domain_name = extract_features_from_url(url)
        
        # Make prediction
        prediction, probability = predict_phishing(url_features)
        
        # Prepare response
        result = "phishing" if prediction == 1 else "legitimate"
        confidence = probability if prediction == 1 else (1 - probability)
        nameservers = get_nameservers(url)
        
        response = {
            'url': url,
            'prediction': result,
            'confidence': round(float(confidence), 4),
            'domain': domain_name,
            'nameservers': nameservers,
            'phishing_probability': round(float(probability), 4),
            'timestamp': datetime.now().isoformat(),
            'features': {
                'length_url': int(url_features.get('length_url', 0)),
                'ip_address': bool(url_features.get('ip', 0)),
                'nb_dots': int(url_features.get('nb_dots', 0)),
                'phish_hints': int(url_features.get('phish_hints', 0)),
                'nb_hyperlinks': int(url_features.get('nb_hyperlinks', 0)),
                'empty_title': bool(url_features.get('empty_title', 1))
            },
            'extracted_content': extracted_content,
            'status': 'success'
        }
        
        # Convert any remaining numpy types to Python native types
        response = convert_numpy_types(response)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in prediction: {str(e)}")
        return jsonify({
            'error': f'Prediction failed: {str(e)}',
            'status': 'error',
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    """Batch prediction endpoint for multiple URLs"""
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'error': 'URLs array is required',
                'status': 'error'
            }), 400
        
        urls = data['urls']
        
        if not isinstance(urls, list):
            return jsonify({
                'error': 'URLs must be an array',
                'status': 'error'
            }), 400
        
        if len(urls) > 100:  # Limit batch size
            return jsonify({
                'error': 'Maximum 100 URLs allowed per batch',
                'status': 'error'
            }), 400
        
        results = []
        
        for url in urls:
            try:
                url = url.strip()
                
                if not url:
                    results.append({
                        'url': url,
                        'error': 'URL is empty',
                        'status': 'error'
                    })
                    continue
                
                # Add protocol if missing
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url

                # Parse URL and ensure proper format
                parsed = urlparse(url)
                hostname = parsed.hostname
                
                # If no hostname, the URL is invalid
                if not hostname:
                    results.append({
                        'url': url,
                        'error': 'Invalid URL format',
                        'status': 'error'
                    })
                    continue

                # Add www if missing for common TLDs
                if not hostname.startswith('www.'):
                    parts = hostname.split('.')
                    if len(parts) == 2 or (len(parts) == 3 and parts[1] in ['co', 'com', 'net', 'org', 'gov', 'edu']):
                        url = parsed._replace(netloc='www.' + hostname).geturl()
                
                # Extract features
                url_features, extracted_content, domain_name = extract_features_from_url(url)
                
                # Make prediction
                prediction, probability = predict_phishing(url_features)
                
                # Prepare result
                result = "phishing" if prediction == 1 else "legitimate"
                confidence = probability if prediction == 1 else (1 - probability)
                nameservers = get_nameservers(url)
                
                results.append({
                    'url': url,
                    'prediction': result,
                    'domain': domain_name,
                    'nameservers': nameservers,
                    'confidence': round(float(confidence), 4),
                    'phishing_probability': round(float(probability), 4),
                    'status': 'success'
                })
                
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'status': 'error'
                })
        
        response = {
            'results': results,
            'total_urls': len(urls),
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        }
        
        # Convert any remaining numpy types to Python native types
        response = convert_numpy_types(response)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in batch prediction: {str(e)}")
        return jsonify({
            'error': f'Batch prediction failed: {str(e)}',
            'status': 'error',
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/model/info', methods=['GET'])
def model_info_endpoint():
    """Get model information"""
    global model_info
    
    if model_info is None:
        return jsonify({
            'error': 'Model not loaded',
            'status': 'error'
        }), 500
    
    response = {
        'model_type': model_info.get('model_type', 'Unknown'),
        'feature_count': model_info.get('feature_count', 0),
        'features': model_info.get('features', []),
        'accuracy': model_info.get('accuracy', 0),
        'training_samples': model_info.get('training_samples', 0),
        'test_samples': model_info.get('test_samples', 0),
        'model_parameters': model_info.get('model_parameters', {}),
        'status': 'success'
    }
    
    # Convert any remaining numpy types to Python native types
    response = convert_numpy_types(response)
    
    return jsonify(response)

@app.route('/', methods=['GET'])
def index():
    """API documentation"""
    return jsonify({
        'name': 'Phishing Detection API',
        'version': '1.0.0',
        'description': 'API for detecting phishing URLs using XGBoost model',
        'endpoints': {
            'GET /': 'API documentation (this page)',
            'GET /health': 'Health check',
            'POST /predict': 'Predict single URL',
            'POST /predict/batch': 'Predict multiple URLs',
            'GET /model/info': 'Get model information'
        },
        'usage': {
            'single_prediction': {
                'method': 'POST',
                'endpoint': '/predict',
                'body': {'url': 'https://example.com'}
            },
            'batch_prediction': {
                'method': 'POST',
                'endpoint': '/predict/batch',
                'body': {'urls': ['https://example1.com', 'https://example2.com']}
            }
        },
        'status': 'success'
    })

if __name__ == '__main__':
    # Load model on startup
    if load_model():
        logger.info("🚀 Starting Phishing Detection API...")
        app.run(host='0.0.0.0', port=8080, debug=False)
    else:
        logger.error("❌ Failed to load model. API cannot start.")
        exit(1) 