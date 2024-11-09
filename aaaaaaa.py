import streamlit as st
import pickle
import joblib
import numpy as np
import re
from urllib.parse import urlparse
from tld import get_tld
from googlesearch import search

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' 
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    if match:
        return 1
    else:
        return 0

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

def google_index(url):
    site = search(url, 5)
    return 1 if site else 0

def count_dot(url):
    return url.count('.')

def count_www(url):
    return url.count('www')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits += 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters += 1
    return letters

def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

def analyze_url(url):
    features_test = [
        having_ip_address(url), abnormal_url(url), count_dot(url), count_www(url), count_atrate(url),
        no_of_dir(url), no_of_embed(url), shortening_service(url), count_https(url), count_http(url),
        count_per(url), count_ques(url), count_hyphen(url), count_equal(url), url_length(url),
        hostname_length(url), suspicious_words(url), digit_count(url), letter_count(url), fd_length(url),
        tld_length(get_tld(url, fail_silently=True))
    ]
    features_test = np.array(features_test).reshape((1, -1))
    
    # Load models
    loaded_lgb_model = joblib.load('lgb_model.pkl')
    with open('lgb_model.pkl', 'rb') as f:
        loaded_lgb_model = pickle.load(f)
        
    loaded_xgb_model = joblib.load('xgb_model.pkl')
    with open('xgb_model.pkl', 'rb') as f:
        loaded_xgb_model = pickle.load(f)
    
    with open('rf_model.pkl', 'rb') as f:
        loaded_rf_model = pickle.load(f)

    # Predictions using all three models
    lgb_pred = loaded_lgb_model.predict(features_test)
    xgb_pred = loaded_xgb_model.predict(features_test)
    rf_pred = loaded_rf_model.predict(features_test)

    return lgb_pred[0], xgb_pred[0], rf_pred[0]

def main():
    st.title('URL Analyzer')

    # Get user input
    url = st.text_input('Enter the URL')

    # Define categories and corresponding labels
    categories = {
        0: "Benign",
        1: "Defacement",
        2: "Malware",
        3: "Phishing",
    }

    model_accuracies = {
        "LGBM": 95,
        "XGBoost": 92,
        "Random Forest": 90
    }

    # Display the URL
    if url:
        st.subheader('Entered URL:')
        st.write(url)

    # Add button to analyze URL
    if st.button('Analyze URL'):
        lgb_pred, xgb_pred, rf_pred = analyze_url(url)

        # Display predictions and categories
        st.subheader('Predictions:')
        st.write(f"LGBM Prediction: {categories[lgb_pred]}")
        st.write(f"XGBoost Prediction: {categories[xgb_pred]}")
        st.write(f"Random Forest Prediction: {categories[rf_pred]}")

        # Display model accuracies
        st.subheader('Model Accuracies:')
        for model, accuracy in model_accuracies.items():
            st.write(f"{model} Accuracy: {accuracy}%")

if __name__ == '__main__':
    main()
