# coding: utf-8
import pandas as pd
from sklearn.model_selection import train_test_split
import numpy as np
import re
from urllib.parse import urlparse
from tld import get_tld
from googlesearch import search
import joblib
import pickle
import xgboost as xgb
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier

# Loading dataset
df = pd.read_csv('balanced_phishing_data.csv')

# Feature Engineering
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

df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))
df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))
df['google_index'] = df['url'].apply(lambda i: google_index(i))
df['count.'] = df['url'].apply(lambda i: count_dot(i))
df['count-www'] = df['url'].apply(lambda i: count_www(i))
df['count@'] = df['url'].apply(lambda i: count_atrate(i))
df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))
df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))
df['short_url'] = df['url'].apply(lambda i: shortening_service(i))
df['count-https'] = df['url'].apply(lambda i: count_https(i))
df['count-http'] = df['url'].apply(lambda i: count_http(i))
df['count%'] = df['url'].apply(lambda i: count_per(i))
df['count?'] = df['url'].apply(lambda i: count_ques(i))
df['count-'] = df['url'].apply(lambda i: count_hyphen(i))
df['count='] = df['url'].apply(lambda i: count_equal(i))
df['url_length'] = df['url'].apply(lambda i: url_length(i))
df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))
df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))
df['count-digits'] = df['url'].apply(lambda i: digit_count(i))
df['count-letters'] = df['url'].apply(lambda i: letter_count(i))
df['fd_length'] = df['url'].apply(lambda i: fd_length(i))
df['tld'] = df['url'].apply(lambda i: get_tld(i, fail_silently=True))
df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))

# Target Encoding
from sklearn.preprocessing import LabelEncoder
lb_make = LabelEncoder()
df["type_code"] = lb_make.fit_transform(df["type"])

# Creation of feature Target
X = df[['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
        'count_dir', 'count_embed_domian', 'short_url', 'count-https',
        'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
        'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits',
        'count-letters']]
y = df['type_code']

# Train Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, shuffle=True, random_state=0)

# Model Building
lgb_model = LGBMClassifier(objective='multiclass', boosting_type='gbdt', n_jobs=5, silent=True, random_state=0)
lgb_model.fit(X_train, y_train)

xgb_model = xgb.XGBClassifier(objective='multi:softmax', num_class=4, n_jobs=5, random_state=0)
xgb_model.fit(X_train, y_train)

rf_model = RandomForestClassifier(n_estimators=100, random_state=0)
rf_model.fit(X_train, y_train)

# Save the models
with open('lgb_model.pkl', 'wb') as f:
    pickle.dump(lgb_model, f)

with open('xgb_model.pkl', 'wb') as f:
    pickle.dump(xgb_model, f)

with open('rf_model.pkl', 'wb') as f:
    pickle.dump(rf_model, f)

# Load the models
with open('lgb_model.pkl', 'rb') as f:
    loaded_lgb_model = pickle.load(f)

with open('xgb_model.pkl', 'rb') as f:
    loaded_xgb_model = pickle.load(f)

with open('rf_model.pkl', 'rb') as f:
    loaded_rf_model = pickle.load(f)

# Prediction Function using the loaded models
def get_prediction_from_url(test_url):
    features_test = [
        having_ip_address(test_url), abnormal_url(test_url), count_dot(test_url), count_www(test_url), count_atrate(test_url),
        no_of_dir(test_url), no_of_embed(test_url), shortening_service(test_url), count_https(test_url), count_http(test_url),
        count_per(test_url), count_ques(test_url), count_hyphen(test_url), count_equal(test_url), url_length(test_url),
        hostname_length(test_url), suspicious_words(test_url), digit_count(test_url), letter_count(test_url), fd_length(test_url),
        tld_length(get_tld(test_url, fail_silently=True))
    ]
    features_test = np.array(features_test).reshape((1, -1))

    # Predictions using the loaded models
    lgb_pred = loaded_lgb_model.predict(features_test)
    xgb_pred = loaded_xgb_model.predict(features_test)
    rf_pred = loaded_rf_model.predict(features_test)

    # Inverse transform predictions
    lgb_pred_label = lb_make.inverse_transform([lgb_pred])[0]
    xgb_pred_label = lb_make.inverse_transform([xgb_pred])[0]
    rf_pred_label = lb_make.inverse_transform([rf_pred])[0]

    return lgb_pred_label, xgb_pred_label, rf_pred_label

# Example Usage
urls = ['https://www.wikipedia.org/','www.chat.openai.com','www.google.com/','www.yahoo.com/']
for url in urls:
    lgb_pred, xgb_pred, rf_pred = get_prediction_from_url(url)
    print(f"URL: {url} -> LGBM Prediction: {lgb_pred}, XGBoost Prediction: {xgb_pred}, Random Forest Prediction: {rf_pred}")