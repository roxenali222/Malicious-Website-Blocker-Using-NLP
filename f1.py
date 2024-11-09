import joblib
import numpy as np
import re
import webbrowser
from urllib.parse import urlparse
from tld import get_tld
from googlesearch import search
import xgboost as xgb
import sklearn
from sklearn.tree import DecisionTreeClassifier

# Check scikit-learn and XGBoost versions
print("scikit-learn version:", sklearn.__version__)
print("XGBoost version:", xgb.__version__)

# Define functions for feature extraction and model analysis

def analyze_url(url):
    # Feature extraction
    features_test = [...]  # Extract features from the URL

    # Load models
    with open('lgb_model.pkl', 'rb') as f:
        loaded_lgb_model = pickle.load(f)

    with open('xgb_model.pkl', 'rb') as f:
        loaded_xgb_model = pickle.load(f)

    # Load Random Forest model using joblib
    loaded_rf_model = joblib.load('rf_model.pkl')

    # Predictions using all three models
    lgb_pred = loaded_lgb_model.predict(features_test)
    xgb_pred = loaded_xgb_model.predict(features_test)
    rf_pred = loaded_rf_model.predict(features_test)

    return lgb_pred[0], xgb_pred[0], rf_pred[0]

def main():
    url = input("Enter the URL: ")

    lgb_pred, xgb_pred, rf_pred = analyze_url(url)

    print("LGBM Prediction:", lgb_pred)
    print("XGBoost Prediction:", xgb_pred)
    print("Random Forest Prediction:", rf_pred)

    # Open URL in web browser if all predictions are safe
    if all(pred == 0 for pred in [lgb_pred, xgb_pred, rf_pred]):
        webbrowser.open_new_tab(url)
    else:
        print("The URL is potentially unsafe.")

if __name__ == '__main__':
    main()
