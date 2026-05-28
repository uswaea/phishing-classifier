import streamlit as st
import joblib
import numpy as np
from urllib.parse import urlparse
import re

# Load model, scaler, features
model = joblib.load('best_model.pkl')
scaler = joblib.load('scaler.pkl')
feature_names = joblib.load('feature_names.pkl')

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    full = url

    features = {
        'URLLength': len(full),
        'DomainLength': len(domain),
        'IsDomainIP': 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) else 0,
        'TLDLegitimateProb': 0.5,  # neutral default
        'URLCharProb': len(re.findall(r'[a-zA-Z0-9]', full)) / len(full) if len(full) > 0 else 0,
        'TLDLength': len(domain.split('.')[-1]) if '.' in domain else 0,
        'NoOfSubDomain': max(0, len(domain.split('.')) - 2),
        'HasObfuscation': 1 if '%' in full or '0x' in full else 0,
        'ObfuscationRatio': full.count('%') / len(full) if len(full) > 0 else 0,
        'IsHTTPS': 1 if parsed.scheme == 'https' else 0,
        'LineOfCode': 0,
        'LargestLineLength': 0,
        'DegitRatioInURL': len(re.findall(r'\d', full)) / len(full) if len(full) > 0 else 0,
        'LetterRatioInURL': len(re.findall(r'[a-zA-Z]', full)) / len(full) if len(full) > 0 else 0,
        'SpacialCharRatioInURL': len(re.findall(r'[^a-zA-Z0-9]', full)) / len(full) if len(full) > 0 else 0,
        'CharContinuationRate': 0.5,
        'NoOfLettersInURL': len(re.findall(r'[a-zA-Z]', full)),
        'NoOfDegitsInURL': len(re.findall(r'\d', full)),
        'NoOfEqualsInURL': full.count('='),
        'NoOfQMarkInURL': full.count('?'),
        'NoOfAmpersandInURL': full.count('&'),
        'NoOfOtherSpecialCharsInURL': len(re.findall(r'[^a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]', full))
    }

    return np.array([features[f] for f in feature_names]).reshape(1, -1)


# UI
st.set_page_config(page_title="Phishing URL Classifier", page_icon="🔐")
st.title("🔐 Phishing URL Classifier")
st.write("Enter a URL below to check if it is phishing or legitimate.")

url_input = st.text_input("Enter URL:", placeholder="https://example.com")

if st.button("Classify"):
    if not url_input.strip():
        st.warning("Please enter a URL first.")
    else:
        features = extract_features(url_input)
        features_scaled = scaler.transform(features)
        prediction = model.predict(features_scaled)[0]
        probability = model.predict_proba(features_scaled)[0]

        if prediction == 0:
            st.error(f"⚠️ PHISHING — This URL appears to be malicious!")
            st.write(f"Confidence: {probability[0]*100:.1f}%")
        else:
            st.success(f"✅ LEGITIMATE — This URL appears to be safe.")
            st.write(f"Confidence: {probability[1]*100:.1f}%")

st.markdown("---")
st.caption("Phishing Link Classifier — COMP360 Final Project | Uswa, Nawal, Tania")