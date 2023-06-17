from flask import Flask, request
import joblib
import pandas as pd
from urllib.parse import urlparse
import tldextract
import re

class URLClassification:
    def __init__(self, web_url):
        self.web_url = web_url
        self.url_features = self.obtain_url_features()

    def obtain_url_features(self):
        return pd.DataFrame([self.construct_features_dict()])

    def construct_features_dict(self):
        features_dict = self.initialize_url_properties()
        features_dict.update(self.count_character_occurrences())
        features_dict.update(self.check_url_properties())

        return features_dict

    def initialize_url_properties(self):
        parsed_url = urlparse(self.web_url)
        features_dict = {
            'https': int(self.web_url.startswith('https')),
            'hostname_length': len(parsed_url.netloc),
            'path_length': len(parsed_url.path),
            'url_length': len(self.web_url),
        }
        return features_dict

    def count_character_occurrences(self):
        characters_dict = {
            'count-{}'.format(char): self.web_url.count(char) for char in ['-', '@', '?', '%', '.', '=', 'http', 'https', 'www']
        }
        return characters_dict

    def check_url_properties(self):
        parsed_url_path = urlparse(self.web_url).path
        tld = tldextract.extract(self.web_url).suffix

        features_dict = {
            'fd_length': len(parsed_url_path.split('/')[1]) if parsed_url_path.split('/')[1] else 0,
            'valid_tld': int(tld in ['com', 'org', 'net', 'edu', 'gov', 'mil']),
            'tld_length': len(tld) if tld else -1,
            'count-letters': sum(char.isalpha() for char in self.web_url),
            'count_dir': parsed_url_path.count('/'),
            'use_of_ip': self.check_regex('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.' '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|' '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}'),
            'short_url': self.check_regex('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|' 'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|' 'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|' 'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|' 'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|' 'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|' 'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|' 'tr\.im|link\.zip\.net'),
        }

        return features_dict

    def check_regex(self, pattern):
        return -1 if re.search(pattern, self.web_url) else 1

    def predict(self, ml_model):
        self.url_features = self.url_features.astype(float)

        prediction_output = ml_model.predict(self.url_features)
        self.url_features["prediction"] = prediction_output[0]

        prediction_result = {
            "features": self.url_features.to_json(orient="records"),
            "message": "URL is safe" if prediction_output[0] == 1 else "URL is Malicious",
        }

        return prediction_result

flask_app = Flask(__name__)

@flask_app.route('/predict', methods=['POST'])
def get_prediction():
    json_data = request.get_json(force=True)
    url_input = json_data["url"]

    url_classifier = URLClassification(url_input)
    prediction_result = url_classifier.predict(loaded_model)

    return prediction_result

if __name__ == '__main__':
    loaded_model = joblib.load('joblib_model - Copy.pkl')
    flask_app.run(port=5000, debug=True)
