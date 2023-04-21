#this is the main.py file that is used to take the inputs from the html file to lookup malware

import requests
import json
import sys
from flask import Flask, request, render_template
import pandas as pd

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/query', methods=['POST'])
def query():
    api_keys = {
        'hybrid_analysis': request.form.get('hybrid_analysis_key', ''),
        'virustotal': request.form.get('virustotal_key', ''),
        'malware_bazaar': request.form.get('malware_bazaar_key', '')
    }
    indicator = request.form['indicator']

    results = []

    if api_keys['hybrid_analysis']:
        headers = {'api-key': api_keys['hybrid_analysis']}
        url = f'https://www.hybrid-analysis.com/api/v2/search/terms?_timestamp=0&file_type=any&domain={indicator}'
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = json.loads(response.text)
            for entry in data['data']:
                results.append([indicator, 'Hybrid Analysis', entry['sha256'], entry['host']])

    if api_keys['virustotal']:
        headers = {'x-apikey': api_keys['virustotal']}
        url = f'https://www.virustotal.com/api/v3/search?query={indicator}'
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = json.loads(response.text)
            for entry in data['data']:
                results.append([indicator, 'VirusTotal', entry['id']])

    if api_keys['malware_bazaar']:
        headers = {'API-KEY': api_keys['malware_bazaar']}
        url = f'https://mb-api.abuse.ch/api/v1/query/selector/'
        payload = {'query': 'get_info', 'selector': indicator}
        response = requests.post(url, data=payload, headers=headers)
        if response.status_code == 200:
            data = json.loads(response.text)
            if 'data' in data:
                for entry in data['data']:
                    results.append([indicator, 'Malware Bazaar', entry['sha256_hash'], entry['host']])

    df = pd.DataFrame(results, columns=['Query', 'Source', 'Associated Indicator', 'Host'])
    df.to_csv('output.csv', index=False)

    return 'Query results saved to output.csv'

if __name__ == '__main__':
    app.run(debug=True)
