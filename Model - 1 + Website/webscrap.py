from flask import Flask, Response, request, jsonify
from flask import send_file
import base64
import requests
import json
import joblib
from flask_cors import CORS 
import pycountry
import time
from datetime import datetime, timedelta
from pymongo import MongoClient
import threading
import numpy as np 
import pandas as pd

app = Flask(__name__)
CORS(app)

model = joblib.load('new_model_filename.pkl')
# client = MongoClient('mongodb+srv://purushoth170288:Bruce17@cluster0.yfliaq8.mongodb.net/?retryWrites=true&w=majority')  # Connect to MongoDB
# db = client['test']
# collection = db['new_cyber']

# Dictionary to store the count of attacks per destination country
attack_counts = {}

def get_country_name(code):
    try:
        country = pycountry.countries.get(alpha_2=code)
        if country:
            return country.name
        else:
            return code  # Return code if country name not found
    except Exception as e:
        print(f"Error getting country name: {e}")
        return code

def extract_data_from_sse(url):
    with requests.get(url, stream=True) as response:
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            
            if line.startswith('data:'):
                data = line.split(':', 1)[1].strip()
                
                try:
                    parsed_data = json.loads(data)
                    source_country_code = parsed_data.get("s_co")
                    destination_country_code = parsed_data.get("d_co")
                    attack_name = parsed_data.get("a_n")
                    legend = parsed_data.get("a_t")

                    source_country = get_country_name(source_country_code)
                    destination_country = get_country_name(destination_country_code)

                    simplified_data = {
                        "source_country": source_country,
                        "destination_country": destination_country,
                        "attack_name": attack_name,
                        "legend": legend,
                        'time': datetime.now().strftime("%H:%M:%S")
                    }

                    # Update attack count for destination country
                    if destination_country in attack_counts:
                        attack_counts[destination_country] += 1
                    else:
                        attack_counts[destination_country] = 1
                    
                    # Include attack count in the data being inserted into MongoDB
                    
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON: {e}")
                    continue
                
                if simplified_data['attack_name'] is not None:
                    yield "data: " + json.dumps(simplified_data) + "\n\n"
                    simplified_data['attack_count'] = attack_counts[destination_country]
                    
                    # Insert data into MongoDB
                    # collection.insert_one(simplified_data)
                time.sleep(1)
             

@app.get('/')
def stream_data():
    url = 'https://threatmap-api.checkpoint.com/ThreatMap/api/feed'
    response = Response(extract_data_from_sse(url), content_type='text/event-stream')
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/predict', methods=['POST'])
def make_predictions():
    if request.method == 'POST':
        # Read the CSV file sent in the request
        input_data = pd.read_csv(request.files['file'])

        

# Define dictionary for sttl values mapping
        sttl_dict = {0: 0, 1: 1, 29: 2, 30: 3, 31: 4, 32: 5, 60: 6, 62: 7, 63: 8, 64: 9, 252: 10, 254: 11, 255: 12}

# Map sttl values using the dictionary
        input_data['sttl'] = input_data['sttl'].map(sttl_dict)
        # print("sttl:",input_data['sttl'] )

        # Define function to categorize rate, dload, sload, and sbytes
        def categorize(value):
            if value < 100:
                return 0
            elif 100 < value < 500:
                return 1
            elif 500 < value < 1000:
                return 2
            elif 1000 < value < 2000:
                return 3
            elif 2000 < value < 3000:
                return 4
            elif 3000 < value < 4000:
                return 5
            elif 4000 < value < 5000:
                return 6
            elif 5000 < value < 10000:
                return 7
            elif 10000 < value < 20000:
                return 8
            elif 20000 < value < 50000:
                return 9
            else:
                return 10

        # Apply categorization to rate, dload, sload, and sbytes columns
        input_data['rate'] = input_data['rate'].apply(categorize)
        input_data['dload'] = input_data['dload'].apply(categorize)
        input_data['sload'] = input_data['sload'].apply(categorize)
        input_data['sbytes'] = input_data['sbytes'].apply(categorize)

        # Round ct_srv_dst column
        input_data['ct_srv_dst'] = input_data['ct_srv_dst'] // 10
        severity=[]
        # # Calculate severity
        for i in range(len(input_data)):
            val = input_data['sttl'].iloc[i] * 0.127 + input_data['ct_state_ttl'].iloc[i] * 0.0987 + input_data['rate'].iloc[i] * 0.056 + input_data['dload'].iloc[i] * 0.0498 + input_data['sload'].iloc[i] * 0.0457 + input_data['sbytes'].iloc[i] * 0.0431 + input_data['ct_srv_dst'].iloc[i] * 0.0405

            severity.append(val)
       
        



        predictions = model.predict(input_data)

        attack_names = {0: 'Normal', 1: 'Backdoor', 2: 'Analysis', 3: 'Fuzzers', 4: 'Shellcode',
                        5: 'Reconnaissance', 6: 'Exploits', 7: 'DoS', 8: 'Worms', 9: 'Generic'}

        
        predicted_attacks = [{"attack": attack_names[prediction], "severity": severity_value} for prediction, severity_value in zip(predictions, severity)]
        # sever= [severity for severity in input_data['severity']]


        # Return predicted attack names as JSON
        return jsonify(predicted_attacks)
@app.route('/images', methods=['GET'])
def get_images():
    category = request.args.get('category')
    # Fetch images based on the category
    if category == 'advanced-persistent':
        # Replace this with your actual image fetching logic
        images = [
            {'id': 1, 'url': 'static\output_forecast\AP.png', 'alt': 'Image 1'},
            
           
        ]
    elif category=="adware":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Adware3.png', 'alt': 'Image 1'},
        ]
    elif category=="backdoor":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Backdoor3.png', 'alt': 'Image 1'},
        ]
    elif category=="cryptojacking":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Cryptojacking3.png', 'alt': 'Image 1'},
        ]
    
    elif category=="data-breach":
        images = [
            {'id': 1, 'url': 'static\output_forecast\DB.png', 'alt': 'Image 1'},
        ]
    elif category=="data-poisoning":
        images = [
            {'id': 1, 'url': 'static\output_forecast\DP.png', 'alt': 'Image 1'},
        ]
    elif category=="defacement":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Defacement3.png', 'alt': 'Image 1'},
        ]
    elif category=="disinformation":
        images = [
            {'id': 1, 'url': 'static\output_forecast\DI.png', 'alt': 'Image 1'},
        ]
    elif category=="dns-spoofing":
        images = [
            {'id': 1, 'url': 'static\output_forecast\DNS.png', 'alt': 'Image 1'},
        ]
    elif category=="dns-tunneling":
        images = [
            {'id': 1, 'url': 'static\output_forecast\DNST.png', 'alt': 'Image 1'},
        ]
    
    elif category=="drive-by":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Drive-by3.png', 'alt': 'Image 1'},
        ]
    
    elif category=="insider-threat":
        images = [
            {'id': 1, 'url': 'static\output_forecast\IT.png', 'alt': 'Image 1'},
        ]
    elif category=="key-logger":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Keylogger3.png', 'alt': 'Image 1'},
        ]
    elif category=="malvertising":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Malvertising3.png', 'alt': 'Image 1'},
        ]
    elif category=="password-attack":
        images = [
            {'id': 1, 'url': 'static\output_forecast\password-attack3.png', 'alt': 'Image 1'},
        ]
    elif category=="pharming":
        images = [
            {'id': 1, 'url': 'static\output_forecast\pharming3.png', 'alt': 'Image 1'},
        ]
    elif category=="phishing":
        images = [
            {'id': 1, 'url': 'static\output_forecast\phishing3.png', 'alt': 'Image 1'},
        ]
    elif category=="rootkit":
        images = [
            {'id': 1, 'url': 'static\output_forecast\rootkit3.png', 'alt': 'Image 1'},
        ]
    elif category=="session-hijacking":
        images = [
            {'id': 1, 'url': 'static\output_forecast\session-hijacking3.png', 'alt': 'Image 1'},
        ]
    elif category=="spyware":
        images = [
            {'id': 1, 'url': 'static\output_forecast\spyware3.png', 'alt': 'Image 1'},
        ]
    elif category=="sql-injection":
        images = [
            {'id': 1, 'url': 'static\output_forecast\sql-injection3.png', 'alt': 'Image 1'},
        ]
    elif category=="targetted-attack":
        images = [
            {'id': 1, 'url': 'static\output_forecast\targetted-attack3.png', 'alt': 'Image 1'},
        ]
   
    elif category=="trojan":
        images = [
            {'id': 1, 'url': 'static\output_forecast\trojan3.png', 'alt': 'Image 1'},
        ]
   
    elif category=="url-manipulation":
        images = [
            {'id': 1, 'url': 'static\output_forecast\url-manipulation3.png', 'alt': 'Image 1'},
        ]
    elif category=="vulnerability":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Vulnerability3.png', 'alt': 'Image 1'},
        ]
    elif category=="wannacry":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Wannacry3.png', 'alt': 'Image 1'},
        ]
    elif category=="wiper":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Wiper3.png', 'alt': 'Image 1'},
        ]
    elif category=="worms":
        images = [
            {'id': 1, 'url': 'static\output_forecast\Worms3.png', 'alt': 'Image 1'},
        ]
    elif category=="xss":
        images = [
            {'id': 1, 'url': 'static\output_forecast\XSS3.png', 'alt': 'Image 1'},
        ]

    

    else:
        return jsonify([])

       
    for image in images:
        with open(image['url'], 'rb') as file:
            encoded_string = base64.b64encode(file.read()).decode('utf-8')
            image['data'] = f'data:image/png;base64,{encoded_string}'
    
    return jsonify(images)
    
if __name__ == '__main__':
    app.run(debug=True)
