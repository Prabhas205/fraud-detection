from flask import Flask, request, render_template
import requests
import os
import time

# Load API key from environment variable for security
API_KEY = os.getenv("SAFE_BROWSING_API_KEY")  # Set this variable in your system

# Flask app setup
app = Flask(__name__)

# Simple cache dictionary to store recent checks (URL: result)
cache = {}

# Function to check link safety using Google Safe Browsing API
def check_safe_browsing(url):
    global cache

    # If the URL was checked recently, return cached result (avoids inconsistency)
    if url in cache:
        return cache[url]

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {"clientId": "LinkVerifier", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    
    try:
        response = requests.post(api_url, json=payload)
        response.raise_for_status()  # Raise error for bad response codes (4xx, 5xx)
        data = response.json()
        
        # Check if the response contains any matches
        if "matches" in data:
            result = "⚠️ Unsafe: The link is potentially dangerous!"
        else:
            result = "✅ Safe: The link is safe to visit."

        # Store result in cache with a timestamp
        cache[url] = result

        return result

    except requests.exceptions.RequestException as e:
        print(f"Error checking URL safety: {e}")
        return "Error: Unable to check link safety. Try again later."

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Route to verify link
@app.route('/verify', methods=['POST'])
def verify():
    url = request.form.get('url')  # Get URL from form
    
    if url:
        result = check_safe_browsing(url)
    else:
        result = "Error: Please enter a valid URL."
    
    return render_template('result.html', url=url, result=result)

# Simple login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == "admin" and password == "password":  # Example credentials
            return "Welcome, admin!"
        else:
            return "Invalid credentials. Please try again."
    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)
