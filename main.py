import os
import requests
from fastapi import FastAPI
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables from your .env file
load_dotenv()

# Initialize the FastAPI app
app = FastAPI()

# Get your Google API Key from the environment
API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_API_URL = f"https://webrisk.googleapis.com/v1/uris:search?key={API_KEY}"

# Define the structure of the data we expect to receive
class URLRequest(BaseModel):
    url: str

# A simple "homepage" for the API to confirm it's working
@app.get("/")
def read_root():
    return {"status": "API is running"}

# The main endpoint that will check URLs
@app.post("/check_url")
def check_url(request: URLRequest):
    """
    Receives a URL, checks it against the Google Web Risk API,
    and returns a threat status.
    """
    payload = {
        "uri": request.url,
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
    }

    try:
        # Send the request to Google's API
        response = requests.get(GOOGLE_API_URL, params=payload)
        response.raise_for_status() # Check for errors
        data = response.json()

        # If the response contains a "threat" key, it's a dangerous URL
        if "threat" in data:
            return {"status": "PHISHING"}
        else:
            # An empty response means the URL is safe
            return {"status": "SAFE"}

    except requests.exceptions.RequestException as e:
        # If something goes wrong, return a "suspicious" status
        print(f"Error calling Google API: {e}")
        return {"status": "SUSPICIOUS", "error": "Could not verify URL"}