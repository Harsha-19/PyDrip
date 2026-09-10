import os
import urllib.request
import json

def load_env(filepath):
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, val = line.split('=', 1)
                    os.environ[key.strip()] = val.strip().strip('"').strip("'")
    except Exception:
        pass

load_env('.env')
api_key = os.environ.get("GROQ_API_KEY")

def test_groq():
    model = os.environ.get("GROQ_MODEL", "llama3-8b-8192")
    prompt = "Reply with exactly: FIM+ Groq connection OK"
    
    data = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }
    
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=json.dumps(data).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "FIM_Plus/1.0"
        }
    )
    
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result_json = json.loads(response.read())
            print(f"Success! Response: {result_json['choices'][0]['message']['content']}")
            return True
    except urllib.error.HTTPError as e:
        print(f"Failed. HTTP Error {e.code}: {e.reason}")
        print(f"Error body: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"Exception: {e}")
        return False

print("Testing Groq connection...")
test_groq()
