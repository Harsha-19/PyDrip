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
api_key = os.environ.get("XAI_API_KEY")

def test_grok(use_json_format=False):
    model = "grok-4.6"
    prompt = "Reply with exactly: FIM+ Grok connection OK"
    
    data = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }
    
    if use_json_format:
        data["response_format"] = { "type": "json_object" }
        
    req = urllib.request.Request(
        "https://api.x.ai/v1/chat/completions",
        data=json.dumps(data).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
    )
    
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result_json = json.loads(response.read())
            print(f"Success with json_format={use_json_format}! Response: {result_json['choices'][0]['message']['content']}")
            return True
    except urllib.error.HTTPError as e:
        print(f"Failed with json_format={use_json_format}. HTTP Error {e.code}: {e.reason}")
        print(f"Error body: {e.read().decode('utf-8')}")
        return False
    except Exception as e:
        print(f"Exception: {e}")
        return False

print("Testing without json_format...")
test_grok(use_json_format=False)

print("\nTesting with json_format...")
test_grok(use_json_format=True)
