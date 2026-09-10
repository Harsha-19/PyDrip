import urllib.request
import urllib.error
import json

def run_test():
    url = "http://127.0.0.1:8000/investigate"
    
    payload = {
        "input_data": {
            "scan_id": "API-TEST-999",
            "changes": [
                {
                    "file_path": "/var/www/html/index.html",
                    "change_type": "MODIFIED",
                    "old_hash": "hash_old",
                    "new_hash": "hash_new",
                    "criticality": "Medium",
                    "evidence": []
                }
            ]
        },
        "file_contents_map": {
            "/var/www/html/index.html": {
                "old": "<html>Welcome</html>",
                "new": "<html>Welcome back! Hacker was here.</html>"
            }
        }
    }
    
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    
    print("Sending POST request to the API...")
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read())
            print("\nAPI Response Received (Final Investigation Report):")
            print(json.dumps(result, indent=2))
            print("\nPASS: The AI Investigation Engine is live and successfully served the request!")
    except urllib.error.URLError as e:
        print(f"FAIL: Failed to reach the API. Is Uvicorn running? Error: {e}")
    except Exception as e:
        print(f"FAIL: An error occurred: {e}")

if __name__ == "__main__":
    run_test()
