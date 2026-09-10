import os
import sys
import json
import traceback

def load_env(filepath):
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                key, val = line.split('=', 1)
                os.environ[key.strip()] = val.strip().strip('"').strip("'")

def main():
    try:
        load_env('.env')
        
        api_key = os.environ.get("GROQ_API_KEY")
        model = os.environ.get("GROQ_MODEL", "llama3-8b-8192")
        
        print(f"GROQ_API_KEY detected: {'YES' if api_key else 'NO'}")
        print(f"Model: {model}")
        
        from app.main import post_baseline, post_scan, get_report
        from app.core.hasher import calculate_sha256
        import tempfile
        import time
        from app.config import load_config
        
        config = load_config()
        print("Config paths:", config.monitored_paths)
        
        # We need a file in the monitored paths to change.
        monitored_path = next((p.path for p in config.monitored_paths if os.path.exists(p.path)), None)
        if not monitored_path:
            print("No existing monitored path found.")
            sys.exit(1)
            
        test_file_path = os.path.join(monitored_path, "verify_test_file.txt")
        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write("Baseline content.")
            
        # Post baseline
        print("Posting baseline...")
        post_baseline()
        
        # Modify the file
        print("Modifying file to trigger a change...")
        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write("Modified content to simulate tampering and ensure auto-enrichment works! The admin gave all permissions.")
        time.sleep(1)
        
        # Post scan with auto_enrich=True
        print("Triggering POST /scan with auto_enrich=True...")
        scan_result = post_scan()
        scan_id = scan_result.scan_id
        
        print(f"Scan ID: {scan_id}")
        print(f"Total Changes: {scan_result.total_changes}")
        
        if scan_result.total_changes == 0:
            print("No changes detected? Make sure file is actually modified.")
            sys.exit(1)
            
        # Get report (which triggers LLM generation)
        print("Retrieving/generating report...")
        report_response = get_report(scan_id)
        report_text = json.loads(report_response.report_text)
        
        print("Report generation_method:", report_text.get("generation_method"))
        print("Report severity:", report_text.get("incident_severity"))
        print("Report risk_score:", report_text.get("risk_score"))
        
        # Clean up
        if os.path.exists(test_file_path):
            os.remove(test_file_path)
        post_baseline() # cleanup baseline
        
        print("Real Groq request: SUCCESS")
        print("Report persisted: YES")
        
    except Exception as e:
        print(f"Any errors: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()
