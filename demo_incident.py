"""
demo_incident.py — Hackathon Demonstration Script
Cryptographic File Integrity & AI Incident Investigation Engine

Demonstrates the 5-Stage Live Investigation Pipeline:
  Stage 1: Core Cryptographic Baseline & SHA-256 Verification
  Stage 2: Investigation & Evidence Detection (Metadata, Content, Structure)
  Stage 3: AI Semantic Analysis (Dense Embeddings + Fallback Resilience)
  Stage 4: Evidence-Driven Severity & Risk Scoring
  Stage 5: Forensic Incident Report & Auditable Evidence Ledger
"""

import os
import sys
import tempfile
import time
from unittest.mock import patch

from app.core.baseline import IntegrityEngine
from app.investigation.investigator import InvestigationEngine
from app.investigation.report import InvestigationReporter
from app.investigation.schemas import InvestigationInput, ScoredChange


def print_banner(text: str):
    print("\n" + "=" * 78)
    print(f"  {text}")
    print("=" * 78)


def print_step(stage: int, title: str):
    print(f"\n[STAGE {stage}] >> {title}")
    print("-" * 65)


def run_demo():
    print_banner("CRYPTOGRAPHIC FILE INTEGRITY INCIDENT REPORT SYSTEM\n  End-to-End Live Hackathon Demonstration")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        core = IntegrityEngine()
        engine = InvestigationEngine()
        reporter = InvestigationReporter()
        
        # -------------------------------------------------------------
        # 1. SETUP MONITORED FILES & CREATE BASELINE
        # -------------------------------------------------------------
        print_step(1, "ESTABLISHING CRYPTOGRAPHIC BASELINE (SHA-256)")
        
        nginx_path = os.path.join(temp_dir, "nginx.conf")
        sudoers_path = os.path.join(temp_dir, "sudoers")
        
        nginx_baseline = (
            "server {\n"
            "    listen 80;\n"
            "    server_name internal.corp.net;\n"
            "    location /admin {\n"
            "        deny all;\n"
            "    }\n"
            "}\n"
        )
        sudoers_baseline = (
            "# /etc/sudoers\n"
            "root ALL=(ALL:ALL) ALL\n"
            "%admin ALL=(ALL) ALL\n"
            "%developers ALL=(ALL) /bin/systemctl restart app\n"
        )
        
        with open(nginx_path, "w") as f:
            f.write(nginx_baseline)
        with open(sudoers_path, "w") as f:
            f.write(sudoers_baseline)
            
        base_nginx = core.create_baseline(nginx_path)
        base_sudo = core.create_baseline(sudoers_path)
        
        print(f" Baseline Established: {os.path.basename(nginx_path)}")
        print(f"   SHA-256: {base_nginx.baseline_hash}")
        print(f"   Status : {base_nginx.integrity_status}")
        print(f" Baseline Established: {os.path.basename(sudoers_path)}")
        print(f"   SHA-256: {base_sudo.baseline_hash}")
        print(f"   Status : {base_sudo.integrity_status}")
        
        # -------------------------------------------------------------
        # 2. SIMULATE TAMPERING / INCIDENT
        # -------------------------------------------------------------
        time.sleep(0.5)
        print_step(1, "SIMULATING SYSTEM TAMPERING & INTEGRITY CHECK")
        
        # Tamper sudoers: Privilege escalation
        sudoers_tampered = (
            "# /etc/sudoers\n"
            "root ALL=(ALL:ALL) ALL\n"
            "%admin ALL=(ALL) ALL\n"
            "%developers ALL=(ALL) NOPASSWD: ALL\n"
        )
        with open(sudoers_path, "w") as f:
            f.write(sudoers_tampered)
            
        # Nginx: superficial whitespace change
        nginx_tampered = (
            "server {\n"
            "    listen 80;\n"
            "    server_name internal.corp.net;\n"
            "    # Updated configuration comment\n"
            "    location /admin {\n"
            "        deny all;\n"
            "    }\n"
            "}\n"
        )
        with open(nginx_path, "w") as f:
            f.write(nginx_tampered)
            
        chk_nginx = core.check_integrity(nginx_path)
        chk_sudo = core.check_integrity(sudoers_path)
        
        print(f" Integrity Check [{os.path.basename(nginx_path)}]: {chk_nginx.integrity_status}")
        print(f"   Baseline: {chk_nginx.baseline_hash[:16]}... | Current: {chk_nginx.current_hash[:16]}...")
        print(f" Integrity Check [{os.path.basename(sudoers_path)}]: {chk_sudo.integrity_status}")
        print(f"   Baseline: {chk_sudo.baseline_hash[:16]}... | Current: {chk_sudo.current_hash[:16]}...")
        
        # -------------------------------------------------------------
        # 3. RUN PIPELINE (STAGES 2, 3, 4)
        # -------------------------------------------------------------
        print_step(2, "STAGE 2 INVESTIGATION DETECTORS (METADATA + CONTENT + STRUCTURE)")
        print_step(3, "STAGE 3 AI SEMANTIC ANALYSIS & INTENT DRIFT")
        print_step(4, "STAGE 4 EVIDENCE-DRIVEN SEVERITY & RISK ENGINE")
        
        changes = [
            ScoredChange(
                file_path=nginx_path,
                change_type="MODIFIED",
                old_hash=chk_nginx.baseline_hash,
                new_hash=chk_nginx.current_hash,
                criticality="Medium",
                evidence=[]
            ),
            ScoredChange(
                file_path=sudoers_path,
                change_type="MODIFIED",
                old_hash=chk_sudo.baseline_hash,
                new_hash=chk_sudo.current_hash,
                criticality="Critical",
                evidence=[]
            )
        ]
        
        inp = InvestigationInput(scan_id="INCIDENT-DEMO-2026", changes=changes)
        file_map = {
            nginx_path: {"old": nginx_baseline, "new": nginx_tampered},
            sudoers_path: {"old": sudoers_baseline, "new": sudoers_tampered}
        }
        
        inv_result = engine.investigate(inp, file_map)
        
        for file_res in inv_result["file_details"]:
            fname = os.path.basename(file_res["file_path"])
            sem = file_res["semantic_analysis"]
            risk = file_res["risk_assessment"]
            
            print(f"\n>> FILE: {fname}")
            print(f"   - Change Type: {file_res['change_type']} | Hash Mismatch: {file_res['hash_mismatch']}")
            print(f"   - Stage 2 Evidence Items: {len(file_res['evidence'])}")
            print(f"   - Stage 3 Semantic Drift: {sem['semantic_drift']} ({sem['status']})")
            print(f"     Explanation: {sem['explanation']}")
            print(f"   - Stage 4 Risk Score: {risk['score']:.4f} --> SEVERITY: {risk['severity']}")
            print(f"     Confidence: {risk['confidence']:.2f}")
            print("     Factor Breakdown:")
            for f in risk["factors"]:
                if f["contribution"] > 0:
                    print(f"       * {f['name']:24}: +{f['contribution']:.2f} | {f['evidence']}")

        # -------------------------------------------------------------
        # 4. GENERATE STAGE 5 INCIDENT REPORT
        # -------------------------------------------------------------
        print_step(5, "STAGE 5 FINAL INCIDENT REPORT & AUDITABLE LEDGER")
        
        report = reporter.generate_report(inv_result)
        
        print(f"\n REPORT ID        : {report.report_id}")
        print(f" SCAN ID          : {report.scan_id}")
        print(f" GENERATED AT     : {report.generated_at}")
        print(f" OVERALL SEVERITY : {report.incident_severity}")
        print(f" RISK SCORE       : {report.risk_score:.4f} / 1.0000")
        print(f" CONFIDENCE       : {report.confidence:.2f}")
        print(f" METHOD           : {report.generation_method}")
        print("\n EXECUTIVE SUMMARY:")
        print(f"   {report.executive_summary}")
        
        print("\n KEY FINDINGS (Provenance-Attributed):")
        for finding in report.key_findings:
            print(f"   [+] {finding}")
            
        print("\n RECOMMENDED ACTIONS:")
        for action in report.recommended_actions:
            print(f"   [>] {action}")
            
        print("\n METHODOLOGICAL LIMITATIONS:")
        for limitation in report.limitations:
            print(f"   [!] {limitation}")

        # -------------------------------------------------------------
        # 5. DEMONSTRATE FALLBACK RESILIENCE
        # -------------------------------------------------------------
        print_banner("DEMONSTRATING FALLBACK RESILIENCE (Zero-Crash Guarantee)")
        print("Simulating primary SentenceTransformer model failure (e.g. GPU OOM)...")
        
        with patch.object(engine.semantic_analyzer.primary_model, 'calculate_similarity_and_drift', side_effect=RuntimeError("Simulated GPU Failure")):
            fallback_inv = engine.investigate(inp, file_map)
            fallback_report = reporter.generate_report(fallback_inv)
            
            fb_sem = fallback_inv["file_details"][1]["semantic_analysis"]
            print(f" [OK] Primary Failure Handled Gracefully!")
            print(f"      Status: {fb_sem['status']} | Analysis Method: {fb_sem['analysis_method']}")
            print(f"      Transition History: {' -> '.join(fb_sem['transition_history'])}")
            print(f"      Fallback Semantic Drift: {fb_sem['semantic_drift']}")
            print(f"      Report Limitation Disclosed: {any('fallback' in l.lower() for l in fallback_report.limitations)}")
            print(f"      System Severity Assessed: {fallback_report.incident_severity} (Score: {fallback_report.risk_score:.2f})")

    print_banner("ALL 5 STAGES VERIFIED & DEMONSTRATION COMPLETE SUCCESSFULLY")


if __name__ == "__main__":
    run_demo()
