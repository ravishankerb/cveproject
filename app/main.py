import json
import asyncio
import pandas as pd

from typing import Dict, Any
from scan_parsers import parse_snyk_report
from llm_requests import analyze_with_llm
from utils import load_kev_catalog
from utils import enrich_findings

async def process_findings():    
    
    print(f"Starting to process {len(findings)} findings...")
    
    # Create actual Task objects with their finding data
    task_objects = []
    for i, finding in enumerate(findings):
        print(f"Creating task for finding {i}: {finding.get('cve', 'Unknown CVE')}")
        task = asyncio.create_task(analyze_with_llm(finding, project_context))
        task_objects.append((i, finding, task))
    
    print(f"Created {len(task_objects)} tasks, starting async processing...")
    
    # Use a different approach - process tasks as they complete
    pending_tasks = {task: (i, finding) for i, finding, task in task_objects}
    
    while pending_tasks:
        # Wait for any task to complete
        done, pending = await asyncio.wait(
            pending_tasks.keys(), 
            return_when=asyncio.FIRST_COMPLETED
        )
        
        for task in done:
            result = await task
            i, finding = pending_tasks[task]
            print(f"Task {i} completed for {finding.get('cve', 'Unknown CVE')}")
            
            yield {
                'finding': finding,
                'analysis': result
            }
            
            # Remove completed task from pending
            del pending_tasks[task]

scan_details = parse_snyk_report("E:\\AgentAI\\enterprise-vuln-app\\snyk_report.json")
print(f"Found {len(scan_details)} scan details")
project_context = "This is a Java-based microservice exposed to the internet, handling sensitive customer data."
kev_db = load_kev_catalog(".\\data\\kev.json")
findings = enrich_findings(scan_details, kev_db, "E:\\AgentAI\\enterprise-vuln-app")
print(f"Enriched {len(findings)} findings")

# Run the async function and process yielded resultsfinding["kev"] 
async def main():
    async for item in process_findings():
        print(item)
        print(f"\n{'='*60}")
        print(f"CVE: {item['finding']['cve']} | Package: {item['finding']['pkg']} | CVSS: {item['finding']['cvss']} | Kev: {item['finding']['kev']} | Used in Code: {item['finding']['used_in_code']}")
        
        # Display usage details if the package is found in code
        if item['finding']['used_in_code'] and item['finding'].get('usage_details'):
            print("Usage locations:")
            for usage in item['finding']['usage_details']:
                print(f"  - {usage['file']}:{usage['line_number']} - {usage['line_content']}")
        
        print(json.dumps(item['analysis'], indent=2))

asyncio.run(main())
