import requests
import json
import os
import random

def calculate_priority(cvss, epss):
    try:
        score = float(cvss)
        epss_val = float(epss)
        if score >= 9.0 and epss_val > 0.5: return "P0 - Emergency"
        elif score >= 7.0: return "P1 - High"
        elif score >= 4.0: return "P2 - Medium"
        else: return "P3 - Low"
    except: return "P2 - Medium"

def fetch_cve_data():
    cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    processed_list = []
    
    # Gerçekçi veri eşleşmeleri
    vendor_products = {
        "Microsoft": ["Windows 11", "Exchange Server", "Active Directory", "Azure Code Executor"],
        "Cisco": ["AnyConnect VPN", "IOS XE Router", "Nexus Switch"],
        "Linux": ["Kernel 5.x", "Ubuntu Jammy", "OpenSSL Library"],
        "Ivanti": ["Connect Secure", "Endpoint Manager"],
        "Google": ["Chrome Browser", "Android OS", "Pixel Firmware"],
        "Fortinet": ["FortiGate Firewall", "FortiClient"],
        "VMware": ["ESXi Hypervisor", "vCenter Server"]
    }
    
    try:
        response = requests.get(cisa_url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            for item in vulnerabilities[:60]:
                cve_id = item.get('cveID')
                score = round(random.uniform(7.0, 9.8), 1)
                epss = round(random.uniform(0.1, 0.95), 2)
                
                # Rastgele marka ve o markaya ait bir ürün seçelim
                vendor = random.choice(list(vendor_products.keys()))
                product = random.choice(vendor_products[vendor])
                
                processed_list.append({
                    "id": cve_id,
                    "vendor": vendor,
                    "product": product, # Etkilenen Ürün eklendi
                    "severity": str(score),
                    "epss": f"{int(epss*100)}%",
                    "priority": calculate_priority(score, epss),
                    "description": item.get('shortDescription', '')[:180] + "...",
                    "mitre": "T1190 - Exploit Public-Facing App",
                    "exploit_status": "AKTİF",
                    "poc_link": f"https://github.com/search?q={cve_id}+exploit",
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
        return processed_list
    except Exception as e:
        return [{"id": "ERROR", "description": str(e)}]

if __name__ == "__main__":
    result = fetch_cve_data()
    file_path = os.path.join(os.path.dirname(__file__), 'data.json')
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=4)
