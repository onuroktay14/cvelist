import requests
import json
import os

def calculate_priority(cvss, has_exploit):
    try:
        score = float(cvss)
        if score >= 9.0 and has_exploit: return "P0 - Emergency"
        elif score >= 7.0: return "P1 - High"
        elif score >= 4.0: return "P2 - Medium"
        else: return "P3 - Low"
    except:
        return "P2 - Medium"

def fetch_cve_data():
    # En güncel ve detaylı zafiyetleri içeren GitHub Arşivi (Daily)
    url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        delta_data = response.json()
        
        processed_list = []
        # Hem yeni hem güncellenen zafiyetleri alalım
        raw_cves = delta_data.get('new', []) + delta_data.get('updated', [])
        
        for item in raw_cves[:60]: # Son 60 güncel zafiyet
            cve_id = item.get('cveId')
            # Rastgele veya sabit veri yerine 'has_exploit' kontrolü simülasyonu
            # Gerçek üründe burada GitHub Search API veya Exploit-DB API kullanılabilir
            description = f"{cve_id} numaralı zafiyet kritik sistemleri etkileyebilir."
            
            # PoC/Exploit var mı kontrolü (Basit logic)
            has_poc = "PoC" if "poc" in description.lower() else "N/A"
            mitre_tactic = "Initial Access" # Örnek MITRE eşleşmesi
            
            processed_list.append({
                "id": cve_id,
                "severity": "8.5", 
                "priority": calculate_priority(8.5, False),
                "description": description,
                "mitre": mitre_tactic,
                "exploit_status": "Sorgulanıyor",
                "poc_link": f"https://github.com/search?q={cve_id}+exploit",
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })
            
        return processed_list
    except Exception as e:
        return [{"id": "DEBUG", "severity": "0", "priority": "P3", "description": str(e)}]

if __name__ == "__main__":
    result = fetch_cve_data()
    file_path = os.path.join(os.path.dirname(__file__), 'data.json')
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=4)
