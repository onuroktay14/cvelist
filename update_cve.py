import requests
import json
import os
from datetime import datetime

def calculate_priority(cvss, epss):
    if cvss is None: return "P3 - Low"
    if cvss >= 9.0: return "P0 - Emergency"
    elif cvss >= 7.0: return "P1 - High"
    elif cvss >= 4.0: return "P2 - Medium"
    else: return "P3 - Low"

def fetch_cve_data():
    # NVD API 2.0 URL - Son 1 günün verilerini çekmeye odaklanalım
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50"
    headers = {
        "User-Agent": "CVE-Dashboard-Project",
        "apiKey": os.getenv("NVD_API_KEY", "")
    }
    
    try:
        print("NVD API'den veri çekiliyor...")
        response = requests.get(api_url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        processed_list = []
        vulnerabilities = data.get('vulnerabilities', [])
        
        for item in vulnerabilities:
            cve = item.get('cve', {})
            metrics = cve.get('metrics', {})
            
            # CVSS v3.1 veya v3.0 puanını al
            cvss_v3 = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', [{}]))[0]
            cvss_score = cvss_v3.get('cvssData', {}).get('baseScore')
            
            # Priority hesapla (EPSS şimdilik sabit 0.05)
            priority = calculate_priority(cvss_score, 0.05)
            
            processed_list.append({
                "id": cve.get('id'),
                "severity": cvss_score if cvss_score else "N/A",
                "priority": priority,
                "description": cve.get('descriptions', [{}])[0].get('value', 'No description')[:250] + "...",
                "status": cve.get('vulnStatus', 'Unknown'),
                "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}"
            })
            
        return processed_list
    except Exception as e:
        print(f"Hata detayı: {e}")
        return None

# Ana çalışma bloğu
if __name__ == "__main__":
    result = fetch_cve_data()
    
    # Eğer API hata verirse boş liste dönmesin, en azından yapı korunsun
    final_data = result if result is not None else []
    
    # Dosyayı ana dizine zorla yaz (UTF-8 desteğiyle)
    file_path = os.path.join(os.path.dirname(__file__), 'data.json')
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(final_data, f, ensure_ascii=False, indent=4)
    
    print(f"İşlem tamamlandı. {len(final_data)} kayıt data.json dosyasına yazıldı.")
