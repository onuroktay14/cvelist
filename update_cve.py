import requests
import json
import os

# Priority Hesaplama Mantığı (Logic)
def calculate_priority(cvss, epss):
    if cvss is None: return "P3 - Low"
    
    # P0: Kritik skor ve yüksek saldırı ihtimali
    if cvss >= 9.0 and epss >= 0.1:
        return "P0 - Emergency"
    # P1: Yüksek skor veya orta seviye saldırı ihtimali
    elif cvss >= 7.0 or epss >= 0.3:
        return "P1 - High"
    # P2: Orta seviye zafiyetler
    elif cvss >= 4.0:
        return "P2 - Medium"
    else:
        return "P3 - Low"

def fetch_cve_data():
    # Not: NVD API Key'in varsa URL'ye eklemek hızı artırır
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50"
    headers = {"apiKey": os.getenv("NVD_API_KEY", "")}
    
    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        processed_list = []
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id')
            
            # CVSS Puanını Al (V3.1 yoksa V3.0'a bak)
            metrics = cve.get('metrics', {})
            cvss_data = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', [{}]))[0]
            cvss_score = cvss_data.get('cvssData', {}).get('baseScore')
            
            # EPSS Verisi (Basitleştirilmiş: NVD doğrudan vermezse varsayılan 0.01 ata)
            # Normalde API.first.org/data/v1/epss adresinden çekilir
            fake_epss = 0.05 # Geliştirme aşaması için sabit, ileride API eklenebilir
            
            priority = calculate_priority(cvss_score, fake_epss)
            
            processed_list.append({
                "id": cve_id,
                "severity": cvss_score,
                "priority": priority,
                "description": cve.get('descriptions', [{}])[0].get('value')[:200] + "...",
                "status": cve.get('vulnStatus')
            })
            
        return processed_list
    except Exception as e:
        print(f"Hata oluştu: {e}")
        return None

# Veriyi JSON olarak kaydet
processed_data = fetch_cve_data()
if processed_data:
    with open('data.json', 'w') as f:
        json.dump(processed_data, f, indent=4)
    print("Veri başarıyla güncellendi!")