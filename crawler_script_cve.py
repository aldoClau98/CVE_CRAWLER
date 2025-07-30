import requests
import csv
import argparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; CVE-Extractor/1.0; +https://nvd.nist.gov/)"
}

def scrape_nvd_page(cve_id):
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        if response.status_code != 200:
            print(f"[✗] {cve_id}: HTTP {response.status_code}")
            return cve_id, "N/A", "N/A", "NVD (crawl)", "Pagina non accessibile"

        soup = BeautifulSoup(response.text, "html.parser")

        # Descrizione
        desc_div = soup.find("p", {"data-testid": "vuln-description"})
        description = desc_div.text.strip() if desc_div else "N/A"

        # Vettore CVSS (prova multipla)
        vector_tag = (
            soup.find("span", {"data-testid": "vuln-cvss3-nist-vector"}) or
            soup.find("span", {"data-testid": "vuln-cvss3-cna-vector"}) or
            soup.find("span", {"data-testid": "vuln-cvss3-adp-vector"}) or
            soup.find("span", {"data-testid": "vuln-cvss3-panel-vector"}) or
            soup.find("span", {"data-testid": "vuln-cvss2-panel-vector"})
        )
        vector = vector_tag.text.strip() if vector_tag else "N/A"

        # Severity (score + livello)
        score_tag = (
		soup.find("a", {"data-testid": "vuln-cvss3-panel-score"}) or
		soup.find("a", {"data-testid": "vuln-cvss3-cna-panel-score"}) or
		soup.find("a", {"data-testid": "vuln-cvss3-adp-panel-score"}) or
         	soup.find("a", {"id": "Cvss2CalculatorAnchor"}) 
	)
        if score_tag:
            severity = f"{score_tag.text.strip()}"
        else:
            severity = "N/A"

        print(f"[✓] {cve_id}: vettore = {vector}, severity = {severity}")
        return cve_id, vector, severity, "NVD (crawl)", description

    except Exception as e:
        print(f"[✗] {cve_id}: Errore: {e}")
        return cve_id, "N/A", "N/A", "Errore", "N/A"

def main():
    parser = argparse.ArgumentParser(description="Estrai CVSS, severity e descrizioni dalle pagine NVD di CVE.")
    parser.add_argument("input_file", help="File contenente CVE (una per riga)")
    parser.add_argument("-o", "--output", help="File CSV in output", default="output.csv")
    args = parser.parse_args()

    try:
        with open(args.input_file, "r") as f:
            cve_list = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f" File non trovato: {args.input_file}")
        return

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        for result in executor.map(scrape_nvd_page, cve_list):
            if result:
                results.append(result)

    with open(args.output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["CVE", "CVSS Vector", "Severity", "Fonte", "Descrizione"])
        writer.writerows(results)

    print(f"\n Output salvato in '{args.output}'.")

if __name__ == "__main__":
    main()
