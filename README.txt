# Estrattore CVSS da CVE via Crawling (NVD.gov)

Questo script Python estrae automaticamente il **vettore CVSS** e la **descrizione** associati a una lista di CVE, facendo scraping direttamente dal sito ufficiale del [National Vulnerability Database (NVD)](https://nvd.nist.gov/).

---

## Funzionalità

- Estrae il **vettore CVSS v3 o v2** (quando disponibile) per ciascuna CVE.
- Estrae la **descrizione testuale** della vulnerabilità.
- Salva i risultati in un file **CSV** con le seguenti colonne:
  - `CVE`
  - `CVSS Vector`
  - `Fonte` (sempre "NVD (crawl)")
  - `Descrizione`
- Supporta **threading** per velocizzare l’analisi.
- Non richiede API Key.

---

## Requisiti

- Python 3.7 o superiore
- Moduli:
  - `requests`
  - `beautifulsoup4`

Installa i moduli necessari con:  pip install requests beautifulsoup4


## Utilizzo

1. Prepara il file di input
Crea un file di testo (es. input.txt) con una CVE per riga:
CVE-2023-32560
CVE-2022-1388
CVE-2021-34527

2. Avvia lo script

python estrai_cve_crawler.py input.txt -o output.csv

Opzioni:

input.txt: percorso del file contenente le CVE

-o output.csv: nome del file CSV in output (default: output.csv)



##  Come funziona
Lo script accede a ogni pagina CVE su https://nvd.nist.gov/vuln/detail/<CVE-ID> e cerca il vettore CVSS in quest’ordine:

vuln-cvss3-nist-vector → vettore ufficiale NIST (preferito)

vuln-cvss3-cna-vector → vettore fornito dal CNA (fallback)

vuln-cvss3-panel-vector-string → vecchia interfaccia NVD

vuln-cvss2-panel-vector-string → CVSS v2 (se v3 non disponibile)

La descrizione viene estratta dal campo:

	<p data-testid="vuln-description">


## Output
Il file CSV generato conterrà ad esempio:

CVE,CVSS Vector,Fonte,Descrizione
CVE-2023-32560,CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H,NVD (crawl),"Ivanti Avalanche has a login vulnerability..."
CVE-2022-1388,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,NVD (crawl),"This vulnerability affects F5 BIG-IP iControl REST API..."

