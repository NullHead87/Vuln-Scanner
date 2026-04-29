# Vuln-Scanner

HTTP-tietoturvaskanneri joka tarkistaa web-sivustojen yleisimmät tietoturvapuutteet.
Rakennettu Python/FastAPI-backendillä ja SQLite-tietokannalla.

---

## Vaatimukset

- Python 3.10+
- pip

---

## Asennus

### 1. Kloonaa tai lataa projekti

```bash
git clone <repository-url>
cd vuln_scanner
```

### 2. Luo virtuaaliympäristö

```bash
python -m venv venv
```

### 3. Aktivoi virtuaaliympäristö

**Windows:**
```bash
venv\Scripts\activate
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

### 4. Asenna riippuvuudet

```bash
pip install fastapi uvicorn httpx sqlalchemy aiosqlite aiofiles
```

---

## Käynnistys

```bash
uvicorn main:app --reload
```

Sovellus käynnistyy osoitteeseen `http://localhost:8000`

---

## Käyttö

### Selainliittymä

Avaa selaimessa: `http://localhost:8000`  
  
1. Kirjoita kohde-URL kenttään, esim. `https://google.com`
2. Paina **Scan** tai Enter
3. Tulokset näkyvät ruudulla — klikkaa mitä tahansa löydöstä nähdäksesi selityksen oikealla
4. Score-palkki näyttää kokonaisarvion (vihreä / keltainen / punainen)

**Quick targets** — valmiit napit täyttävät URL-kentän automaattisesti testikohteilla.

---

### API-dokumentaatio (Swagger UI)  
  
`http://localhost:8000/docs`  
  
Swagger UI:ssa voit testata kaikkia endpointteja suoraan selaimella.

---

## API-endpointit

| Metodi | Endpoint | Kuvaus |
|--------|----------|--------|
| POST | `/api/scan` | Käynnistää uuden skannauksen |
| GET | `/api/results` | Listaa kaikki tallennetut skannaukset |
| GET | `/api/results/{id}` | Hakee yksittäisen skannauksen ID:llä |

### Esimerkki: skannaus PowerShellissä

```powershell
Invoke-WebRequest -Uri "http://localhost:8000/api/scan" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"url": "https://example.com"}'
```

---

## Mitä skanneri tarkistaa

### HTTP Security Headers
| Header | Kuvaus |
|--------|--------|
| Strict-Transport-Security | Pakottaa HTTPS-yhteyden |
| Content-Security-Policy | Estää XSS-hyökkäyksiä |
| X-Frame-Options | Estää clickjacking-hyökkäyksiä |
| X-Content-Type-Options | Estää MIME-tyypin arvailun |
| Referrer-Policy | Rajoittaa referrer-tiedon jakamista |
| Permissions-Policy | Hallitsee selaimen ominaisuuksien käyttöä |

### TLS / SSL
- TLS-versio (suositeltu: TLSv1.2 tai TLSv1.3)
- Sertifikaatin voimassaoloaika
- Sertifikaatin Common Name (CN)

### Uudelleenohjaukset
- Open redirect -tarkistus
- HTTP → HTTPS uudelleenohjaus

### Info
- robots.txt sijainti
- Sitemap sijainti

---

## Projektirakenne
  
vuln_scanner/
├── main.py              # FastAPI-sovellus, reitit ja käynnistys
├── database.py          # Tietokantayhteys ja alustus
├── models.py            # SQLAlchemy-tietokantamallit
├── scanner/
│   ├── headers.py       # HTTP security header -tarkistukset
│   ├── tls.py           # TLS/SSL-tarkistukset
│   └── redirects.py     # Uudelleenohjauksen tarkistukset
├── routers/
│   └── scan.py          # API-endpointit
├── static/
│   ├── style.css        # Käyttöliittymän tyylitiedosto
│   └── app.js           # Käyttöliittymän logiikka
├── frontend.html        # Selainliittymä
└── README.md            # Tämä tiedosto

---

## Tietokanta

Skannaukset tallennetaan automaattisesti SQLite-tietokantaan (`scanner.db`).
Tietokanta luodaan automaattisesti ensimmäisellä käynnistyskerralla.

---

## Tekijä  
  
@NullHead87
