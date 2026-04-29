const API = 'http://localhost:8000';

const EXPLANATIONS = {
  'strict-transport-security': {
    title: 'Strict-Transport-Security (HSTS)',
    text: 'Pakottaa selaimen käyttämään aina HTTPS-yhteyttä. Ilman tätä selain saattaa ensin yrittää HTTP-yhteyttä, jolloin hyökkääjä voi siepata liikenteen ennen kuin salattu yhteys muodostuu.',
    risk: 'Altistaa man-in-the-middle -hyökkäyksille jossa liikenne voidaan siepata ja muokata.',
    tip: 'Korjaus: lisää palvelimelle\nStrict-Transport-Security: max-age=31536000'
  },
  'content-security-policy': {
    title: 'Content-Security-Policy (CSP)',
    text: 'Määrittelee mistä lähteistä selain saa ladata skriptejä, kuvia ja muuta sisältöä. Yksi tehokkaimmista suojista XSS-hyökkäyksiä vastaan.',
    risk: 'Ilman CSP:tä hyökkääjä voi injektoida haitallista JavaScript-koodia sivulle, joka ajetaan käyttäjän selaimessa.',
    tip: "Korjaus: määrittele sallitut lähteet\nContent-Security-Policy: default-src 'self'"
  },
  'x-frame-options': {
    title: 'X-Frame-Options',
    text: 'Estää sivuston lataamisen iframe-elementtiin toisella sivustolla. Suojaa clickjacking-hyökkäyksiltä.',
    risk: 'Ilman tätä hyökkääjä voi upottaa sivuston näkymättömäksi kerrokseksi oman sivustonsa päälle ja huijata käyttäjää klikkaamaan vääriä kohtia.',
    tip: 'Korjaus:\nX-Frame-Options: DENY\ntai\nX-Frame-Options: SAMEORIGIN'
  },
  'x-content-type-options': {
    title: 'X-Content-Type-Options',
    text: 'Estää selainta arvaamasta tiedostotyypin itse. Ilman tätä selain saattaa tulkita tiedoston eri tavalla kuin palvelin tarkoitti.',
    risk: 'Hyökkääjä voi ladata kuvatiedoston joka sisältää JavaScript-koodia ja saada selaimen ajamaan sen.',
    tip: 'Korjaus:\nX-Content-Type-Options: nosniff'
  },
  'referrer-policy': {
    title: 'Referrer-Policy',
    text: 'Määrittelee mitä tietoa lähetetään Referer-headerissa kun käyttäjä siirtyy sivustolta toiselle.',
    risk: 'Ilman tätä koko URL lähetetään ulkoisille sivuille, mikä voi paljastaa arkaluonteisia tietoja kuten hakuparametreja tai käyttäjätunnisteita.',
    tip: 'Korjaus:\nReferrer-Policy: strict-origin-when-cross-origin'
  },
  'permissions-policy': {
    title: 'Permissions-Policy',
    text: 'Määrittelee mitkä selaimen ominaisuudet ovat sallittuja sivustolla. Koskee esimerkiksi kameraa, mikrofonia ja GPS-sijaintia.',
    risk: 'Ilman tätä kolmannen osapuolen skriptit voivat pyytää pääsyä selaimen ominaisuuksiin käyttäjän tietämättä.',
    tip: 'Korjaus:\nPermissions-Policy: camera=(), microphone=(), geolocation=()'
  },
  'server': {
    title: 'Server-header (versiopaljastus)',
    text: 'Palvelin kertoo vastauksessaan mitä ohjelmistoa se käyttää. Tämä tieto ei ole tarpeellinen tavallisille käyttäjille.',
    risk: 'Hyökkääjä voi käyttää tietoa etsiäkseen kyseisen ohjelmistoversion tunnettuja haavoittuvuuksia.',
    tip: 'Korjaus: piilota versio palvelimen\nkonfiguraatiossa (Apache: ServerTokens Prod)'
  },
  'tls_version': {
    title: 'TLS-versio',
    text: 'TLS (Transport Layer Security) salaa tietoliikenteen selaimen ja palvelimen välillä. Uudemmat versiot ovat turvallisempia.',
    risk: 'Vanhat versiot kuten TLS 1.0 ja 1.1 sisältävät tunnettuja haavoittuvuuksia kuten BEAST ja POODLE.',
    tip: 'TLSv1.3 on uusin ja turvallisin versio.\nTLSv1.2 on hyväksyttävä.\nVanhemmat tulisi poistaa käytöstä.'
  },
  'cert_expiry': {
    title: 'Sertifikaatin voimassaolo',
    text: 'HTTPS-sertifikaatilla on vanhenemispäivä. Kun se vanhenee, selaimet näyttävät tietoturvavirheen eikä sivustolle pääse normaalisti.',
    risk: 'Vanhentunut sertifikaatti katkaisee käyttäjien pääsyn sivustolle ja voi aiheuttaa vakavan mainehaitan.',
    tip: 'Alle 30 päivää — uusi sertifikaatti kiireesti.\nLets Encrypt uusii automaattisesti jos certbot on konfiguroitu.'
  },
  'common_name': {
    title: 'Sertifikaatin Common Name (CN)',
    text: 'CN kertoo mille domainille sertifikaatti on myönnetty. Sen tulisi täsmätä sivuston osoitteen kanssa.',
    risk: 'Jos CN ei täsmää domainin kanssa, selaimet näyttävät tietoturvavirheen.',
    tip: 'Varmista että sertifikaatti kattaa\nsekä example.com että www.example.com'
  },
  'open_redirect': {
    title: 'Open Redirect',
    text: 'Sivusto ohjaa käyttäjän automaattisesti toiseen osoitteeseen. Tämä voi olla normaalia tai haavoittuvuus.',
    risk: 'Oikea open redirect mahdollistaa phishing-hyökkäykset: hyökkääjä lähettää luotettavan näköisen linkin joka ohjaa haitalliselle sivustolle.',
    tip: 'Jos uudelleenohjaus on tarkoituksellinen\n(www-redirect), se on normaalia toimintaa.'
  },
  'redirect': {
    title: 'Uudelleenohjaus',
    text: 'Sivusto ei ohjaa käyttäjää automaattisesti muualle root-osoitteesta. Tämä on neutraali tulos.',
    risk: 'Ei riskiä tässä kohdassa.',
    tip: 'HTTP → HTTPS uudelleenohjaus on\nsuositeltava tietoturvakäytäntö.'
  },
  'http_to_https': {
    title: 'HTTP → HTTPS uudelleenohjaus',
    text: 'Tarkistaa ohjaako sivusto käyttäjän automaattisesti HTTP:stä HTTPS:ään.',
    risk: 'Ilman tätä käyttäjä voi käyttää sivustoa salaamattomalla HTTP-yhteydellä tietämättään.',
    tip: 'Korjaus: lisää palvelimelle 301-uudelleenohjaus\nHTTP:stä HTTPS:ään.'
  },
  'robots_txt': {
    title: 'robots.txt',
    text: 'Tiedosto joka kertoo hakukoneroboteille mitkä sivut saa indeksoida. Löytyy osoitteesta /robots.txt.',
    risk: 'Voi vahingossa paljastaa arkaluonteisia polkuja kuten /admin tai /backup.',
    tip: 'Tarkista manuaalisesti ettei robots.txt\npaljasta arkaluonteisia polkuja.'
  },
  'sitemap': {
    title: 'Sitemap',
    text: 'Listaa sivuston kaikki sivut hakukoneita varten. Löytyy yleensä osoitteesta /sitemap.xml.',
    risk: 'Ei suoranainen tietoturvariski, mutta paljastaa sivuston rakenteen ulkopuolisille.',
    tip: 'Normaali osa sivustoa. Varmista että\nsitemap ei sisällä admin-polkuja.'
  },
  'ssl_error': {
    title: 'SSL-virhe',
    text: 'TLS/SSL-yhteyden muodostamisessa tapahtui virhe. Voi johtua virheellisestä sertifikaatista tai yhteysongelmasta.',
    risk: 'SSL-virhe voi tarkoittaa että yhteys ei ole salattu tai sertifikaatti on virheellinen.',
    tip: 'Tarkista sertifikaatin voimassaolo\nja palvelimen TLS-konfiguraatio.'
  },
  'spf': {
    title: 'SPF-tietue',
    text: 'Sender Policy Framework määrittelee mitkä palvelimet saavat lähettää sähköpostia domainin nimissä.',
    risk: 'Ilman SPF:ää hyökkääjä voi lähettää sähköpostia domainin nimissä (spoofing).',
    tip: 'Lisää DNS:ään TXT-tietue:\nv=spf1 include:_spf.example.com ~all'
  },
  'dmarc': {
    title: 'DMARC-tietue',
    text: 'Domain-based Message Authentication määrittelee miten vastaanottaja käsittelee epäilyttävät sähköpostit.',
    risk: 'Ilman DMARCia sähköpostispoofaus on helpompaa ja phishing-hyökkäykset uskottavampia.',
    tip: 'Lisää DNS:ään:\n_dmarc.example.com TXT "v=DMARC1; p=reject"'
  },
  'dkim': {
    title: 'DKIM-tietue',
    text: 'DomainKeys Identified Mail lisää digitaalisen allekirjoituksen sähköposteihin joka todentaa lähettäjän.',
    risk: 'Ilman DKIMia sähköpostien muokkaaminen lähetyksen aikana on mahdollista.',
    tip: 'DKIM konfiguroidaan sähköpostipalvelimen\nasetuksissa ja julkaistaan DNS TXT-tietueena.'
  },
  'secure_flag': {
    title: 'Evästeen Secure-lippu',
    text: 'Secure-lippu estää evästeen lähettämisen salaamattoman HTTP-yhteyden yli.',
    risk: 'Ilman Secure-lippua eväste voidaan siepata salaamattomassa verkossa.',
    tip: 'Aseta eväste:\nSet-Cookie: session=abc; Secure; HttpOnly'
  },
  'httponly_flag': {
    title: 'Evästeen HttpOnly-lippu',
    text: 'HttpOnly-lippu estää JavaScriptiä pääsemästä evästeeseen, suojaten XSS-hyökkäyksiltä.',
    risk: 'Ilman HttpOnly-lippua haitallinen JavaScript voi varastaa evästeen.',
    tip: 'Aseta eväste:\nSet-Cookie: session=abc; Secure; HttpOnly'
  },
  'samesite_flag': {
    title: 'Evästeen SameSite-lippu',
    text: 'SameSite-lippu estää evästeen lähettämisen cross-site-pyynöissä, suojaten CSRF-hyökkäyksiltä.',
    risk: 'Ilman SameSite-lippua sivusto on alttiimpi CSRF-hyökkäyksille.',
    tip: 'Aseta eväste:\nSet-Cookie: session=abc; SameSite=Strict'
  },
  'error': {
    title: 'Yhteysvirhe',
    text: 'Skanneri ei pystynyt muodostamaan yhteyttä kohteeseen.',
    risk: 'Ei voida arvioida tietoturvatilannetta.',
    tip: 'Tarkista että URL on oikein ja\nkohde on saavutettavissa.'
  }
};

let currentScanId = null;

function getExplanation(key) {
  if (!key) return null;
  const clean = key.toLowerCase().replace(/[^a-z_-]/g, '');
  return EXPLANATIONS[clean] || null;
}

function showExplanation(key, status) {
  const exp = getExplanation(key);
  const body = document.getElementById('sidebarBody');
  if (!exp) {
    body.innerHTML = `<div class="sidebar-empty">── ei selitystä<br>tälle kohdalle</div>`;
    return;
  }
  const riskClass = status === 'ok' ? 'ok' : status === 'warning' ? 'warning' : '';
  body.innerHTML = `
    <div class="explain-name">${exp.title}</div>
    <span class="explain-status badge ${status}">${status}</span>
    <p class="explain-text">${exp.text}</p>
    <div class="explain-risk ${riskClass}">${status === 'ok' ? '✓ Ei riskiä tässä kohdassa.' : '⚠ ' + exp.risk}</div>
    <div class="explain-tip">${exp.tip}</div>
  `;
}

function setUrl(url) {
  document.getElementById('urlInput').value = url;
  document.getElementById('urlInput').focus();
}

function setStatus(s) {
  const p = document.getElementById('statusPill');
  p.className = 'status-pill ' + s;
  p.textContent = s.toUpperCase();
}

function setScore(score, max) {
  const bar = document.getElementById('scoreBar');
  const fill = document.getElementById('barFill');
  const num = document.getElementById('scoreNum');
  bar.style.display = 'flex';
  const pct = max ? Math.round((score / max) * 100) : 0;
  fill.style.width = pct + '%';
  fill.className = 'bar-fill' + (pct >= 70 ? '' : pct >= 40 ? ' mid' : ' low');
  num.textContent = score + '/' + max;
  num.style.color = pct >= 70 ? '#00ff88' : pct >= 40 ? '#ffaa00' : '#ff4466';
}

function setPdfButton(scanId) {
  const bar = document.getElementById('scoreBar');
  const existing = document.getElementById('pdfBtn');
  if (existing) existing.remove();

  const btn = document.createElement('a');
  btn.id = 'pdfBtn';
  btn.href = `${API}/api/results/${scanId}/pdf`;
  btn.target = '_blank';
  btn.textContent = '↓ PDF';
  btn.style.cssText = `
    font-family: 'Syne', sans-serif;
    font-size: 11px;
    font-weight: 700;
    color: #0a0a0f;
    background: #00ff88;
    border-radius: 6px;
    padding: 4px 12px;
    text-decoration: none;
    white-space: nowrap;
    transition: opacity 0.15s;
  `;
  btn.onmouseover = () => btn.style.opacity = '0.8';
  btn.onmouseout = () => btn.style.opacity = '1';
  bar.appendChild(btn);
}

function makeFinding(badge, label, value, key) {
  const safeKey = (key || '').replace(/'/g, '');
  const safeStatus = (badge || '').replace(/'/g, '');
  return `<div class="finding" data-key="${safeKey}" data-status="${safeStatus}">
    <span class="badge ${badge}">${badge}</span>
    <span class="finding-text">${label}${value ? ` <span class="finding-val">— ${value.substring(0, 55)}${value.length > 55 ? '…' : ''}</span>` : ''}</span>
  </div>`;
}

function attachFindingClicks() {
  document.querySelectorAll('.finding[data-key]').forEach(el => {
    el.addEventListener('click', function () {
      document.querySelectorAll('.finding').forEach(f => f.classList.remove('active'));
      this.classList.add('active');
      showExplanation(this.dataset.key, this.dataset.status);
    });
  });
}

function renderFindings(data) {
  const body = document.getElementById('resultsBody');
  let html = '';

  if (data.results) {
    const r = data.results;

    const sections = [
      { title: 'HTTP Headers',      findings: r.headers?.findings,    keyField: 'header',  valField: 'value' },
      { title: 'TLS / SSL',         findings: r.tls?.findings,        keyField: 'check',   valField: 'detail' },
      { title: 'Redirects',         findings: r.redirects?.findings,  keyField: 'check',   valField: 'detail' },
      { title: 'DNS',               findings: r.dns?.findings,        keyField: 'check',   valField: 'detail' },
      { title: 'HTTP-metodit',      findings: r.methods?.findings,    keyField: 'check',   valField: 'detail' },
      { title: 'Evästeet',          findings: r.cookies?.findings,    keyField: 'check',   valField: 'detail' },
      { title: 'Portit',            findings: r.ports?.findings,      keyField: 'check',   valField: 'detail' },
      { title: 'Subdomainit',       findings: r.subdomains?.findings, keyField: 'check',   valField: 'detail' },
      { title: 'Info',              findings: r.info?.findings,       keyField: 'check',   valField: 'detail' },
    ];

    sections.forEach(({ title, findings, keyField, valField }) => {
      if (!findings || findings.length === 0) return;
      html += `<div class="section"><div class="section-title">${title}</div>`;
      findings.forEach(f => {
        const key = f[keyField] || '';
        const val = f[valField] || f.value || '';
        html += makeFinding(f.status, key, val, key);
      });
      html += `</div>`;
    });

    setScore(data.overall_score, data.max_score);
    if (data.id) setPdfButton(data.id);

  } else if (Array.isArray(data)) {
    html += `<div class="section"><div class="section-title">Tallennetut skannaukset</div>`;
    if (data.length === 0) {
      html += `<div class="finding"><span class="finding-text" style="color:#555570">Ei tuloksia vielä.</span></div>`;
    }
    data.forEach(s => {
      html += `<div class="finding"><span class="badge ${s.overall_score > 5 ? 'ok' : 'warning'}">#${s.id}</span><span class="finding-text">${s.url} <span class="finding-val">— score ${s.overall_score} · ${new Date(s.created_at).toLocaleString('fi-FI')}</span></span></div>`;
    });
    html += `</div>`;
    document.getElementById('scoreBar').style.display = 'none';
  } else {
    html = `<pre style="color:#8888aa;font-size:11px;white-space:pre-wrap">${JSON.stringify(data, null, 2)}</pre>`;
  }

  body.innerHTML = html;
  attachFindingClicks();
}

async function runScan() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) return;
  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.textContent = '⟳ Scanning';
  setStatus('scanning');
  document.getElementById('resultsBody').innerHTML = `<div class="placeholder"><span class="spinning">◌</span> Skannataan ${url}…</div>`;
  document.getElementById('scoreBar').style.display = 'none';
  const existing = document.getElementById('pdfBtn');
  if (existing) existing.remove();
  document.getElementById('sidebarBody').innerHTML = `<div class="sidebar-empty">── skannataan…</div>`;

  try {
    const res = await fetch(`${API}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Virhe');
    setStatus('done');
    renderFindings(data);
  } catch (e) {
    setStatus('error');
    document.getElementById('resultsBody').innerHTML = `<div class="finding"><span class="badge error">error</span><span class="finding-text">${e.message}</span></div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = '▶ Scan';
  }
}

async function listResults() {
  setStatus('scanning');
  document.getElementById('resultsBody').innerHTML = `<div class="placeholder"><span class="spinning">◌</span> Haetaan tuloksia…</div>`;
  try {
    const res = await fetch(`${API}/api/results`);
    const data = await res.json();
    setStatus('done');
    renderFindings(data);
  } catch (e) {
    setStatus('error');
    document.getElementById('resultsBody').innerHTML = `<div class="finding"><span class="badge error">error</span><span class="finding-text">${e.message}</span></div>`;
  }
}

async function promptId() {
  const id = prompt('Syötä scan ID:');
  if (!id) return;
  setStatus('scanning');
  document.getElementById('resultsBody').innerHTML = `<div class="placeholder"><span class="spinning">◌</span> Haetaan #${id}…</div>`;
  try {
    const res = await fetch(`${API}/api/results/${id}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Ei löydy');
    setStatus('done');
    renderFindings(data);
    if (data.id) setPdfButton(data.id);
  } catch (e) {
    setStatus('error');
    document.getElementById('resultsBody').innerHTML = `<div class="finding"><span class="badge error">error</span><span class="finding-text">${e.message}</span></div>`;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') runScan();
  });
});