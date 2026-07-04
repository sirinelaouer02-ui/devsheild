import requests
import json
from urllib.parse import urlparse
from datetime import datetime

# ============================================================
# CHECKS GÉNÉRIQUES (sécurité web standard)
# ============================================================

def analyze_url(url):
    results = {
        'url': url,
        'timestamp': datetime.utcnow().isoformat(),
        'checks': [],
        'score': 100,
        'tickets': [],
        'nis2_score': 0,
        'nis2_details': []
    }

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # --- Check 1 : HTTPS ---
    https_ok = url.startswith('https://')
    results['checks'].append({
        'name': 'HTTPS activé',
        'status': 'pass' if https_ok else 'fail',
        'severity': 'critical',
        'detail': 'La connexion utilise HTTPS.' if https_ok else 'Le site n\'utilise pas HTTPS. Les données transitent en clair.'
    })
    if not https_ok:
        results['score'] -= 30
        results['tickets'].append({
            'title': 'HTTPS non activé',
            'description': 'Le site utilise HTTP. Toutes les données transitent en clair — critique pour les données énergétiques des foyers Check-Elec.',
            'severity': 'critical'
        })

    # --- Requête HTTP ---
    headers_data = {}
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=True)
        headers_data = dict(response.headers)
    except requests.exceptions.SSLError:
        results['checks'].append({
            'name': 'Certificat SSL',
            'status': 'fail',
            'severity': 'critical',
            'detail': 'Certificat SSL invalide ou expiré.'
        })
        results['score'] -= 25
        results['tickets'].append({
            'title': 'Certificat SSL invalide',
            'description': 'Le certificat SSL est invalide. Bloquant pour la conformité NIS2.',
            'severity': 'critical'
        })
        results['nis2_details'] = _compute_nis2(results['checks'])
        results['nis2_score'] = _nis2_score(results['nis2_details'])
        return results
    except requests.exceptions.ConnectionError:
        results['checks'].append({
            'name': 'Connexion',
            'status': 'error',
            'severity': 'critical',
            'detail': 'Impossible de se connecter. Vérifie que l\'URL est correcte.'
        })
        results['score'] = 0
        return results
    except requests.exceptions.Timeout:
        results['checks'].append({
            'name': 'Connexion',
            'status': 'error',
            'severity': 'medium',
            'detail': 'Timeout — le serveur ne répond pas en moins de 10s.'
        })
        results['score'] -= 10
        return results

    # --- Check 2 : HSTS ---
    hsts = 'Strict-Transport-Security' in headers_data
    results['checks'].append({
        'name': 'HSTS (Strict-Transport-Security)',
        'status': 'pass' if hsts else 'fail',
        'severity': 'high',
        'detail': headers_data.get('Strict-Transport-Security', 'Header absent. Requis par NIS2 article 21.')
    })
    if not hsts:
        results['score'] -= 15
        results['tickets'].append({
            'title': 'HSTS manquant',
            'description': 'Requis par NIS2 Art. 21. Sans HSTS, les connexions HTTP peuvent être forcées par un attaquant (SSL stripping).',
            'severity': 'high'
        })

    # --- Check 3 : X-Frame-Options ---
    xfo = 'X-Frame-Options' in headers_data
    results['checks'].append({
        'name': 'X-Frame-Options (anti-clickjacking)',
        'status': 'pass' if xfo else 'fail',
        'severity': 'medium',
        'detail': headers_data.get('X-Frame-Options', 'Header absent. Ajoute: X-Frame-Options: DENY')
    })
    if not xfo:
        results['score'] -= 10
        results['tickets'].append({
            'title': 'X-Frame-Options manquant',
            'description': 'Le site peut être intégré dans une iframe malveillante (clickjacking). Risque sur les dashboards clients Check-Elec.',
            'severity': 'medium'
        })

    # --- Check 4 : X-Content-Type-Options ---
    xcto = headers_data.get('X-Content-Type-Options', '').lower() == 'nosniff'
    results['checks'].append({
        'name': 'X-Content-Type-Options',
        'status': 'pass' if xcto else 'fail',
        'severity': 'medium',
        'detail': headers_data.get('X-Content-Type-Options', 'Header absent. Ajoute: X-Content-Type-Options: nosniff')
    })
    if not xcto:
        results['score'] -= 10
        results['tickets'].append({
            'title': 'X-Content-Type-Options manquant',
            'description': 'Les navigateurs peuvent mal interpréter le type de fichiers servis, permettant l\'exécution de scripts malveillants.',
            'severity': 'medium'
        })

    # --- Check 5 : CSP ---
    csp = 'Content-Security-Policy' in headers_data
    results['checks'].append({
        'name': 'Content-Security-Policy (CSP)',
        'status': 'pass' if csp else 'warn',
        'severity': 'medium',
        'detail': headers_data.get('Content-Security-Policy', 'Absent. Vulnérabilité XSS accrue — critique pour les APIs IoT.')
    })
    if not csp:
        results['score'] -= 10
        results['tickets'].append({
            'title': 'CSP absente',
            'description': 'Sans Content-Security-Policy, les APIs exposant des données de consommation Check-Elec sont plus vulnérables aux attaques XSS.',
            'severity': 'medium'
        })

    # --- Check 6 : Fuite version serveur ---
    server = headers_data.get('Server', '')
    server_leak = bool(server) and any(
        v in server.lower() for v in ['apache', 'nginx', 'iis', 'php', 'express']
    )
    results['checks'].append({
        'name': 'Fuite version serveur (Server header)',
        'status': 'warn' if server_leak else 'pass',
        'severity': 'low',
        'detail': f'Server: {server}' if server else 'Header Server masqué. Bonne pratique.'
    })
    if server_leak:
        results['score'] -= 5
        results['tickets'].append({
            'title': 'Version serveur exposée',
            'description': f'Le header Server expose : "{server}". Aide les attaquants à cibler des CVE connues.',
            'severity': 'low'
        })

    # --- Check 7 : Referrer-Policy ---
    rp = 'Referrer-Policy' in headers_data
    results['checks'].append({
        'name': 'Referrer-Policy',
        'status': 'pass' if rp else 'warn',
        'severity': 'low',
        'detail': headers_data.get('Referrer-Policy', 'Absent. Recommandé : strict-origin-when-cross-origin')
    })
    if not rp:
        results['score'] -= 5

    # ============================================================
    # CHECKS SPÉCIFIQUES LENERGY SMART
    # ============================================================

    # --- Check NIS2 : Permissions-Policy ---
    pp = 'Permissions-Policy' in headers_data
    results['checks'].append({
        'name': '[NIS2] Permissions-Policy',
        'status': 'pass' if pp else 'warn',
        'severity': 'medium',
        'detail': headers_data.get('Permissions-Policy', 'Absent. NIS2 Art.21 recommande de limiter les permissions navigateur (géolocalisation, caméra, micro).')
    })
    if not pp:
        results['score'] -= 5
        results['tickets'].append({
            'title': '[NIS2] Permissions-Policy absent',
            'description': 'NIS2 Art. 21 impose des mesures de contrôle d\'accès. Ce header limite les fonctionnalités navigateur accessibles aux scripts tiers.',
            'severity': 'medium'
        })

    # --- Check RGPD : Exposition de données personnelles ---
    rgpd_headers = ['set-cookie', 'x-user-id', 'x-customer-id', 'x-account']
    exposed_rgpd = [h for h in rgpd_headers if h in {k.lower() for k in headers_data.keys()}]
    rgpd_ok = len(exposed_rgpd) == 0

    # Vérifie aussi si les cookies ont les flags Secure et HttpOnly
    cookie = headers_data.get('Set-Cookie', '')
    cookie_secure = 'secure' in cookie.lower() if cookie else True
    cookie_httponly = 'httponly' in cookie.lower() if cookie else True

    if cookie and (not cookie_secure or not cookie_httponly):
        rgpd_ok = False
        results['tickets'].append({
            'title': '[RGPD] Cookie sans flag Secure/HttpOnly',
            'description': 'Les cookies de session ne sont pas protégés. Risque de vol de session sur les comptes clients Check-Elec. Non conforme RGPD Art. 32.',
            'severity': 'high'
        })
        results['score'] -= 10

    results['checks'].append({
        'name': '[RGPD] Sécurité des cookies et données personnelles',
        'status': 'pass' if rgpd_ok else 'fail',
        'severity': 'high',
        'detail': 'Cookies correctement sécurisés (Secure + HttpOnly).' if rgpd_ok else 'Cookies sans flag Secure ou HttpOnly détectés. Non conforme RGPD Art. 32.'
    })

    # --- Check IoT : Exposition d'endpoints sensibles ---
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    iot_endpoints = ['/api', '/api/v1', '/metrics', '/health', '/debug', '/admin', '/status']
    exposed_endpoints = []

    for endpoint in iot_endpoints:
        try:
            r = requests.get(base + endpoint, timeout=5, verify=False)
            if r.status_code == 200:
                exposed_endpoints.append(endpoint)
        except Exception:
            pass

    iot_ok = len(exposed_endpoints) == 0
    results['checks'].append({
        'name': '[IoT/Lenergy] Endpoints sensibles exposés',
        'status': 'pass' if iot_ok else 'fail',
        'severity': 'critical' if not iot_ok else 'low',
        'detail': 'Aucun endpoint sensible exposé publiquement.' if iot_ok else f'Endpoints accessibles sans auth : {", ".join(exposed_endpoints)}. Critique pour les APIs Check-Elec.'
    })
    if not iot_ok:
        results['score'] -= 20
        results['tickets'].append({
            'title': '[IoT] Endpoints API exposés sans authentification',
            'description': f'Les endpoints suivants sont accessibles publiquement sans authentification : {", ".join(exposed_endpoints)}. Pour une plateforme gérant 1,2M de points télémétrés, c\'est critique.',
            'severity': 'critical'
        })

    # --- Check NIS2 : CORS ---
    cors = headers_data.get('Access-Control-Allow-Origin', '')
    cors_wildcard = cors == '*'
    results['checks'].append({
        'name': '[NIS2] CORS — contrôle des origines',
        'status': 'fail' if cors_wildcard else 'pass',
        'severity': 'high',
        'detail': 'CORS en wildcard (*) : toute origine peut interroger cette API. Critique pour les APIs Enedis/Check-Elec.' if cors_wildcard else f'CORS correctement configuré : {cors if cors else "header absent (OK si API privée)"}.'
    })
    if cors_wildcard:
        results['score'] -= 15
        results['tickets'].append({
            'title': '[NIS2] CORS wildcard (*)',
            'description': 'L\'API accepte des requêtes de n\'importe quelle origine. N\'importe quel site tiers peut interroger vos APIs Check-Elec. Non conforme NIS2 Art. 21.',
            'severity': 'high'
        })

    results['score'] = max(0, results['score'])

    # Calcul conformité NIS2
    results['nis2_details'] = _compute_nis2(results['checks'])
    results['nis2_score'] = _nis2_score(results['nis2_details'])

    return results


# ============================================================
# CALCUL CONFORMITÉ NIS2
# ============================================================

NIS2_CRITERIA = [
    {
        'id': 'nis2_https',
        'label': 'Chiffrement des communications (Art. 21.2.h)',
        'check_names': ['HTTPS activé', 'HSTS (Strict-Transport-Security)'],
        'description': 'Toutes les communications doivent être chiffrées. HTTPS + HSTS obligatoires.'
    },
    {
        'id': 'nis2_access',
        'label': 'Contrôle d\'accès et authentification (Art. 21.2.i)',
        'check_names': ['[NIS2] CORS — contrôle des origines', '[IoT/Lenergy] Endpoints sensibles exposés'],
        'description': 'Les APIs et endpoints doivent être protégés par authentification. CORS correctement configuré.'
    },
    {
        'id': 'nis2_data',
        'label': 'Protection des données personnelles (Art. 21.2 + RGPD)',
        'check_names': ['[RGPD] Sécurité des cookies et données personnelles'],
        'description': 'Les données clients (foyers Check-Elec) doivent être protégées conformément au RGPD Art. 32.'
    },
    {
        'id': 'nis2_integrity',
        'label': 'Intégrité des systèmes (Art. 21.2.e)',
        'check_names': ['Content-Security-Policy (CSP)', 'X-Content-Type-Options', '[NIS2] Permissions-Policy'],
        'description': 'Protection contre les injections de contenu malveillant (XSS, clickjacking).'
    },
    {
        'id': 'nis2_config',
        'label': 'Sécurité de la configuration (Art. 21.2.b)',
        'check_names': ['X-Frame-Options (anti-clickjacking)', 'Fuite version serveur (Server header)'],
        'description': 'Configuration sécurisée des serveurs, pas d\'exposition d\'informations techniques.'
    },
]


def _compute_nis2(checks):
    check_map = {c['name']: c['status'] for c in checks}
    details = []
    for criterion in NIS2_CRITERIA:
        statuses = [check_map.get(name, 'unknown') for name in criterion['check_names']]
        if all(s == 'pass' for s in statuses):
            status = 'conforme'
        elif any(s == 'fail' for s in statuses):
            status = 'non_conforme'
        else:
            status = 'partiel'
        details.append({
            'id': criterion['id'],
            'label': criterion['label'],
            'description': criterion['description'],
            'status': status,
            'checks': criterion['check_names']
        })
    return details


def _nis2_score(nis2_details):
    if not nis2_details:
        return 0
    points = sum(
        2 if d['status'] == 'conforme' else (1 if d['status'] == 'partiel' else 0)
        for d in nis2_details
    )
    return round((points / (len(nis2_details) * 2)) * 100)


def score_to_grade(score):
    if score >= 90: return 'A'
    elif score >= 75: return 'B'
    elif score >= 60: return 'C'
    elif score >= 40: return 'D'
    else: return 'F'


def score_to_color(score):
    if score >= 75: return 'green'
    elif score >= 50: return 'orange'
    else: return 'red'


def nis2_status_label(status):
    if status == 'conforme': return '✓ Conforme'
    elif status == 'partiel': return '⚠ Partiel'
    else: return '✗ Non conforme'


def nis2_status_color(status):
    if status == 'conforme': return 'green'
    elif status == 'partiel': return 'orange'
    else: return 'red'