import requests
import json
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def analyze_url(url):
    """
    Analyse une URL et retourne un rapport de sécurité.
    Retourne un dict avec les résultats et un score global.
    """
    results = {
        'url': url,
        'timestamp': datetime.utcnow().isoformat(),
        'checks': [],
        'score': 0,
        'tickets': []
    }
    
    # Normalise l'URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    hostname = parsed.netloc
    
    # --- Check 1 : HTTPS (40 points) ---
    https_ok = url.startswith('https://')
    results['checks'].append({
        'name': 'HTTPS activé',
        'status': 'pass' if https_ok else 'fail',
        'severity': 'critical',
        'detail': 'La connexion utilise HTTPS.' if https_ok else 'Le site n\'utilise pas HTTPS. Les données transitent en clair.'
    })
    if https_ok:
        results['score'] += 40
    else:
        results['tickets'].append({
            'title': 'HTTPS non activé',
            'description': 'Le site utilise HTTP au lieu de HTTPS. Toutes les données échangées entre l\'utilisateur et le serveur transitent en clair et peuvent être interceptées.',
            'severity': 'critical'
        })
    
    # --- Requête HTTP pour récupérer les headers ---
    headers_data = {}
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=True)
        headers_data = dict(response.headers)
        status_code = response.status_code
    except requests.exceptions.SSLError:
        results['checks'].append({
            'name': 'Certificat SSL',
            'status': 'fail',
            'severity': 'critical',
            'detail': 'Le certificat SSL est invalide ou expiré.'
        })
        results['score'] = max(0, results['score'] - 25)
        results['tickets'].append({
            'title': 'Certificat SSL invalide',
            'description': 'Le certificat SSL du site est invalide, auto-signé ou expiré. Les navigateurs afficheront un avertissement de sécurité.',
            'severity': 'critical'
        })
        return results
    except requests.exceptions.ConnectionError:
        results['checks'].append({
            'name': 'Connexion',
            'status': 'error',
            'severity': 'critical',
            'detail': 'Impossible de se connecter au serveur. Vérifie que l\'URL est correcte.'
        })
        results['score'] = 0
        return results
    except requests.exceptions.Timeout:
        results['checks'].append({
            'name': 'Connexion',
            'status': 'error',
            'severity': 'medium',
            'detail': 'Le serveur a mis trop de temps à répondre (timeout > 10s).'
        })
        results['score'] = max(0, results['score'] - 10)
        return results
    
    # --- Check 2 : HSTS (15 points) ---
    hsts = 'Strict-Transport-Security' in headers_data
    results['checks'].append({
        'name': 'HSTS (Strict-Transport-Security)',
        'status': 'pass' if hsts else 'fail',
        'severity': 'high',
        'detail': headers_data.get('Strict-Transport-Security', 'Header absent. Ajoute: Strict-Transport-Security: max-age=31536000; includeSubDomains')
    })
    if hsts:
        results['score'] += 15
    else:
        results['tickets'].append({
            'title': 'Header HSTS manquant',
            'description': 'Le header Strict-Transport-Security est absent. Sans HSTS, les utilisateurs peuvent être redirigés vers une version HTTP du site lors d\'une attaque de type SSL-stripping.',
            'severity': 'high'
        })
    
    # --- Check 3 : X-Frame-Options (10 points) ---
    xfo = 'X-Frame-Options' in headers_data
    results['checks'].append({
        'name': 'X-Frame-Options (anti-clickjacking)',
        'status': 'pass' if xfo else 'fail',
        'severity': 'medium',
        'detail': headers_data.get('X-Frame-Options', 'Header absent. Ajoute: X-Frame-Options: DENY')
    })
    if xfo:
        results['score'] += 10
    else:
        results['tickets'].append({
            'title': 'Header X-Frame-Options manquant',
            'description': 'Sans ce header, le site peut être intégré dans une iframe malveillante. Cela permet des attaques de clickjacking où l\'utilisateur clique sur des éléments invisibles.',
            'severity': 'medium'
        })
    
    # --- Check 4 : X-Content-Type-Options (10 points) ---
    xcto = headers_data.get('X-Content-Type-Options', '').lower() == 'nosniff'
    results['checks'].append({
        'name': 'X-Content-Type-Options',
        'status': 'pass' if xcto else 'fail',
        'severity': 'medium',
        'detail': headers_data.get('X-Content-Type-Options', 'Header absent. Ajoute: X-Content-Type-Options: nosniff')
    })
    if xcto:
        results['score'] += 10
    else:
        results['tickets'].append({
            'title': 'Header X-Content-Type-Options manquant',
            'description': 'Sans ce header, les navigateurs peuvent "deviner" le type MIME d\'un fichier, ce qui peut permettre l\'exécution de scripts malveillants déguisés en fichiers inoffensifs.',
            'severity': 'medium'
        })
    
    # --- Check 5 : CSP (10 points) ---
    csp = 'Content-Security-Policy' in headers_data
    results['checks'].append({
        'name': 'Content-Security-Policy (CSP)',
        'status': 'pass' if csp else 'warn',
        'severity': 'medium',
        'detail': headers_data.get('Content-Security-Policy', 'Header absent. Ajoute une CSP pour limiter les sources de scripts autorisées.')
    })
    if csp:
        results['score'] += 10
    else:
        results['tickets'].append({
            'title': 'Content-Security-Policy absent',
            'description': 'La CSP permet de définir quelles sources de contenu (scripts, images, styles) sont autorisées. Sans CSP, le site est plus vulnérable aux attaques XSS (Cross-Site Scripting).',
            'severity': 'medium'
        })
    
    # --- Check 6 : Server header (5 points si masqué) ---
    server = headers_data.get('Server', '')
    server_info_leak = bool(server) and any(v in server.lower() for v in ['apache', 'nginx', 'iis', 'php', 'express'])
    results['checks'].append({
        'name': 'Fuite d\'information (Server header)',
        'status': 'warn' if server_info_leak else 'pass',
        'severity': 'low',
        'detail': f'Server: {server}' if server else 'Header Server absent ou masqué. Bonne pratique.'
    })
    if not server_info_leak:
        results['score'] += 5
    else:
        results['tickets'].append({
            'title': 'Fuite de version serveur',
            'description': f'Le header Server expose la technologie utilisée : "{server}". Cette information aide les attaquants à cibler des vulnérabilités connues pour cette version.',
            'severity': 'low'
        })
    
    # --- Check 7 : Referrer-Policy (5 points) ---
    rp = 'Referrer-Policy' in headers_data
    results['checks'].append({
        'name': 'Referrer-Policy',
        'status': 'pass' if rp else 'warn',
        'severity': 'low',
        'detail': headers_data.get('Referrer-Policy', 'Header absent. Recommandé : Referrer-Policy: strict-origin-when-cross-origin')
    })
    if rp:
        results['score'] += 5
    
    # Bonus "connexion réussie" (15 points)   <-- MODIFIÉ ICI
    results['score'] += 15
    
    # Assure que le score est entre 0 et 100
    results['score'] = min(100, max(0, results['score']))
    
    return results


def score_to_grade(score):
    """Convertit un score numérique en lettre."""
    if score >= 90:
        return 'A'
    elif score >= 75:
        return 'B'
    elif score >= 60:
        return 'C'
    elif score >= 40:
        return 'D'
    else:
        return 'F'


def score_to_color(score):
    """Retourne une couleur CSS selon le score."""
    if score >= 75:
        return 'green'
    elif score >= 50:
        return 'orange'
    else:
        return 'red'