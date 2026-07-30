import requests
import json
import socket
import ssl
import re
import uuid
from urllib.parse import urlparse
from datetime import datetime
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')  # On garde seulement pour les warnings internes

# ============================================================
# PONDERATION PAR CRITICITE (documentation / auditabilite)
# ============================================================
SEVERITY_SCORE_RANGES = {
    'critical': (20, 30),
    'high':     (10, 20),
    'medium':   (5, 10),
    'low':      (2, 5),
}

def scoring_formula_explanation():
    """Texte a afficher dans le rapport NIS2 pour expliquer le bareme de scoring."""
    return (
        "Le score part de 100 points. Chaque verification en echec applique une penalite "
        "proportionnelle a sa criticite : "
        f"Critique (-{SEVERITY_SCORE_RANGES['critical'][0]} a -{SEVERITY_SCORE_RANGES['critical'][1]} pts), "
        f"Elevee (-{SEVERITY_SCORE_RANGES['high'][0]} a -{SEVERITY_SCORE_RANGES['high'][1]} pts), "
        f"Moyenne (-{SEVERITY_SCORE_RANGES['medium'][0]} a -{SEVERITY_SCORE_RANGES['medium'][1]} pts), "
        f"Faible (-{SEVERITY_SCORE_RANGES['low'][0]} a -{SEVERITY_SCORE_RANGES['low'][1]} pts). "
        "Le score final est plafonne entre 0 et 100. "
        "Les penalites de headers HTTP appartenant a la meme famille de risque "
        "(injection de contenu / clickjacking) sont regroupees et plafonnees "
        "afin d'eviter un cumul disproportionne par rapport a la severite reelle."
    )


# ============================================================
# GROUPES DE RISQUE — PLAFONNEMENT DES PENALITES CUMULEES
# ============================================================
RISK_GROUPS = {
    'content_injection_clickjacking': {
        'label': 'Defense en profondeur — injection de contenu / clickjacking',
        'members': [
            'csp', 'xfo', 'xcto', 'coop', 'corp', 'permissions_policy'
        ],
        'max_penalty': 20,
    },
}


def _apply_grouped_penalty(results, group_key, member_key, raw_penalty):
    if '_grouped_penalties' not in results:
        results['_grouped_penalties'] = {}
    bucket = results['_grouped_penalties'].setdefault(group_key, {})
    bucket[member_key] = raw_penalty


def _finalize_grouped_penalties(results):
    grouped = results.pop('_grouped_penalties', {})
    for group_key, members in grouped.items():
        group_def = RISK_GROUPS.get(group_key)
        if not group_def:
            continue
        raw_total = sum(members.values())
        capped = min(raw_total, group_def['max_penalty'])
        results['score'] -= capped
        if raw_total > capped:
            results['checks'].append({
                'name': f"[Scoring] Plafonnement — {group_def['label']}",
                'status': 'info',
                'severity': 'low',
                'detail': (
                    f"Penalite brute cumulee du groupe : -{raw_total} pts "
                    f"({len(members)} controle(s) en echec dans cette famille de risque). "
                    f"Plafonnee a -{capped} pts pour eviter un cumul disproportionne : "
                    f"ces controles se recoupent partiellement (ils protegent tous, en partie, "
                    f"contre l'injection de contenu ou le clickjacking)."
                )
            })


# ============================================================
# HELPER — REQUETE AVEC RETRY (AVEC VALIDATION SSL)
# ============================================================

def _get_with_retry(url, timeout=10, retries=2):
    """
    Effectue une requête GET avec retry et validation SSL active.
    """
    last_exception = None
    for attempt in range(retries + 1):
        try:
            return requests.get(url, timeout=timeout, allow_redirects=True,
                                verify=True,  # ✅ Validation SSL activée
                                headers={'User-Agent': 'DevShield-Scanner/1.0'})
        except requests.exceptions.SSLError as e:
            # On lève l'exception pour la gérer plus haut (certificat invalide)
            raise
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last_exception = e
            continue
    raise last_exception


# ============================================================
# HELPER — DETECTION CATCH-ALL (fiabilite fichiers/endpoints)
# ============================================================

def _detect_catchall(base):
    fake_path = f'/__devshield_probe_{uuid.uuid4().hex[:12]}__.txt'
    try:
        r = requests.get(base + fake_path, timeout=5, verify=True,
                         allow_redirects=False,
                         headers={'User-Agent': 'DevShield-Scanner/1.0'})
        return r.status_code == 200, r.headers.get('Content-Type', ''), len(r.content)
    except Exception:
        return False, None, None


def _looks_like_catchall_response(r, catchall_ctype, catchall_len):
    if catchall_len is None:
        return False
    content_type = r.headers.get('Content-Type', '')
    return content_type == catchall_ctype and abs(len(r.content) - catchall_len) < 50


# ============================================================
# HELPER — TICKETS AVEC NIVEAU DE PREUVE (evidence)
# ============================================================
EVIDENCE_CONFIRMED = 'confirmed'
EVIDENCE_SIGNATURE = 'signature'
EVIDENCE_MISSING_CONTROL = 'missing_control'


def _add_ticket(results, title, description, severity, evidence=EVIDENCE_MISSING_CONTROL):
    results['tickets'].append({
        'title': title,
        'description': description,
        'severity': severity,
        'evidence': evidence
    })


def _add_ticket_with_remediation(results, title, description, severity, remediation, evidence=EVIDENCE_MISSING_CONTROL):
    """Ajoute un ticket avec une recommandation de correction."""
    results['tickets'].append({
        'title': title,
        'description': description,
        'severity': severity,
        'evidence': evidence,
        'remediation': remediation
    })


def _add_check(results, name, status, severity, detail):
    results['checks'].append({
        'name': name,
        'status': status,
        'severity': severity,
        'detail': detail
    })


# ============================================================
# DICTIONNAIRES CVE PAR TECHNOLOGIE (fallback si API NVD indisponible)
# ============================================================
TECH_CVE = {
    'WordPress': [
        {'id': 'CVE-2023-5360', 'description': 'Cross-Site Scripting dans WordPress core', 'severity': 'high'},
        {'id': 'CVE-2023-4519', 'description': 'Cross-Site Scripting dans le bloc Comments', 'severity': 'medium'},
        {'id': 'CVE-2023-3997', 'description': 'SQL Injection dans certains plugins', 'severity': 'critical'},
    ],
    'Drupal': [
        {'id': 'CVE-2023-5437', 'description': 'Cross-Site Scripting dans Drupal core', 'severity': 'high'},
        {'id': 'CVE-2023-3143', 'description': 'Cross-Site Scripting dans le module CKEditor', 'severity': 'medium'},
        {'id': 'CVE-2023-3192', 'description': 'Cross-Site Scripting dans le module File', 'severity': 'medium'},
    ],
    'Apache': [
        {'id': 'CVE-2023-45802', 'description': 'Apache HTTP Server denial of service', 'severity': 'high'},
        {'id': 'CVE-2023-43622', 'description': 'Apache HTTP Server mod_proxy denial of service', 'severity': 'medium'},
        {'id': 'CVE-2022-36760', 'description': 'Apache HTTP Server HTTP/2 denial of service', 'severity': 'high'},
    ],
    'PHP': [
        {'id': 'CVE-2023-3824', 'description': 'PHP denial of service via compression', 'severity': 'high'},
        {'id': 'CVE-2023-3247', 'description': 'PHP stack buffer overflow in sqlite3', 'severity': 'critical'},
        {'id': 'CVE-2023-31042', 'description': 'PHP HTTP proxy authentication bypass', 'severity': 'high'},
    ],
    'jQuery obsolete': [
        {'id': 'CVE-2020-11022', 'description': 'jQuery Cross-Site Scripting (XSS) via HTML', 'severity': 'high'},
        {'id': 'CVE-2020-11023', 'description': 'jQuery Cross-Site Scripting (XSS)', 'severity': 'high'},
        {'id': 'CVE-2019-11358', 'description': 'jQuery Cross-Site Scripting via jQuery.parseHTML', 'severity': 'medium'},
    ],
    'nginx': [
        {'id': 'CVE-2021-23017', 'description': 'nginx HTTP/2 denial of service', 'severity': 'high'},
        {'id': 'CVE-2022-41741', 'description': 'nginx HTTP/2 denial of service', 'severity': 'medium'},
        {'id': 'CVE-2023-44487', 'description': 'nginx HTTP/2 Rapid Reset denial of service', 'severity': 'critical'},
    ],
}


# ============================================================
# SOUS-DOMAINES COMMUNS POUR L'ENUMERATION DNS
# ============================================================
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
    'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ftp',
    'mail2', 'new', 'mysql', 'old', 'mssql', 'backup', 'mx', 'download', 'support',
    'careers', 'media', 'static', 'staging', 'api', 'docs', 'shop', 'store',
    'app', 'demo', 'cloud', 'files', 'portal', 'remote', 'secure', 'web', 'email',
    'dashboard', 'account', 'auth', 'login', 'signup', 'register', 'pay', 'payment',
    'billing', 'invoice', 'order', 'cart', 'checkout', 'partner', 'partners',
    'affiliate', 'help', 'info', 'about', 'contact', 'sales', 'marketing',
    'analytics', 'metrics', 'monitor', 'status', 'health', 'proxy', 'cdn',
    'static', 'assets', 'img', 'images', 'css', 'js', 'fonts', 'downloads'
]


# ============================================================
# PORTS COMMUNS À SCANNER
# ============================================================
COMMON_PORTS = [
    # Services web
    80, 443, 8080, 8443,
    # Mail
    25, 465, 587, 993, 995,
    # FTP
    20, 21, 22, 23,
    # Bases de données
    1433, 3306, 5432, 6379, 27017,
    # Administration
    3389, 5900, 5901, 5800,
    # Autres services
    53, 110, 143, 389, 636, 3306, 3389,
    5060, 5061, 5222, 5223,
    8080, 8443, 9000, 9090,
    9200, 9300, 9418, 9999,
]


# ============================================================
# ANTI-SSRF — DETECTION DES IP PRIVEES ET DOMAINES INTERNES
# ============================================================

PRIVATE_IP_RANGES = [
    '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '169.254.0.0/16', '::1', 'fc00::/7', 'fe80::/10'
]

def _is_private_ip(hostname):
    """
    Vérifie si une adresse IP (ou un hôte) est une IP privée / interne.
    """
    try:
        # Résoudre l'hôte en IP
        ip = socket.gethostbyname(hostname)
        # Vérifier si l'IP est dans les plages privées
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        for network in PRIVATE_IP_RANGES:
            if ip_obj in ipaddress.ip_network(network, strict=False):
                return True
        return False
    except Exception:
        # En cas d'erreur (nom de domaine non résolu), on autorise le scan
        return False


def _is_internal_domain(hostname):
    """
    Vérifie si le domaine est interne (ex: .local, .intra, etc.)
    """
    internal_suffixes = ['.local', '.intra', '.internal', '.lan', '.home', '.host']
    return any(hostname.endswith(suffix) for suffix in internal_suffixes)

# ============================================================
# VALIDATION DE PROPRIETE DE DOMAINE (via TXT record)
# ============================================================

def _validate_domain_ownership(hostname):
    """
    Vérifie la propriété du domaine via un enregistrement TXT.
    Pour l'instant, on vérifie simplement que le domaine a un enregistrement TXT
    contenant un token spécifique, ou on simule une validation.
    """
    # Simulons une validation simple : on vérifie que le domaine existe et a un enregistrement TXT
    # Dans une vraie implémentation, on vérifierait un token spécifique.
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, 'TXT', lifetime=5)
        for r in answers:
            txt = str(r).lower()
            if 'devshield-verify' in txt:
                return True
        # Si pas de token, on considère que le domaine n'est pas vérifié
        return False
    except Exception:
        # Si on ne peut pas résoudre, on retourne False par sécurité
        return False


# ============================================================
# MOTEUR PRINCIPAL
# ============================================================

def analyze_url(url, active_scan=False):
    """
    active_scan=True active les tests OWASP actifs (SQLi, XSS reflechi, CSRF)
    qui envoient des payloads d'injection au serveur cible. A n'activer QUE
    pour des projets explicitement autorises par leur proprietaire
    (Project.authorized_active_scan == True). Ne JAMAIS activer sur
    quick_scan, qui accepte n'importe quelle URL sans consentement du
    proprietaire — envoyer des payloads d'injection sans autorisation
    est illegal en France (Art. 323-1 Code penal).
    """
    results = {
        'url': url,
        'timestamp': datetime.utcnow().isoformat(),
        'checks': [],
        'score': 100,
        'score_label': 'Indice de durcissement / conformite DevShield',
        'tickets': [],
        'nis2_score': 0,
        'nis2_details': [],
        'categories': {},
        '_grouped_penalties': {}
    }

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]
    base = f"{parsed.scheme}://{parsed.netloc}"

    # ============================================================
    # ANTI-SSRF : BLOCAGE DES IP PRIVEES
    # ============================================================
    if _is_private_ip(hostname) or _is_internal_domain(hostname):
        _add_check(results, 'Sécurité - Anti-SSRF', 'fail', 'critical',
                   f"Le domaine '{hostname}' pointe vers une adresse IP privée ou un domaine interne. "
                   "DevShield n'autorise pas le scan de cibles internes pour des raisons de sécurité.")
        results['score'] = 0
        results['tickets'].append({
            'title': 'Tentative de scan d\'une cible interne bloquée',
            'description': f'Le scan de {hostname} a été bloqué car il cible une adresse IP privée ou un domaine interne.',
            'severity': 'critical',
            'evidence': EVIDENCE_CONFIRMED
        })
        results['nis2_details'] = _compute_nis2(results['checks'])
        results['nis2_score'] = _nis2_score(results['nis2_details'])
        return results

    # ============================================================
    # VALIDATION DE PROPRIETE DU DOMAINE
    # ============================================================
    # Si ce n'est pas un scan rapide, on vérifie la propriété
    # Pour le quick_scan, on laisse passer (pas de validation stricte)
    # Mais on pourrait l'activer si besoin
    # if not quick_scan and not _validate_domain_ownership(hostname):
    #     _add_check(results, 'Validation de propriété du domaine', 'warn', 'high',
    #                "Le domaine n'a pas de token de validation. Veuillez ajouter un enregistrement TXT 'devshield-verify' pour confirmer la propriété.")
    #     results['score'] -= 10
    #     results['tickets'].append({
    #         'title': 'Domaine non vérifié',
    #         'description': "Le domaine n'a pas été vérifié. Pour autoriser les scans approfondis, ajoutez un enregistrement TXT 'devshield-verify=<token>'.",
    #         'severity': 'medium',
    #         'evidence': EVIDENCE_MISSING_CONTROL
    #     })
    # Pour l'instant, je laisse commenté car la validation est optionnelle
    # On pourra l'activer plus tard.
	
    # ============================================================
    # VALIDATION DE PROPRIETE DU DOMAINE (pour les scans intrusifs)
    # ============================================================
    # Pour les scans avec tests actifs, on vérifie la propriété du domaine
    if active_scan:
        try:
            from app.models import DomainVerification
            domain_verified = DomainVerification.query.filter_by(
                domain=hostname,
                verified=True
            ).first()
            
            if not domain_verified:
                _add_check(results, 'Validation de propriété du domaine', 'warn', 'high',
                           f"Le domaine '{hostname}' n'est pas vérifié. "
                           "Les tests actifs (SQLi, XSS, CSRF) nécessitent une autorisation explicite du propriétaire. "
                           "Générez un token de vérification depuis la page du projet.")
                results['score'] -= 5
                results['tickets'].append({
                    'title': 'Domaine non vérifié pour les tests actifs',
                    'description': f"Le domaine {hostname} n'a pas été vérifié. "
                                   f"Pour autoriser les tests actifs, générez un token de vérification.",
                    'severity': 'high',
                    'evidence': EVIDENCE_MISSING_CONTROL,
                    'remediation': '1. Allez sur la page du projet\n'
                                   '2. Cliquez sur "Vérifier le domaine"\n'
                                   '3. Placez le fichier généré à l\'URL indiquée\n'
                                   '4. Attendez que le domaine soit vérifié'
                })
        except ImportError:
            pass  # Le modèle n'existe pas encore (migration à faire)
    
    # --- Check 1 : HTTPS ---
    https_ok = url.startswith('https://')
    # ... suite du code ...

    # --- Check 1 : HTTPS ---
    https_ok = url.startswith('https://')
    _add_check(results, 'HTTPS active', 'pass' if https_ok else 'fail', 'critical',
               'La connexion utilise HTTPS.' if https_ok
               else 'Le site n\'utilise pas HTTPS. Les données transitent en clair.')
    if not https_ok:
        results['score'] -= 30
        _add_ticket_with_remediation(
            results,
            'HTTPS non active',
            'Le site utilise HTTP. Toutes les donnees transitent en clair.',
            'critical',
            'Activer HTTPS sur le serveur. Installation d\'un certificat SSL/TLS (Let\'s Encrypt, ou certifie).\n'
            'Nginx : configurer un bloc server avec listen 443 ssl et les certificats.\n'
            'Apache : configurer VirtualHost sur le port 443 avec SSLEngine on.'
        )

    # --- Requête HTTP principale (avec validation SSL) ---
    headers_data = {}
    response = None
    html_content = ''

    try:
        response = _get_with_retry(url, timeout=10, retries=2)
        headers_data = dict(response.headers)
        html_content = response.text[:50000]
    except requests.exceptions.SSLError as e:
        # Gestion des erreurs SSL
        error_msg = str(e)
        _add_check(results, 'Certificat SSL', 'fail', 'critical',
                   f'Certificat SSL invalide ou problème de validation : {error_msg[:150]}')
        results['score'] -= 25
        _add_ticket_with_remediation(
            results,
            'Certificat SSL invalide',
            f'Le certificat SSL est invalide. Erreur : {error_msg[:150]}',
            'critical',
            'Renouveler ou installer un certificat SSL valide. Voir Let\'s Encrypt pour un certificat gratuit.\n'
            'Vérifier que la chaîne de certificats est complète et que les dates sont valides.'
        )
        results['nis2_details'] = _compute_nis2(results['checks'])
        results['nis2_score'] = _nis2_score(results['nis2_details'])
        results.pop('_grouped_penalties', None)
        return results
    except requests.exceptions.ConnectionError:
        _add_check(results, 'Connexion', 'error', 'critical',
                   'Impossible de se connecter. Verifie que l\'URL est correcte.')
        results['score'] = 0
        results.pop('_grouped_penalties', None)
        return results
    except requests.exceptions.Timeout:
        _add_check(results, 'Connexion', 'error', 'medium',
                   'Timeout — le serveur ne repond pas en moins de 10s.')
        results['score'] -= 10
        results.pop('_grouped_penalties', None)
        return results

    # ============================================================
    # CATEGORIE 1 : HEADERS DE SECURITE HTTP
    # ============================================================

    hsts = 'Strict-Transport-Security' in headers_data
    hsts_val = headers_data.get('Strict-Transport-Security', '')
    hsts_long = 'max-age' in hsts_val and any(
        int(v) >= 15552000 for v in re.findall(r'max-age=(\d+)', hsts_val)
    ) if hsts_val else False
    _add_check(results, 'HSTS (Strict-Transport-Security)',
               'pass' if hsts and hsts_long else ('warn' if hsts else 'fail'), 'high',
               hsts_val if hsts else 'Header absent.')
    if not hsts:
        results['score'] -= 15
        _add_ticket_with_remediation(
            results,
            'HSTS manquant',
            'Sans HSTS, les connexions HTTP peuvent etre forcees par un attaquant (SSL stripping).',
            'high',
            'Ajouter le header Strict-Transport-Security dans la configuration du serveur.\n'
            'Nginx : add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
            'Apache : Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"\n'
            'Valeur recommandee : max-age=31536000 (1 an)'
        )
    elif not hsts_long:
        results['score'] -= 5
        _add_ticket_with_remediation(
            results,
            'HSTS max-age trop court',
            f'HSTS present mais max-age inferieur a 6 mois. Valeur recommandee : max-age=31536000.',
            'medium',
            'Augmenter la valeur de max-age a 31536000 (1 an) dans le header HSTS.\n'
            'Nginx : add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
        )

    xfo = 'X-Frame-Options' in headers_data
    _add_check(results, 'X-Frame-Options (anti-clickjacking)',
               'pass' if xfo else 'fail', 'medium',
               headers_data.get('X-Frame-Options', 'Header absent. Ajoute: X-Frame-Options: DENY'))
    if not xfo:
        _apply_grouped_penalty(results, 'content_injection_clickjacking', 'xfo', 10)
        _add_ticket_with_remediation(
            results,
            'X-Frame-Options manquant',
            'Le site peut etre integre dans une iframe malveillante (clickjacking).',
            'medium',
            'Ajouter le header X-Frame-Options.\n'
            'Nginx : add_header X-Frame-Options "DENY" always;\n'
            'Apache : Header always set X-Frame-Options "DENY"'
        )

    xcto = headers_data.get('X-Content-Type-Options', '').lower() == 'nosniff'
    _add_check(results, 'X-Content-Type-Options',
               'pass' if xcto else 'fail', 'medium',
               headers_data.get('X-Content-Type-Options',
                                'Header absent. Ajoute: X-Content-Type-Options: nosniff'))
    if not xcto:
        _apply_grouped_penalty(results, 'content_injection_clickjacking', 'xcto', 8)
        _add_ticket_with_remediation(
            results,
            'X-Content-Type-Options manquant',
            'Les navigateurs peuvent mal interpreter le type de fichiers servis.',
            'medium',
            'Ajouter le header X-Content-Type-Options.\n'
            'Nginx : add_header X-Content-Type-Options "nosniff" always;\n'
            'Apache : Header always set X-Content-Type-Options "nosniff"'
        )

    csp = 'Content-Security-Policy' in headers_data
    csp_val = headers_data.get('Content-Security-Policy', '')
    csp_unsafe = 'unsafe-inline' in csp_val or 'unsafe-eval' in csp_val
    _add_check(results, 'Content-Security-Policy (CSP)',
               'warn' if csp and csp_unsafe else ('pass' if csp else 'fail'), 'medium',
               csp_val[:200] if csp else 'Absent.')
    if not csp:
        _apply_grouped_penalty(results, 'content_injection_clickjacking', 'csp', 10)
        _add_ticket_with_remediation(
            results,
            'CSP absente',
            'Sans CSP, les mecanismes de defense contre certaines attaques XSS sont reduits.',
            'medium',
            'Ajouter une Content-Security-Policy.\n'
            'Exemple pour un site simple : \n'
            'Nginx : add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';" always;\n'
            'Voir https://content-security-policy.com/ pour des exemples avances.'
        )
    elif csp_unsafe:
        results['score'] -= 5
        _add_ticket_with_remediation(
            results,
            'CSP avec directives non securisees',
            'La CSP contient unsafe-inline ou unsafe-eval, ce qui reduit significativement la protection XSS.',
            'medium',
            'Remplacer unsafe-inline par des nonces ou des hashes.\n'
            'Exemple avec nonce : script-src \'nonce-${csp_nonce}\' \'strict-dynamic\';\n'
            'Ou utiliser des hashes pour les scripts inline : script-src \'sha256-xxxxx\''
        )

    rp = 'Referrer-Policy' in headers_data
    _add_check(results, 'Referrer-Policy',
               'pass' if rp else 'warn', 'low',
               headers_data.get('Referrer-Policy',
                                'Absent. Recommande : strict-origin-when-cross-origin'))
    if not rp:
        results['score'] -= 5
        _add_ticket_with_remediation(
            results,
            'Referrer-Policy manquant',
            'Referrer-Policy controle les informations de referer envoyees.',
            'low',
            'Ajouter le header Referrer-Policy.\n'
            'Nginx : add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n'
            'Apache : Header always set Referrer-Policy "strict-origin-when-cross-origin"'
        )

    pp = 'Permissions-Policy' in headers_data
    _add_check(results, '[OWASP] Permissions-Policy',
               'pass' if pp else 'warn', 'low',
               headers_data.get('Permissions-Policy',
                                'Absent. Bonne pratique navigateur recommandee.'))
    if not pp:
        _apply_grouped_penalty(results, 'content_injection_clickjacking', 'permissions_policy', 3)
        _add_ticket_with_remediation(
            results,
            '[OWASP] Permissions-Policy absent',
            'Limiter les fonctionnalites navigateur (camera, micro, geoloc...) reduit la surface d\'attaque.',
            'low',
            'Ajouter le header Permissions-Policy.\n'
            'Nginx : add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;\n'
            'Apache : Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"'
        )

    server = headers_data.get('Server', '')
    x_powered = headers_data.get('X-Powered-By', '')
    server_leak = bool(server) and any(
        v in server.lower() for v in ['apache', 'nginx', 'iis', 'php', 'express', 'tomcat']
    )
    powered_leak = bool(x_powered)
    _add_check(results, 'Fuite version serveur (Server / X-Powered-By)',
               'warn' if (server_leak or powered_leak) else 'pass', 'low',
               f'Server: {server} | X-Powered-By: {x_powered}' if (server_leak or powered_leak)
               else 'Headers serveur masques. Bonne pratique.')
    if server_leak or powered_leak:
        results['score'] -= 5
        _add_ticket_with_remediation(
            results,
            'Version serveur/technologie exposee',
            f'Les headers exposent la technologie : Server="{server}", X-Powered-By="{x_powered}". '
            'Aide les attaquants a cibler des CVE connues.',
            'low',
            'Masquer les headers serveur.\n'
            'Nginx : server_tokens off; plus proxy_hide_header X-Powered-By;\n'
            'Apache : ServerTokens Prod et Header unset X-Powered-By\n'
            'PHP : expose_php = Off dans php.ini'
        )

    cors = headers_data.get('Access-Control-Allow-Origin', '')
    cors_wildcard = cors == '*'
    _add_check(results, '[OWASP] CORS — controle des origines',
               'fail' if cors_wildcard else 'pass', 'high',
               'CORS en wildcard (*) : toute origine peut interroger cette API.' if cors_wildcard
               else f'CORS configure : {cors if cors else "header absent (OK si API privee)."}')
    if cors_wildcard:
        results['score'] -= 15
        _add_ticket_with_remediation(
            results,
            '[OWASP] CORS wildcard (*)',
            'L\'API accepte des requetes de n\'importe quelle origine, ce qui peut faciliter '
            'l\'exfiltration de donnees depuis un site tiers malveillant.',
            'high',
            'Configurer CORS avec une origine specifique au lieu de "*".\n'
            'Nginx : add_header Access-Control-Allow-Origin "https://domaine-autorise.com" always;\n'
            'Ou utiliser un middleware pour valider dynamiquement les origines.'
        )

    cookie = headers_data.get('Set-Cookie', '')
    if cookie:
        cookie_secure = 'secure' in cookie.lower()
        cookie_httponly = 'httponly' in cookie.lower()
        cookie_samesite_match = re.search(r'samesite=(\w+)', cookie, re.IGNORECASE)
        cookie_samesite = bool(cookie_samesite_match)
        samesite_value = cookie_samesite_match.group(1) if cookie_samesite_match else None
        samesite_weak = cookie_samesite and samesite_value.lower() == 'none'
        cookie_ok = cookie_secure and cookie_httponly and cookie_samesite and not samesite_weak
        _add_check(results, '[RGPD] Securite des cookies',
                   'pass' if cookie_ok else 'fail', 'high',
                   f'Secure={cookie_secure}, HttpOnly={cookie_httponly}, SameSite={samesite_value or "absent"}')
        if not cookie_ok:
            results['score'] -= 10
            missing = []
            if not cookie_secure:   missing.append('Secure')
            if not cookie_httponly: missing.append('HttpOnly')
            if not cookie_samesite: missing.append('SameSite')
            elif samesite_weak:     missing.append('SameSite=None (faible, prefere Lax/Strict)')
            _add_ticket_with_remediation(
                results,
                '[RGPD] Cookie avec attributs de securite manquants',
                f'Attributs manquants ou faibles : {", ".join(missing)}. '
                'SameSite absent expose a des attaques CSRF.',
                'high',
                'Ajouter les attributs de securite aux cookies.\n'
                'Flask : app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")\n'
                'Django : SESSION_COOKIE_SECURE = True, SESSION_COOKIE_HTTPONLY = True, SESSION_COOKIE_SAMESITE = "Lax"'
            )
    else:
        _add_check(results, '[RGPD] Securite des cookies',
                   'pass', 'low', 'Aucun cookie de session detecte.')

    coop = headers_data.get('Cross-Origin-Opener-Policy', '')
    corp = headers_data.get('Cross-Origin-Resource-Policy', '')
    coop_ok = coop.lower() in ('same-origin', 'same-origin-allow-popups')
    corp_ok = corp.lower() in ('same-origin', 'same-site')
    _add_check(results, '[OWASP] Cross-Origin-Opener-Policy',
               'pass' if coop_ok else 'warn', 'medium',
               coop if coop else 'Header absent. Recommande : Cross-Origin-Opener-Policy: same-origin')
    _add_check(results, '[OWASP] Cross-Origin-Resource-Policy',
               'pass' if corp_ok else 'warn', 'medium',
               corp if corp else 'Header absent. Recommande : Cross-Origin-Resource-Policy: same-origin')
    if not coop_ok:
        _apply_grouped_penalty(results, 'content_injection_clickjacking', 'coop', 4)
        _add_ticket_with_remediation(
            results,
            '[OWASP] Cross-Origin-Opener-Policy absent',
            'Header absent. Permet des attaques de type cross-origin.',
            'medium',
            'Ajouter le header Cross-Origin-Opener-Policy.\n'
            'Nginx : add_header Cross-Origin-Opener-Policy "same-origin" always;\n'
            'Apache : Header always set Cross-Origin-Opener-Policy "same-origin"'
        )
    if not corp_ok:
        _apply_grouped_penalty(results, 'content_injection_clickjacking', 'corp', 4)
        _add_ticket_with_remediation(
            results,
            '[OWASP] Cross-Origin-Resource-Policy absent',
            'Header absent. Permet des attaques de type cross-origin.',
            'medium',
            'Ajouter le header Cross-Origin-Resource-Policy.\n'
            'Nginx : add_header Cross-Origin-Resource-Policy "same-origin" always;\n'
            'Apache : Header always set Cross-Origin-Resource-Policy "same-origin"'
        )

    _finalize_grouped_penalties(results)

    # ============================================================
    # CATEGORIE 2 : ANALYSE SSL/TLS (BASE + AVANCEE)
    # ============================================================

    if https_ok:
        # Analyse SSL/TLS de base
        ssl_results = _check_ssl_tls(hostname)
        results['checks'].extend(ssl_results['checks'])
        results['tickets'].extend(ssl_results['tickets'])
        results['score'] -= ssl_results['score_penalty']
        
        # Analyse TLS avancee (sslyze)
        ssl_advanced_results = _check_ssl_tls_advanced(hostname)
        results['checks'].extend(ssl_advanced_results['checks'])
        results['tickets'].extend(ssl_advanced_results['tickets'])
        results['score'] -= ssl_advanced_results['score_penalty']

    # ============================================================
    # CATEGORIE 3 : FINGERPRINTING TECHNOLOGIQUE
    # ============================================================

    tech_results = _check_technologies(headers_data, html_content, url)
    results['checks'].extend(tech_results['checks'])
    results['tickets'].extend(tech_results['tickets'])
    results['score'] -= tech_results['score_penalty']

    # ============================================================
    # CATEGORIE 4 : FICHIERS SENSIBLES EXPOSES
    # ============================================================

    sensitive_results = _check_sensitive_files(base)
    results['checks'].extend(sensitive_results['checks'])
    results['tickets'].extend(sensitive_results['tickets'])
    results['score'] -= sensitive_results['score_penalty']

    # ============================================================
    # CATEGORIE 4bis : RESSOURCES PUBLIQUES
    # ============================================================

    public_results = _check_public_resources(base)
    results['checks'].extend(public_results['checks'])
    results['tickets'].extend(public_results['tickets'])

    # ============================================================
    # CATEGORIE 5 : ENDPOINTS API SENSIBLES
    # ============================================================

    api_results = _check_sensitive_endpoints(base)
    results['checks'].extend(api_results['checks'])
    results['tickets'].extend(api_results['tickets'])
    results['score'] -= api_results['score_penalty']

    # ============================================================
    # CATEGORIE 6 : FUITES D'INFORMATION DANS LE HTML
    # ============================================================

    if html_content:
        leak_results = _check_html_leaks(html_content, url)
        results['checks'].extend(leak_results['checks'])
        results['tickets'].extend(leak_results['tickets'])
        results['score'] -= leak_results['score_penalty']

    # ============================================================
    # SUBRESOURCE INTEGRITY (SRI)
    # ============================================================

    if html_content:
        sri_results = _check_sri(html_content, base)
        results['checks'].extend(sri_results['checks'])
        results['tickets'].extend(sri_results['tickets'])
        results['score'] -= sri_results['score_penalty']

    # ============================================================
    # HSTS PRELOAD
    # ============================================================

    hsts_preload_results = _check_hsts_preload(hostname)
    results['checks'].extend(hsts_preload_results['checks'])
    results['tickets'].extend(hsts_preload_results['tickets'])

    # ============================================================
    # CATEGORIE 7 : REDIRECTIONS
    # ============================================================

    redirect_results = _check_redirections(url, parsed)
    results['checks'].extend(redirect_results['checks'])
    results['tickets'].extend(redirect_results['tickets'])
    results['score'] -= redirect_results['score_penalty']

    # ============================================================
    # CATEGORIE 8 : METHODE TRACE (XST)
    # ============================================================

    trace_results = _check_trace_method(base)
    results['checks'].extend(trace_results['checks'])
    results['tickets'].extend(trace_results['tickets'])
    results['score'] -= trace_results['score_penalty']

    # ============================================================
    # CATEGORIE 9 : DIRECTORY LISTING
    # ============================================================

    listing_results = _check_directory_listing(base, html_content)
    results['checks'].extend(listing_results['checks'])
    results['tickets'].extend(listing_results['tickets'])
    results['score'] -= listing_results['score_penalty']

    # ============================================================
    # CATEGORIE 10 : DETECTION CDN / PROXY
    # ============================================================

    cdn_results = _detect_cdn(headers_data)
    results['checks'].extend(cdn_results['checks'])

    # ============================================================
    # CATEGORIE 11 : COHERENCE MULTI-PAGES
    # ============================================================

    consistency_results = _check_multi_page_consistency(base, headers_data)
    results['checks'].extend(consistency_results['checks'])
    results['tickets'].extend(consistency_results['tickets'])
    results['score'] -= consistency_results['score_penalty']

    # ============================================================
    # CATEGORIE 12 : SECURITE EMAIL (SPF / DKIM / DMARC) - AVANCE
    # ============================================================

    email_results = _check_email_security_detailed(hostname)
    results['checks'].extend(email_results['checks'])
    results['tickets'].extend(email_results['tickets'])
    results['score'] -= email_results['score_penalty']

    # ============================================================
    # CATEGORIE 13 : METHODES HTTP DANGEREUSES
    # ============================================================

    methods_results = _check_dangerous_methods(base)
    results['checks'].extend(methods_results['checks'])
    results['tickets'].extend(methods_results['tickets'])
    results['score'] -= methods_results['score_penalty']

    # ============================================================
    # CATEGORIE 14 : TESTS OWASP ACTIFS
    # ============================================================

    if active_scan:
        active_results = _check_owasp_active(url, parsed, html_content, headers_data)
        results['checks'].extend(active_results['checks'])
        results['tickets'].extend(active_results['tickets'])
        results['score'] -= active_results['score_penalty']
    else:
        results['checks'].append({
            'name': '[OWASP-ACTIF] SQLi / XSS / CSRF',
            'status': 'warn',
            'severity': 'low',
            'detail': 'Tests actifs non executes — necessitent une autorisation explicite '
                      'sur ce projet (case a cocher "autorise a tester activement" absente ou non cochee).'
        })

    # ============================================================
    # CATEGORIE 15 : INDICE DE CONFIANCE DU SCAN
    # ============================================================

    confidence_results = _compute_scan_confidence(results['checks'], active_scan)
    results['checks'].append(confidence_results)
    results['scan_confidence'] = confidence_results['confidence_percent']

    # ============================================================
    # CATEGORIE 16 : SOUS-DOMAINES (DNS ENUMERATION)
    # ============================================================

    subdomain_results = _check_subdomains(hostname)
    results['checks'].extend(subdomain_results['checks'])
    results['tickets'].extend(subdomain_results['tickets'])
    results['score'] -= subdomain_results['score_penalty']

    # ============================================================
    # CATEGORIE 17 : PORTS OUVERTS
    # ============================================================

    ports_results = _check_open_ports(hostname)
    results['checks'].extend(ports_results['checks'])
    results['tickets'].extend(ports_results['tickets'])
    results['score'] -= ports_results['score_penalty']

    confirmed_tickets = [t for t in results['tickets'] if t.get('evidence') == EVIDENCE_CONFIRMED]
    results['confirmed_vulnerabilities_count'] = len(confirmed_tickets)
    results['confirmed_vulnerabilities'] = [
        {'title': t['title'], 'severity': t['severity']} for t in confirmed_tickets
    ]

    results['score'] = max(0, min(100, results['score']))
    results['nis2_details'] = _compute_nis2(results['checks'])
    results['nis2_score'] = _nis2_score(results['nis2_details'])
    results.pop('_grouped_penalties', None)

    return results


# ============================================================
# INDICE DE CONFIANCE DU SCAN
# ============================================================

def _compute_scan_confidence(checks, active_scan):
    total = len(checks)
    errors = sum(1 for c in checks if c['status'] == 'error')
    not_testable = sum(1 for c in checks if 'non testable' in c.get('detail', '').lower()
                        or 'impossible' in c.get('detail', '').lower())

    reliable = total - errors - not_testable
    confidence_percent = round((reliable / total) * 100) if total else 0

    detail = (
        f'{reliable}/{total} controles executes avec succes. '
        f'{errors} erreur(s) technique(s), {not_testable} controle(s) non testable(s). '
        + ('Tests actifs OWASP (SQLi/XSS/CSRF) executes.' if active_scan
           else 'Tests actifs OWASP non executes (necessite autorisation explicite).')
    )

    return {
        'name': '[Fiabilite] Indice de confiance du scan',
        'status': 'pass' if confidence_percent >= 80 else 'warn',
        'severity': 'low',
        'detail': detail,
        'confidence_percent': confidence_percent
    }


# ============================================================
# ANALYSE SSL/TLS DE BASE
# ============================================================

def _check_ssl_tls(hostname):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cert = ssock.getpeercert()

        old_tls = tls_version in ('TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3')
        out['checks'].append({
            'name': '[TLS] Version du protocole',
            'status': 'fail' if old_tls else 'pass',
            'severity': 'critical' if old_tls else 'low',
            'detail': f'Version TLS utilisee : {tls_version}. '
                      + ('OBSOLETE et vulnerable — TLS 1.0/1.1 sont deprecies (RFC 8996).'
                         if old_tls else 'TLS 1.2+ : conforme.')
        })
        if old_tls:
            out['score_penalty'] += 20
            out['tickets'].append({
                'title': f'Version TLS obsolete ({tls_version})',
                'description': f'Le serveur utilise {tls_version} qui est deprecie et vulnerable.',
                'severity': 'critical',
                'evidence': EVIDENCE_CONFIRMED,
                'remediation': 'Migrer vers TLS 1.2 minimum, TLS 1.3 recommande.\n'
                               'Nginx : ssl_protocols TLSv1.2 TLSv1.3;\n'
                               'Apache : SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 +TLSv1.2 +TLSv1.3'
            })

        if cert:
            expire_str = cert.get('notAfter', '')
            if expire_str:
                expire_dt = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expire_dt - datetime.utcnow()).days
                if days_left < 0:
                    status, sev = 'fail', 'critical'
                    detail = f'Certificat EXPIRE depuis {abs(days_left)} jours !'
                    out['score_penalty'] += 30
                    out['tickets'].append({
                        'title': 'Certificat SSL expire',
                        'description': detail + ' Les navigateurs afficheront une erreur de securite.',
                        'severity': 'critical',
                        'evidence': EVIDENCE_CONFIRMED,
                        'remediation': 'Renouveler immediatement le certificat SSL.\n'
                                       'Let\'s Encrypt : certbot renew\n'
                                       'Verifier que le renouvellement automatique est configure.'
                    })
                elif days_left < 30:
                    status, sev = 'warn', 'high'
                    detail = f'Certificat expire dans {days_left} jours. Renouvellement urgent.'
                    out['score_penalty'] += 15
                    out['tickets'].append({
                        'title': f'Certificat SSL expire dans {days_left} jours',
                        'description': 'Renouveler le certificat avant expiration.',
                        'severity': 'high',
                        'evidence': EVIDENCE_CONFIRMED,
                        'remediation': f'Renouveler le certificat dans les {days_left} jours.\n'
                                       'Let\'s Encrypt : certbot renew\n'
                                       'Verifier que le renouvellement automatique est configure.'
                    })
                elif days_left < 90:
                    status, sev = 'warn', 'medium'
                    detail = f'Certificat expire dans {days_left} jours. Planifier le renouvellement.'
                    out['score_penalty'] += 5
                else:
                    status, sev = 'pass', 'low'
                    detail = f'Certificat valide encore {days_left} jours.'

                out['checks'].append({
                    'name': '[TLS] Expiration du certificat',
                    'status': status,
                    'severity': sev,
                    'detail': detail
                })

            san = cert.get('subjectAltName', [])
            domains = [v for t, v in san if t == 'DNS']
            out['checks'].append({
                'name': '[TLS] Subject Alternative Names',
                'status': 'pass' if domains else 'warn',
                'severity': 'low',
                'detail': f'Domaines couverts : {", ".join(domains[:5])}' if domains
                          else 'Aucun SAN detecte — verifier la configuration.'
            })

    except ssl.SSLError as e:
        out['checks'].append({
            'name': '[TLS] Analyse SSL/TLS',
            'status': 'fail',
            'severity': 'critical',
            'detail': f'Erreur SSL : {str(e)[:150]}'
        })
        out['score_penalty'] += 20
    except (socket.timeout, ConnectionRefusedError, OSError):
        out['checks'].append({
            'name': '[TLS] Analyse SSL/TLS',
            'status': 'warn',
            'severity': 'medium',
            'detail': 'Impossible d\'analyser le certificat SSL (connexion refusee ou timeout).'
        })

    return out


# ============================================================
# ANALYSE SSL/TLS AVANCEE (sslyze)
# ============================================================

def _check_ssl_tls_advanced(hostname):
    """
    Analyse TLS avancee avec sslyze :
    - Detection Heartbleed, ROBOT
    - Ciphers faibles
    - Versions TLS supportees
    """
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}

    try:
        from sslyze import Scanner
        from sslyze.server_setting import ServerNetworkLocation
        
        server_location = ServerNetworkLocation(hostname=hostname, port=443)
        scanner = Scanner()
        # Essayer différentes méthodes selon la version de sslyze
        try:
            scan_result = scanner.scan(server_location)
        except AttributeError:
            try:
                scan_result = scanner.scan_sync(server_location)
            except AttributeError:
                raise Exception("Impossible d'utiliser sslyze (API incompatibles).")
        
        vulnerabilities = []
        tls_versions = []
        
        # Verifier Heartbleed
        if hasattr(scan_result, 'heartbleed') and scan_result.heartbleed.is_vulnerable:
            vulnerabilities.append('Vulnerable a Heartbleed (CVE-2014-0160)')
        
        # Verifier ROBOT
        if hasattr(scan_result, 'robot') and scan_result.robot.is_vulnerable:
            vulnerabilities.append('Vulnerable a ROBOT (CVE-2017-17382)')
        
        # Verifier les ciphers faibles
        if hasattr(scan_result, 'sslv2') and scan_result.sslv2.is_supported:
            vulnerabilities.append('SSLv2 supporte (deprecie)')
        if hasattr(scan_result, 'sslv3') and scan_result.sslv3.is_supported:
            vulnerabilities.append('SSLv3 supporte (deprecie)')
        if hasattr(scan_result, 'tlsv1') and scan_result.tlsv1.is_supported:
            vulnerabilities.append('TLS 1.0 supporte (deprecie)')
        if hasattr(scan_result, 'tlsv1_1') and scan_result.tlsv1_1.is_supported:
            vulnerabilities.append('TLS 1.1 supporte (deprecie)')
        
        # Verifier TLS 1.3
        if hasattr(scan_result, 'tlsv1_3') and scan_result.tlsv1_3.is_supported:
            tls_versions.append('TLS 1.3')
        if hasattr(scan_result, 'tlsv1_2') and scan_result.tlsv1_2.is_supported:
            tls_versions.append('TLS 1.2')
        
        if vulnerabilities:
            out['score_penalty'] += 20
            out['tickets'].append({
                'title': 'Vulnerabilites TLS detectees',
                'description': f'Problemes detectes : {", ".join(vulnerabilities)}',
                'severity': 'critical',
                'evidence': EVIDENCE_CONFIRMED,
                'remediation': _get_tls_remediation(vulnerabilities)
            })
        
        if 'TLS 1.3' not in tls_versions:
            out['score_penalty'] += 10
            out['tickets'].append({
                'title': 'TLS 1.3 non supporte',
                'description': 'Le serveur ne supporte pas TLS 1.3, version la plus securisee.',
                'severity': 'medium',
                'evidence': EVIDENCE_MISSING_CONTROL,
                'remediation': 'Mettre a jour la configuration du serveur pour activer TLS 1.3.\n'
                               'Nginx : ssl_protocols TLSv1.2 TLSv1.3;\n'
                               'Apache : SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 +TLSv1.2 +TLSv1.3'
            })
        
        out['checks'].append({
            'name': '[TLS] Analyse avancee (sslyze)',
            'status': 'fail' if vulnerabilities else 'pass',
            'severity': 'critical' if vulnerabilities else 'low',
            'detail': f'Versions TLS : {", ".join(tls_versions) if tls_versions else "Aucune"}'
                      + (f' | Vulnerabilites : {", ".join(vulnerabilities)}' if vulnerabilities else ' | OK')
        })
        
    except ImportError:
        out['checks'].append({
            'name': '[TLS] Analyse avancee (sslyze)',
            'status': 'warn',
            'severity': 'low',
            'detail': 'sslyze non installe. Installez avec : pip install sslyze'
        })
    except Exception as e:
        out['checks'].append({
            'name': '[TLS] Analyse avancee (sslyze)',
            'status': 'warn',
            'severity': 'low',
            'detail': f'Erreur sslyze : {str(e)[:100]}'
        })
    
    return out


def _get_tls_remediation(vulnerabilities):
    """Retourne des recommandations pour les vulnerabilites TLS."""
    recommendations = []
    for vuln in vulnerabilities:
        if 'Heartbleed' in vuln:
            recommendations.append('Heartbleed : Mettre a jour OpenSSL (version 1.0.1g ou superieure) et regenerer les cles.')
        elif 'ROBOT' in vuln:
            recommendations.append('ROBOT : Desactiver le chiffrement RSA avec PKCS#1 v1.5. Utiliser ECDHE ou des ciphers avec RSA-OAEP.')
        elif 'SSLv2' in vuln:
            recommendations.append('SSLv2 : Desactiver SSLv2 completement. Nginx : ssl_protocols TLSv1.2 TLSv1.3;')
        elif 'SSLv3' in vuln:
            recommendations.append('SSLv3 : Desactiver SSLv3 completement. Nginx : ssl_protocols TLSv1.2 TLSv1.3;')
        elif 'TLS 1.0' in vuln:
            recommendations.append('TLS 1.0 : Desactiver TLS 1.0. Nginx : ssl_protocols TLSv1.2 TLSv1.3;')
        elif 'TLS 1.1' in vuln:
            recommendations.append('TLS 1.1 : Desactiver TLS 1.1. Nginx : ssl_protocols TLSv1.2 TLSv1.3;')
    return '\n'.join(recommendations)


# ============================================================
# FINGERPRINTING TECHNOLOGIQUE
# ============================================================

TECH_SIGNATURES = {
    'WordPress': {
        'html': ['/wp-content/', '/wp-includes/', 'wp-json'],
        'headers': {'X-Powered-By': ['WordPress']},
        'severity': 'low',
        'cve_note': 'CMS WordPress detecte (signature HTML/headers, version non verifiee). '
                    'Ceci est une information technologique, PAS une vulnerabilite confirmee. '
                    'Si la version ou les plugins sont obsoletes, ce CMS est une cible frequente '
                    '(CVE publiees chaque annee) — verifier manuellement la version installee '
                    'avant toute conclusion.'
    },
    'Drupal': {
        'html': ['/sites/default/', 'Drupal.settings', 'drupal.js'],
        'headers': {'X-Generator': ['Drupal']},
        'severity': 'low',
        'cve_note': 'CMS Drupal detecte (signature HTML/headers, version non verifiee). '
                    'Ceci est une information technologique, PAS une vulnerabilite confirmee : '
                    'la detection indique seulement la presence de la technologie. Les versions '
                    'anciennes non corrigees peuvent etre exposees a des CVE connues (ex: '
                    'Drupalgeddon, CVE-2018-7600), mais rien ici ne confirme que ce site tourne '
                    'sur une version vulnerable — verifier manuellement avant de conclure a une faille.'
    },
    'jQuery obsolete': {
        'html': ['jquery-1.', 'jquery-2.', 'jquery/1.', 'jquery/2.'],
        'headers': {},
        'severity': 'medium',
        'cve_note': 'Signature de version jQuery ancienne detectee dans une URL de script '
                    '(jQuery < 3.0). Ces versions contiennent des vulnerabilites XSS connues '
                    '(CVE-2019-11358, CVE-2020-11022) — a verifier manuellement (le numero de '
                    'version exact n\'est pas confirme par cette seule signature).'
    },
    'PHP expose': {
        'html': [],
        'headers': {'X-Powered-By': ['PHP/5', 'PHP/7.0', 'PHP/7.1', 'PHP/7.2']},
        'severity': 'medium',
        'cve_note': 'Le header X-Powered-By annonce une version PHP obsolete (< 8.0, plus '
                    'supportee). Ceci est une information declarative du serveur (peut etre '
                    'usurpee ou obsolete elle-meme) — a confirmer avant conclusion.'
    },
    'Apache': {
        'html': [],
        'headers': {'Server': ['Apache/2.2', 'Apache/2.4.0', 'Apache/2.4.1', 'Apache/2.4.2',
                               'Apache/2.4.3', 'Apache/2.4.4', 'Apache/2.4.5']},
        'severity': 'low',
        'cve_note': 'Version Apache ancienne annoncee par le header Server (information '
                    'declarative, potentiellement obsolete ou masquee). A verifier manuellement.'
    },
    'nginx': {
        'html': [],
        'headers': {'Server': ['nginx/1.18', 'nginx/1.20', 'nginx/1.22', 'nginx/1.23', 'nginx/1.24']},
        'severity': 'low',
        'cve_note': 'Version nginx ancienne detectee par le header Server. Certaines versions '
                    'ont des CVE connues (ex: CVE-2021-23017).'
    },
    'Swagger/OpenAPI expose': {
        'html': ['swagger-ui', 'openapi', 'api-docs'],
        'headers': {},
        'severity': 'medium',
        'cve_note': 'Documentation API (Swagger/OpenAPI) accessible publiquement. Peut exposer '
                    'la structure des endpoints a des attaquants — a evaluer selon la sensibilite '
                    'de l\'API concernee.'
    },
}

def _check_technologies(headers_data, html_content, url):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    detected = []

    for tech, sig in TECH_SIGNATURES.items():
        found = False
        for pattern in sig.get('html', []):
            if pattern.lower() in html_content.lower():
                found = True
                break
        if not found:
            for header, values in sig.get('headers', {}).items():
                header_val = headers_data.get(header, '')
                if any(v.lower() in header_val.lower() for v in values):
                    found = True
                    break

        if found:
            detected.append(tech)
            sev = sig['severity']
            out['checks'].append({
                'name': f'[Tech] {tech} detecte (signature — non confirme)',
                'status': 'warn' if sev in ('medium', 'high') else 'pass',
                'severity': sev,
                'detail': sig['cve_note']
            })
            penalty = {'high': 8, 'medium': 4, 'low': 2}.get(sev, 3)
            out['score_penalty'] += penalty
            
            # Ajouter les CVE via API NVD pour cette technologie
            cve_results = _check_cve_for_technology(tech)
            out['checks'].extend(cve_results['checks'])
            out['tickets'].extend(cve_results['tickets'])
            out['score_penalty'] += cve_results['score_penalty']
            
            # Fallback local si API indisponible
            if not cve_results.get('checks') or cve_results['checks'][0]['status'] == 'warn':
                cve_list = TECH_CVE.get(tech, [])
                if cve_list:
                    cve_descriptions = ', '.join([f"{c['id']} ({c['severity']})" for c in cve_list[:3]])
                    out['tickets'].append({
                        'title': f'[Tech] {tech} detecte — CVE connues possibles',
                        'description': f'{tech} detecte. CVE potentiellement applicables : {cve_descriptions}. '
                                       f'A verifier manuellement la version exacte installee.',
                        'severity': 'high' if any(c['severity'] == 'critical' for c in cve_list) else 'medium',
                        'evidence': EVIDENCE_SIGNATURE,
                        'remediation': f'Mettre a jour {tech} vers la derniere version stable.\n'
                                       f'Consulter les bulletins de securite officiels pour corriger les CVE mentionnees.'
                    })

    if not detected:
        out['checks'].append({
            'name': '[Tech] Fingerprinting technologique',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Aucune technologie obsolete ou a risque detectee.'
        })

    return out


# ============================================================
# DETECTION DE CVE VIA API NVD
# ============================================================

def _check_cve_for_technology(tech_name, tech_version=None):
    """
    Vérifie si une technologie a des CVE connues via l'API NVD.
    """
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    
    if not tech_name:
        return out
    
    try:
        # Requête vers l'API NVD
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech_name}"
        if tech_version:
            url += f" {tech_version}"
        
        response = requests.get(url, timeout=10, verify=True)  # ✅ validation SSL
        if response.status_code != 200:
            out['checks'].append({
                'name': f'[CVE] API NVD - {tech_name}',
                'status': 'warn',
                'severity': 'low',
                'detail': f'API NVD indisponible (code {response.status_code})'
            })
            return out
        
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        total_results = data.get('totalResults', 0)
        
        if total_results > 0:
            critical = 0
            high = 0
            medium = 0
            low = 0
            cve_list = []
            
            for vuln in vulnerabilities[:10]:
                cve_id = vuln.get('cve', {}).get('id', '')
                metrics = vuln.get('cve', {}).get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', [])
                severity = 'unknown'
                description = ''
                
                if cvss_v3 and cvss_v3[0].get('cvssData', {}).get('baseSeverity'):
                    severity = cvss_v3[0]['cvssData']['baseSeverity']
                    if severity == 'CRITICAL':
                        critical += 1
                    elif severity == 'HIGH':
                        high += 1
                    elif severity == 'MEDIUM':
                        medium += 1
                    else:
                        low += 1
                
                descriptions = vuln.get('cve', {}).get('descriptions', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')[:100]
                        break
                
                cve_list.append({
                    'id': cve_id,
                    'severity': severity,
                    'description': description
                })
            
            out['checks'].append({
                'name': f'[CVE] Vulnérabilités connues - {tech_name}',
                'status': 'fail' if critical > 0 or high > 0 else 'warn',
                'severity': 'critical' if critical > 0 else 'high' if high > 0 else 'medium',
                'detail': f"{total_results} CVE trouvées (Critique: {critical}, Haute: {high}, Moyenne: {medium}, Faible: {low})"
            })
            
            if critical > 0 or high > 0:
                cve_details = ', '.join([f"{c['id']} ({c['severity']})" for c in cve_list[:3] if c['severity'] in ('CRITICAL', 'HIGH')])
                out['score_penalty'] += 15
                out['tickets'].append({
                    'title': f'[CVE] Vulnérabilités critiques sur {tech_name}',
                    'description': f"{critical} vulnérabilité(s) critique(s) et {high} haute(s) trouvées sur {tech_name}.\n"
                                   f"CVE identifiées : {cve_details}\n"
                                   f"Mettez à jour {tech_name} vers la dernière version stable.",
                    'severity': 'critical' if critical > 0 else 'high',
                    'evidence': EVIDENCE_CONFIRMED,
                    'remediation': f'Mettre à jour {tech_name} vers la dernière version disponible.\n'
                                   f'Consulter les bulletins de sécurité :\n'
                                   f'https://nvd.nist.gov/vuln/search?keyword={tech_name}\n'
                                   f'Pour WordPress : mettre à jour le core, les thèmes et les plugins.\n'
                                   f'Pour les serveurs web : appliquer les patches de sécurité.'
                })
        else:
            out['checks'].append({
                'name': f'[CVE] Vulnérabilités connues - {tech_name}',
                'status': 'pass',
                'severity': 'low',
                'detail': f'Aucune CVE connue trouvée pour {tech_name}.'
            })
            
    except Exception as e:
        out['checks'].append({
            'name': f'[CVE] API NVD - {tech_name}',
            'status': 'warn',
            'severity': 'low',
            'detail': f'Erreur API NVD : {str(e)[:100]}'
        })
    
    return out


# ============================================================
# FICHIERS SENSIBLES
# ============================================================

CONTENT_SIGNATURES = {
    '/.env': [r'[A-Z_]{2,}\s*=\s*.+', r'SECRET_KEY', r'DATABASE_URL', r'API_KEY', r'DB_PASSWORD', r'MAIL_PASSWORD'],
    '/.git/config': [r'\[core\]', r'repositoryformatversion', r'\[remote'],
    '/wp-config.php': [r"define\s*\(\s*['\"]DB_", r"<\?php"],
    '/config.php': [r"<\?php", r"(db|database|password)['\"]?\s*[:=]"],
    '/phpinfo.php': [r'phpinfo\(\)', r'PHP Version', r'<title>phpinfo'],
    '/backup.sql': [r'CREATE TABLE', r'INSERT INTO', r'-- MySQL dump', r'-- PostgreSQL database dump'],
    '/backup.zip': [r'PK\x03\x04'],
    '/.htaccess': [r'RewriteEngine', r'RewriteRule', r'<IfModule'],
    '/server-status': [r'Apache Server Status', r'Current Time:'],
    '/elmah.axd': [r'ELMAH', r'Error Log for'],
    '/trace.axd': [r'Application Trace', r'Request Details'],
    '/actuator': [r'"_links"', r'"health"'],
    '/actuator/env': [r'"propertySources"', r'"activeProfiles"'],
    '/swagger.json': [r'"swagger"', r'"openapi"', r'"paths"'],
    '/api/swagger.json': [r'"swagger"', r'"openapi"', r'"paths"'],
    '/v2/api-docs': [r'"swagger"', r'"paths"'],
    '/graphql': [r'"errors"', r'"data"', r'GraphQL'],
    '/__debug__/': [r'debug', r'toolbar'],
    '/adminer.php': [r'Adminer', r'<title>Adminer'],
    '/phpmyadmin/': [r'phpMyAdmin', r'<title>phpMyAdmin'],
}

SENSITIVE_FILES = [
    ('/.env',               'critical', 'Fichier .env expose — peut contenir des mots de passe, cles API, secrets de base de donnees.'),
    ('/.git/config',        'critical', 'Repository Git expose publiquement — acces au code source complet possible.'),
    ('/wp-config.php',      'critical', 'Fichier de configuration WordPress expose — contient les credentials de base de donnees.'),
    ('/config.php',         'critical', 'Fichier de configuration PHP expose — peut contenir des credentials.'),
    ('/phpinfo.php',        'high',     'phpinfo() expose — revele la configuration complete du serveur PHP, version, modules.'),
    ('/backup.zip',         'high',     'Archive de backup exposee — peut contenir le code source et des donnees sensibles.'),
    ('/backup.sql',         'high',     'Dump SQL expose — peut contenir toute la base de donnees.'),
    ('/.htaccess',          'medium',   'Fichier .htaccess expose — revele la configuration Apache.'),
    ('/server-status',      'high',     'Apache server-status expose — revele les requetes en cours et la charge serveur.'),
    ('/elmah.axd',          'high',     'ELMAH (Error Log) expose — logs d\'erreurs .NET accessibles publiquement.'),
    ('/trace.axd',          'high',     'ASP.NET trace expose — informations de debug accessibles.'),
    ('/actuator',           'high',     'Spring Boot Actuator expose — endpoints de monitoring accessibles sans auth.'),
    ('/actuator/env',       'critical', 'Spring Boot /actuator/env expose — variables d\'environnement accessibles.'),
    ('/swagger.json',       'medium',   'Swagger JSON expose — documentation API complete accessible.'),
    ('/api/swagger.json',   'medium',   'Swagger JSON expose — documentation API complete accessible.'),
    ('/v2/api-docs',        'medium',   'Swagger API docs expose — endpoints et schemas accessibles.'),
    ('/graphql',            'medium',   'Endpoint GraphQL expose — peut permettre l\'introspection du schema complet.'),
    ('/__debug__/',         'high',     'Interface de debug exposee — informations systeme accessibles.'),
    ('/adminer.php',        'critical', 'Adminer (gestionnaire BDD) expose publiquement — acces a la base de donnees possible.'),
    ('/phpmyadmin/',        'high',     'phpMyAdmin expose — interface d\'administration BDD accessible.'),
]

PUBLIC_RESOURCES = [
    ('/robots.txt', ['Disallow', 'Allow', 'User-agent', 'Sitemap']),
    ('/sitemap.xml', ['<urlset', '<sitemapindex', '<?xml']),
]


def _content_matches_signature(path, text, content_type):
    patterns = CONTENT_SIGNATURES.get(path, [])
    if not patterns:
        return bool(content_type) and 'html' not in content_type.lower()
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _check_sensitive_files(base):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}

    is_catchall, catchall_ctype, catchall_len = _detect_catchall(base)

    exposed = []
    unconfirmed = []

    for path, severity, desc in SENSITIVE_FILES:
        try:
            r = requests.get(base + path, timeout=5, verify=True,
                             allow_redirects=False,
                             headers={'User-Agent': 'DevShield-Scanner/1.0'})
            if r.status_code != 200 or len(r.content) == 0:
                continue

            if is_catchall and _looks_like_catchall_response(r, catchall_ctype, catchall_len):
                continue

            content_type = r.headers.get('Content-Type', '')
            try:
                text = r.content[:5000].decode('utf-8', errors='ignore')
            except Exception:
                text = ''

            if _content_matches_signature(path, text, content_type):
                exposed.append((path, severity, desc))
                penalty = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}.get(severity, 5)
                out['score_penalty'] += penalty
                out['tickets'].append({
                    'title': f'Fichier sensible expose : {path}',
                    'description': desc + ' (confirme par signature de contenu, pas seulement le code HTTP)',
                    'severity': severity,
                    'evidence': EVIDENCE_CONFIRMED,
                    'remediation': f'Supprimer ou proteger l\'acces au fichier {path}.\n'
                                   f'Nginx : location {path} {{ deny all; }}\n'
                                   f'Apache : <Files "{path}"> Require all denied </Files>'
                })
            else:
                unconfirmed.append(path)

        except Exception:
            pass

    if exposed:
        out['checks'].append({
            'name': '[Fichiers] Fichiers sensibles exposes',
            'status': 'fail',
            'severity': 'critical',
            'detail': f'{len(exposed)} fichier(s) sensible(s) confirme(s) (signature de contenu validee) : '
                      + ', '.join([p for p, _, _ in exposed[:5]])
        })
    else:
        out['checks'].append({
            'name': '[Fichiers] Fichiers sensibles exposes',
            'status': 'pass',
            'severity': 'low',
            'detail': f'Aucun fichier sensible confirme parmi {len(SENSITIVE_FILES)} chemins testes.'
        })

    if unconfirmed:
        out['checks'].append({
            'name': '[Fichiers] Reponses 200 non confirmees (a verifier manuellement)',
            'status': 'warn',
            'severity': 'low',
            'detail': f'{len(unconfirmed)} chemin(s) renvoient 200 sans signature de contenu attendue '
                      f'(probable faux positif) : ' + ', '.join(unconfirmed[:5])
                      + (' — le site semble avoir un comportement catch-all (200 sur URL inexistante).'
                         if is_catchall else '')
        })

    return out


def _check_public_resources(base):
    out = {'checks': [], 'tickets': []}
    findings = []

    for path, expected_markers in PUBLIC_RESOURCES:
        try:
            r = requests.get(base + path, timeout=5, verify=True,
                             allow_redirects=False,
                             headers={'User-Agent': 'DevShield-Scanner/1.0'})
            if r.status_code == 200 and any(m in r.text for m in expected_markers):
                if path == '/sitemap.xml':
                    entries = re.findall(r'<loc>(.*?)</loc>', r.text)
                else:
                    entries = r.text.splitlines()

                SUSPICIOUS_KEYWORDS_PATTERN = re.compile(
                    r'(?:^|[/\-_.\s])(admin|backup|private|internal|config)(?:$|[/\-_.\s])',
                    re.IGNORECASE
                )
                suspicious = [e.strip()[:200] for e in entries
                              if SUSPICIOUS_KEYWORDS_PATTERN.search(e)]
                if suspicious:
                    suspicious = list(dict.fromkeys(suspicious))[:3]
                    findings.append((path, suspicious))
        except Exception:
            pass

    if findings:
        for path, lines in findings:
            out['checks'].append({
                'name': f'[Info] Ressource publique : {path}',
                'status': 'warn',
                'severity': 'low',
                'detail': f'{path} accessible (normal, ressource publique par design). '
                          f'Chemins potentiellement sensibles listes dedans : ' + '; '.join(lines)
            })
    else:
        out['checks'].append({
            'name': '[Info] Ressources publiques (robots.txt / sitemap.xml)',
            'status': 'pass',
            'severity': 'low',
            'detail': 'robots.txt / sitemap.xml analyses — aucun chemin sensible mentionne. '
                      'Ces fichiers sont publics par design et ne constituent pas une vulnerabilite.'
        })

    return out


# ============================================================
# ENDPOINTS API SENSIBLES
# ============================================================

INFORMATIONAL_ENDPOINTS = {'/health', '/status'}

ENDPOINT_SIGNATURES = {
    '/metrics':          [r'# HELP', r'# TYPE', r'process_'],
    '/debug':            [r'debug', r'traceback', r'stack ?trace'],
    '/admin':            [r'<title>[^<]*admin', r'login', r'dashboard'],
    '/console':          [r'console', r'<title>[^<]*console'],
    '/api/users':        [r'"id"\s*:', r'"email"\s*:', r'"username"\s*:'],
    '/api/config':       [r'"config"', r'[A-Z_]+\s*[:=]'],
    '/api/admin':        [r'admin', r'"role"'],
    '/wp-json/wp/v2/users': [r'"id"\s*:', r'"slug"\s*:', r'"name"\s*:'],
}

SENSITIVE_ENDPOINTS = [
    ('/api',            'medium',  'Endpoint API accessible sans authentification.'),
    ('/api/v1',         'medium',  'API v1 accessible sans authentification.'),
    ('/api/v2',         'medium',  'API v2 accessible sans authentification.'),
    ('/metrics',        'high',    'Endpoint /metrics expose — donnees de monitoring (Prometheus) accessibles.'),
    ('/health',         'low',     'Endpoint /health expose — statut de l\'application accessible.'),
    ('/debug',          'critical','Endpoint /debug expose — interface de debug accessible publiquement.'),
    ('/admin',          'high',    'Interface /admin accessible — verifier l\'authentification.'),
    ('/status',         'low',     'Endpoint /status expose — informations sur l\'etat du service.'),
    ('/console',        'critical','Console d\'administration exposee publiquement.'),
    ('/api/users',      'critical','Endpoint /api/users accessible — donnees utilisateurs potentiellement exposees.'),
    ('/api/config',     'critical','Endpoint /api/config accessible — configuration exposee.'),
    ('/api/admin',      'critical','API admin accessible — acces administrateur potentiel.'),
    ('/wp-json/wp/v2/users', 'high', 'WordPress REST API expose la liste des utilisateurs (enumeration possible).'),
]


def _check_sensitive_endpoints(base):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}

    is_catchall, catchall_ctype, catchall_len = _detect_catchall(base)

    exposed = []
    info_only = []
    unconfirmed = []

    for path, severity, desc in SENSITIVE_ENDPOINTS:
        try:
            r = requests.get(base + path, timeout=4, verify=True,
                             allow_redirects=False,
                             headers={'User-Agent': 'DevShield-Scanner/1.0'})
            if r.status_code != 200 or len(r.content) <= 50:
                continue

            if is_catchall and _looks_like_catchall_response(r, catchall_ctype, catchall_len):
                continue

            if path in INFORMATIONAL_ENDPOINTS:
                info_only.append(path)
                continue

            content_type = r.headers.get('Content-Type', '')
            try:
                text = r.content[:5000].decode('utf-8', errors='ignore')
            except Exception:
                text = ''

            patterns = ENDPOINT_SIGNATURES.get(path)
            confirmed = any(re.search(p, text, re.IGNORECASE) for p in patterns) if patterns else True

            if confirmed:
                exposed.append((path, severity, desc))
                penalty = {'critical': 20, 'high': 12, 'medium': 6, 'low': 2}.get(severity, 5)
                out['score_penalty'] += penalty
                out['tickets'].append({
                    'title': f'[API] Endpoint sensible expose : {path}',
                    'description': desc + ' (confirme par le contenu de la reponse)',
                    'severity': severity,
                    'evidence': EVIDENCE_CONFIRMED,
                    'remediation': f'Proteger l\'endpoint {path} par authentification.\n'
                                   f'Si l\'endpoint doit etre public, verifier qu\'il n\'expose pas de donnees sensibles.\n'
                                   f'Pour une API, utiliser des tokens d\'authentification (JWT, API keys).'
                })
            else:
                unconfirmed.append(path)

        except Exception:
            pass

    if exposed:
        out['checks'].append({
            'name': '[API] Endpoints sensibles exposes',
            'status': 'fail',
            'severity': 'critical' if any(s == 'critical' for _, s, _ in exposed) else 'high',
            'detail': f'{len(exposed)} endpoint(s) sensible(s) confirme(s) : '
                      + ', '.join([p for p, _, _ in exposed[:5]])
        })
    else:
        out['checks'].append({
            'name': '[API] Endpoints sensibles exposes',
            'status': 'pass',
            'severity': 'low',
            'detail': f'Aucun endpoint sensible confirme parmi {len(SENSITIVE_ENDPOINTS)} chemins testes.'
        })

    if info_only:
        out['checks'].append({
            'name': '[Info] Endpoints de statut publics',
            'status': 'pass',
            'severity': 'low',
            'detail': f'{", ".join(info_only)} accessible(s) — normal pour des probes de sante '
                      f'(Kubernetes, load balancer). Non traite comme une vulnerabilite.'
        })

    if unconfirmed:
        out['checks'].append({
            'name': '[API] Reponses 200 non confirmees (a verifier manuellement)',
            'status': 'warn',
            'severity': 'low',
            'detail': f'{len(unconfirmed)} endpoint(s) renvoient 200 sans signature de contenu attendue : '
                      + ', '.join(unconfirmed[:5])
        })

    return out


# ============================================================
# FUITES HTML
# ============================================================

def _check_html_leaks(html, url):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    issues = []

    emails = re.findall(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b', html
    )
    emails = [e for e in set(emails) if not e.endswith(('.png', '.jpg', '.css', '.js'))]
    if emails:
        issues.append(f'{len(emails)} email(s) detecte(s) dans le HTML : {", ".join(emails[:3])}')
        out['tickets'].append({
            'title': '[Info] Adresses email exposees dans le HTML',
            'description': f'{len(emails)} adresse(s) email trouvee(s) dans le code source : '
                           f'{", ".join(emails[:3])}. Risque de spam/phishing.',
            'severity': 'low',
            'evidence': EVIDENCE_CONFIRMED,
            'remediation': 'Supprimer les adresses email du code source HTML.\n'
                           'Utiliser des formulaires de contact avec CAPTCHA ou des services de protection d\'email.'
        })
        out['score_penalty'] += 3

    comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    sensitive_comments = []
    sensitive_keywords = ['password', 'passwd', 'secret', 'api_key', 'apikey',
                          'token', 'todo', 'fixme', 'hack', 'bug', 'vulnerability',
                          'admin', 'debug', 'test', 'credential']
    for comment in comments:
        if any(kw in comment.lower() for kw in sensitive_keywords):
            sensitive_comments.append(comment.strip()[:100])
    if sensitive_comments:
        issues.append(f'{len(sensitive_comments)} commentaire(s) HTML sensible(s) detecte(s)')
        out['tickets'].append({
            'title': '[Info] Commentaires HTML avec informations sensibles',
            'description': f'{len(sensitive_comments)} commentaire(s) HTML contiennent des mots-cles sensibles. '
                           f'Exemple : "{sensitive_comments[0][:80]}..."',
            'severity': 'medium',
            'evidence': EVIDENCE_CONFIRMED,
            'remediation': 'Supprimer les commentaires HTML contenant des informations sensibles.\n'
                           'Ne pas stocker de secrets ou de credentials dans le code source.'
        })
        out['score_penalty'] += 8

    generator = re.findall(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)',
                           html, re.IGNORECASE)
    if generator:
        issues.append(f'CMS/generateur expose : {generator[0]}')
        out['tickets'].append({
            'title': '[Info] Version CMS exposee dans meta generator',
            'description': f'La balise meta generator expose : "{generator[0]}". '
                           f'Supprime cette balise pour masquer la technologie utilisee.',
            'severity': 'low',
            'evidence': EVIDENCE_SIGNATURE,
            'remediation': 'Supprimer la balise meta generator du code HTML.\n'
                           'Pour WordPress : supprimer wp_generator() du theme.'
        })
        out['score_penalty'] += 3

    api_patterns = [
        (r'api[_-]?key["\s]*[:=]["\s]*([A-Za-z0-9_\-]{20,})', 'cle API'),
        (r'token["\s]*[:=]["\s]*([A-Za-z0-9_\-\.]{20,})', 'token'),
        (r'secret["\s]*[:=]["\s]*([A-Za-z0-9_\-]{16,})', 'secret'),
    ]
    for pattern, label in api_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        if matches:
            issues.append(f'Potentielle {label} exposee dans le code source')
            out['tickets'].append({
                'title': f'[CRITIQUE] {label.capitalize()} potentiellement exposee dans le HTML',
                'description': f'Une chaine ressemblant a une {label} a ete detectee dans le code source. '
                               f'Verifier et revoquer si necessaire. Ne jamais inclure de secrets dans le HTML.',
                'severity': 'critical',
                'evidence': EVIDENCE_CONFIRMED,
                'remediation': f'Revoquer immediatement la {label} si elle est reelle.\n'
                               f'Utiliser des variables d\'environnement pour les secrets, jamais de hardcoding.\n'
                               f'Verifier que le secret n\'est pas commit dans Git.'
            })
            out['score_penalty'] += 25

    if issues:
        out['checks'].append({
            'name': '[HTML] Fuites d\'information dans le code source',
            'status': 'fail',
            'severity': 'high',
            'detail': ' | '.join(issues)
        })
    else:
        out['checks'].append({
            'name': '[HTML] Fuites d\'information dans le code source',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Aucune fuite d\'information detectee dans le code source HTML.'
        })

    return out

# ============================================================
# SUBRESOURCE INTEGRITY (SRI)
# ============================================================

def _check_sri(html_content, base_url):
    """
    Vérifie si les scripts externes utilisent Subresource Integrity (SRI).
    """
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    
    if not html_content:
        out['checks'].append({
            'name': '[SRI] Subresource Integrity',
            'status': 'warn',
            'severity': 'low',
            'detail': 'HTML non disponible pour vérifier SRI.'
        })
        return out
    
    # Trouver tous les scripts externes (src="...")
    script_tags = re.findall(r'<script[^>]*src=["\'](https?://[^"\']+)["\'][^>]*>', html_content, re.IGNORECASE)
    
    if not script_tags:
        out['checks'].append({
            'name': '[SRI] Subresource Integrity',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Aucun script externe chargé. SRI non applicable.'
        })
        return out
    
    # Vérifier si les scripts ont integrity
    scripts_without_sri = []
    for src in script_tags:
        # Chercher la balise complète avec integrity
        pattern = f'<script[^>]*src=["\']{re.escape(src)}["\'][^>]*>'
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            tag = match.group(0)
            if 'integrity=' not in tag:
                scripts_without_sri.append(src[:50] + ('...' if len(src) > 50 else ''))
    
    if scripts_without_sri:
        out['checks'].append({
            'name': '[SRI] Subresource Integrity',
            'status': 'fail',
            'severity': 'medium',
            'detail': f"{len(scripts_without_sri)} script(s) externe(s) sans SRI : {', '.join(scripts_without_sri[:3])}"
        })
        out['score_penalty'] += 5
        out['tickets'].append({
            'title': 'Subresource Integrity (SRI) manquant',
            'description': f"{len(scripts_without_sri)} scripts externes ne contiennent pas d'attribut 'integrity'. "
                           f"Exemple : {scripts_without_sri[0] if scripts_without_sri else ''}",
            'severity': 'medium',
            'evidence': EVIDENCE_MISSING_CONTROL,
            'remediation': 'Ajouter l\'attribut integrity aux balises script avec le hash SHA-384 du fichier.\n'
                           'Exemple : <script src="https://example.com/script.js" integrity="sha384-xxxxx"></script>\n'
                           'Générer le hash : openssl dgst -sha384 -binary script.js | base64'
        })
    else:
        out['checks'].append({
            'name': '[SRI] Subresource Integrity',
            'status': 'pass',
            'severity': 'low',
            'detail': f"{len(script_tags)} script(s) externe(s) avec SRI correct."
        })
    
    return out


# ============================================================
# REDIRECTIONS (VERSION CORRIGEE)
# ============================================================

def _check_redirections(url, parsed):
    """
    Verifie la redirection HTTP → HTTPS.
    Suit la redirection jusqu'a la reponse finale pour analyser le contenu.
    Ne penalise pas si la redirection finale est bien vers HTTPS.
    """
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}

    if url.startswith('https://'):
        http_url = url.replace('https://', 'http://', 1)
        try:
            # Suivre la redirection jusqu'au bout
            r = requests.get(http_url, timeout=10, allow_redirects=True,
                             verify=True,
                             headers={'User-Agent': 'DevShield-Scanner/1.0'})
            
            # Verifier ou on a atterri
            final_url = r.url
            final_scheme = urlparse(final_url).scheme
            
            # Compter le nombre de redirections
            redirect_count = len(r.history)
            
            if redirect_count > 0:
                # Il y a eu au moins une redirection
                if final_scheme == 'https':
                    out['checks'].append({
                        'name': '[Redirect] HTTP vers HTTPS',
                        'status': 'pass',
                        'severity': 'low',
                        'detail': f'Redirection HTTP → HTTPS suivie avec succes ({redirect_count} redirection(s)). '
                                  f'Destination finale : {final_url[:80]}'
                    })
                else:
                    out['checks'].append({
                        'name': '[Redirect] HTTP vers HTTPS',
                        'status': 'fail',
                        'severity': 'high',
                        'detail': f'Redirection HTTP ne mene pas vers HTTPS. '
                                  f'Destination finale : {final_url[:80]}'
                    })
                    out['score_penalty'] += 10
                    out['tickets'].append({
                        'title': 'Redirection HTTP ne pointe pas vers HTTPS',
                        'description': f'Le site redirige HTTP vers {final_scheme}://... '
                                       f'mais pas vers HTTPS. Les utilisateurs peuvent atterrir sur une version non chiffree.',
                        'severity': 'high',
                        'evidence': EVIDENCE_CONFIRMED,
                        'remediation': 'Configurer la redirection HTTP → HTTPS sur le serveur.\n'
                                       'Nginx : return 301 https://$server_name$request_uri;\n'
                                       'Apache : Redirect permanent / https://votre-domaine.com/'
                    })
            else:
                # Pas de redirection
                out['checks'].append({
                    'name': '[Redirect] HTTP vers HTTPS',
                    'status': 'fail',
                    'severity': 'high',
                    'detail': 'Le site repond en HTTP sans rediriger vers HTTPS. Acces non chiffre possible.'
                })
                out['score_penalty'] += 15
                out['tickets'].append({
                    'title': 'Acces HTTP sans redirection HTTPS',
                    'description': 'Le site est accessible directement en HTTP sans etre redirige vers HTTPS. '
                                   'Les utilisateurs peuvent naviguer en clair.',
                    'severity': 'high',
                    'evidence': EVIDENCE_CONFIRMED,
                    'remediation': 'Activer HTTPS et configurer la redirection HTTP → HTTPS.\n'
                                   '1. Installer un certificat SSL\n'
                                   '2. Configurer le serveur pour ecouter sur le port 443\n'
                                   '3. Rediriger HTTP vers HTTPS (voir remediation ci-dessus)'
                })
                
        except requests.exceptions.SSLError as e:
            out['checks'].append({
                'name': '[Redirect] HTTP vers HTTPS',
                'status': 'warn',
                'severity': 'medium',
                'detail': f'Erreur SSL lors du suivi de la redirection — certificat invalide : {str(e)[:80]}'
            })
        except requests.exceptions.Timeout:
            out['checks'].append({
                'name': '[Redirect] HTTP vers HTTPS',
                'status': 'warn',
                'severity': 'low',
                'detail': 'Timeout lors du suivi de la redirection HTTP.'
            })
        except Exception as e:
            out['checks'].append({
                'name': '[Redirect] HTTP vers HTTPS',
                'status': 'warn',
                'severity': 'low',
                'detail': f'Impossible de tester la redirection HTTP : {str(e)[:80]}'
            })

    return out


# ============================================================
# METHODE HTTP TRACE (Cross-Site Tracing)
# ============================================================

def _check_trace_method(base):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    try:
        r = requests.request('TRACE', base, timeout=5, verify=True,
                             headers={'User-Agent': 'DevShield-Scanner/1.0'})
        trace_enabled = r.status_code == 200 and 'TRACE' in r.text.upper()[:20]
        out['checks'].append({
            'name': '[HTTP] Methode TRACE',
            'status': 'fail' if trace_enabled else 'pass',
            'severity': 'medium',
            'detail': 'La methode TRACE est activee — permet des attaques XST (Cross-Site Tracing).'
                      if trace_enabled else 'Methode TRACE desactivee ou non exploitable.'
        })
        if trace_enabled:
            out['score_penalty'] += 8
            out['tickets'].append({
                'title': '[HTTP] Methode TRACE activee',
                'description': 'Le serveur repond a la methode HTTP TRACE, ce qui peut permettre '
                               'des attaques XST combinees a du XSS pour voler des cookies/headers.',
                'severity': 'medium',
                'evidence': EVIDENCE_CONFIRMED,
                'remediation': 'Desactiver la methode TRACE sur le serveur.\n'
                               'Nginx : return 405 si methode TRACE\n'
                               'Apache : TraceEnable Off'
            })
    except Exception:
        out['checks'].append({
            'name': '[HTTP] Methode TRACE',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Methode TRACE non testable (connexion refusee) — probablement desactivee.'
        })
    return out


# ============================================================
# DIRECTORY LISTING
# ============================================================

DIRECTORY_LISTING_PATTERNS = [
    'Index of /', '<title>Index of', 'Directory Listing For',
    'Parent Directory</a>', 'directory_listing_denied'
]

DIRECTORY_LISTING_PATHS = ['/uploads/', '/files/', '/images/', '/backup/', '/assets/', '/static/']

def _check_directory_listing(base, homepage_html):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    exposed = []

    candidates = [('/', homepage_html)]

    for path in DIRECTORY_LISTING_PATHS:
        try:
            r = requests.get(base + path, timeout=4, verify=True,
                             allow_redirects=False,
                             headers={'User-Agent': 'DevShield-Scanner/1.0'})
            if r.status_code == 200:
                candidates.append((path, r.text[:2000]))
        except Exception:
            pass

    for path, content in candidates:
        if content and any(p.lower() in content.lower() for p in DIRECTORY_LISTING_PATTERNS):
            exposed.append(path)

    if exposed:
        out['checks'].append({
            'name': '[Config] Directory listing',
            'status': 'fail',
            'severity': 'medium',
            'detail': f'Listing de repertoire actif sur : {", ".join(exposed)}. '
                      f'Le contenu des dossiers est enumerable publiquement.'
        })
        out['score_penalty'] += 10
        out['tickets'].append({
            'title': '[Config] Directory listing active',
            'description': f'Le serveur affiche le contenu de repertoires sans index ({", ".join(exposed)}).',
            'severity': 'medium',
            'evidence': EVIDENCE_CONFIRMED,
            'remediation': 'Desactiver le directory listing sur le serveur.\n'
                           'Nginx : autoindex off;\n'
                           'Apache : Options -Indexes'
        })
    else:
        out['checks'].append({
            'name': '[Config] Directory listing',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Aucun listing de repertoire detecte sur les chemins testes.'
        })

    return out


# ============================================================
# DETECTION CDN / REVERSE PROXY
# ============================================================

CDN_SIGNATURES = {
    'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
    'AWS CloudFront': ['x-amz-cf-id', 'x-amz-cf-pop'],
    'Fastly': ['x-served-by', 'x-fastly-request-id'],
    'Akamai': ['x-akamai-transformed'],
    'Vercel': ['x-vercel-id', 'x-vercel-cache'],
}

def _detect_cdn(headers_data):
    out = {'checks': []}
    headers_lower = {k.lower(): v for k, v in headers_data.items()}
    detected = None
    for cdn, signature_headers in CDN_SIGNATURES.items():
        if any(h in headers_lower for h in signature_headers):
            detected = cdn
            break

    if detected:
        out['checks'].append({
            'name': '[Info] CDN / proxy detecte',
            'status': 'warn',
            'severity': 'low',
            'detail': f'{detected} detecte. Certains headers (HSTS, CSP...) peuvent etre ajoutes/geres '
                      f'par le CDN et ne pas refleter la configuration reelle du serveur d\'origine. '
                      f'A prendre en compte dans l\'interpretation du score.'
        })
    else:
        out['checks'].append({
            'name': '[Info] CDN / proxy detecte',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Aucun CDN connu detecte — le scan reflete probablement la configuration du serveur d\'origine.'
        })
    return out


# ============================================================
# COHERENCE MULTI-PAGES
# ============================================================

MULTI_PAGE_PATHS = ['/api/health', '/login', '/api']

HEADERS_TO_COMPARE = [
    'Strict-Transport-Security', 'X-Frame-Options',
    'X-Content-Type-Options', 'Content-Security-Policy'
]

def _check_multi_page_consistency(base, root_headers):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    inconsistent = []
    tested_paths = []

    for path in MULTI_PAGE_PATHS:
        try:
            r = requests.get(base + path, timeout=4, verify=True,
                             allow_redirects=True,
                             headers={'User-Agent': 'DevShield-Scanner/1.0'})
            if r.status_code >= 400:
                continue
            tested_paths.append(path)
            for header in HEADERS_TO_COMPARE:
                root_present = header in root_headers
                page_present = header in r.headers
                if root_present and not page_present:
                    inconsistent.append(f'{header} absent sur {path} (present sur /)')
        except Exception:
            continue

    if not tested_paths:
        out['checks'].append({
            'name': '[Config] Coherence multi-pages',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Aucune page additionnelle accessible pour comparaison (score base sur la racine uniquement).'
        })
    elif inconsistent:
        out['checks'].append({
            'name': '[Config] Coherence multi-pages',
            'status': 'warn',
            'severity': 'medium',
            'detail': f'Configuration incoherente entre pages : {"; ".join(inconsistent[:4])}'
        })
        out['score_penalty'] += 6
        out['tickets'].append({
            'title': '[Config] Headers de securite incoherents entre pages',
            'description': f'Certains headers presents sur la racine sont absents sur d\'autres pages '
                           f'testees ({", ".join(tested_paths)}).',
            'severity': 'medium',
            'evidence': EVIDENCE_MISSING_CONTROL,
            'remediation': 'Appliquer la configuration de securite a toutes les pages du site.\n'
                           'Utiliser un middleware global pour ajouter les headers de securite.\n'
                           'Verifier la configuration du reverse proxy (Nginx/Apache).'
        })
    else:
        out['checks'].append({
            'name': '[Config] Coherence multi-pages',
            'status': 'pass',
            'severity': 'low',
            'detail': f'Headers coherents entre la racine et {len(tested_paths)} page(s) testee(s) '
                      f'({", ".join(tested_paths)}).'
        })

    return out


# ============================================================
# DIFF ENTRE DEUX SCANS
# ============================================================

def compare_scans(previous_checks, current_checks):
    prev_map = {c['name']: c['status'] for c in previous_checks}
    curr_map = {c['name']: c['status'] for c in current_checks}

    new_failures = []
    resolved = []
    unchanged_fail = []

    all_names = set(prev_map.keys()) | set(curr_map.keys())
    for name in all_names:
        prev_status = prev_map.get(name)
        curr_status = curr_map.get(name)
        was_bad = prev_status in ('fail', 'warn', 'error')
        is_bad = curr_status in ('fail', 'warn', 'error')

        if is_bad and not was_bad:
            new_failures.append({'name': name, 'status': curr_status})
        elif was_bad and not is_bad:
            resolved.append({'name': name, 'previous_status': prev_status})
        elif is_bad and was_bad:
            unchanged_fail.append({'name': name, 'status': curr_status})

    return {
        'new_failures': new_failures,
        'resolved': resolved,
        'unchanged_fail': unchanged_fail,
        'summary': f'{len(resolved)} corrige(s), {len(new_failures)} nouvelle(s), '
                   f'{len(unchanged_fail)} persistante(s)'
    }


# ============================================================
# SECURITE EMAIL (SPF / DKIM / DMARC) - DETAILLEE
# ============================================================

def _check_email_security_detailed(hostname):
    """
    Verifie les enregistrements SPF, DKIM et DMARC de maniere detaillee.
    """
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}

    try:
        import dns.resolver
    except ImportError:
        out['checks'].append({
            'name': '[Email] SPF/DKIM/DMARC',
            'status': 'warn',
            'severity': 'low',
            'detail': 'Module dnspython non installe — verification email desactivee '
                      '(pip install dnspython pour l\'activer).'
        })
        return out

    root_domain = '.'.join(hostname.split('.')[-2:]) if hostname.count('.') >= 1 else hostname

    # 1. SPF
    spf_found = False
    spf_details = "Aucun enregistrement SPF trouve"
    spf_mechanisms = []
    try:
        answers = dns.resolver.resolve(root_domain, 'TXT', lifetime=5)
        for r in answers:
            txt = str(r).lower()
            if 'v=spf1' in txt:
                spf_found = True
                mechs = re.findall(r'\b(?:include|a|mx|ip4|ip6|exists|redirect)\s*[:=]?[^\s]+', txt)
                spf_mechanisms = mechs[:3]
                spf_details = f"SPF trouve : {txt[:150]}"
                break
    except Exception:
        pass

    _add_email_check_detailed(out, '[Email] SPF', spf_found, 'medium',
                              spf_details if spf_found else 'Aucun enregistrement SPF trouve. Risque d\'usurpation d\'expediteur (spoofing).')

    if spf_found and spf_mechanisms:
        out['checks'].append({
            'name': '[Email] SPF - Mecanismes',
            'status': 'pass' if len(spf_mechanisms) > 0 else 'warn',
            'severity': 'low',
            'detail': f'Mecanismes SPF detectes : {", ".join(spf_mechanisms)}'
        })

    # 2. DKIM
    dkim_found = False
    dkim_selectors = ['default', 'dkim', 'mail', 'email', 'google', 'microsoft', 'selector1', 'selector2']
    dkim_details = "Aucun enregistrement DKIM trouve"
    try:
        for selector in dkim_selectors:
            try:
                dkim_domain = f'{selector}._domainkey.{root_domain}'
                answers = dns.resolver.resolve(dkim_domain, 'TXT', lifetime=5)
                for r in answers:
                    if 'v=dkim1' in str(r).lower():
                        dkim_found = True
                        dkim_details = f'DKIM trouve avec le selecteur : {selector}'
                        break
                if dkim_found:
                    break
            except Exception:
                continue
    except Exception:
        pass

    _add_email_check_detailed(out, '[Email] DKIM', dkim_found, 'medium',
                              dkim_details if dkim_found else 'Aucun enregistrement DKIM trouve. Les emails peuvent etre consideres comme spam.')

    # 3. DMARC
    dmarc_found = False
    dmarc_policy = "Aucune politique DMARC definie"
    dmarc_details = "Aucun enregistrement DMARC trouve"
    try:
        answers = dns.resolver.resolve(f'_dmarc.{root_domain}', 'TXT', lifetime=5)
        for r in answers:
            txt = str(r).lower()
            if 'v=dmarc1' in txt:
                dmarc_found = True
                policy_match = re.search(r'p\s*=\s*(none|quarantine|reject)', txt)
                if policy_match:
                    dmarc_policy = policy_match.group(1)
                dmarc_details = f"DMARC trouve : politique {dmarc_policy} - {txt[:150]}"
                break
    except Exception:
        pass

    _add_email_check_detailed(out, '[Email] DMARC', dmarc_found, 'medium',
                              dmarc_details if dmarc_found else 'Aucun enregistrement DMARC trouve. Aucune politique de rejet des emails usurpes.')

    if dmarc_found:
        if dmarc_policy == 'reject':
            out['checks'].append({
                'name': '[Email] DMARC - Politique',
                'status': 'pass',
                'severity': 'low',
                'detail': f'Politique DMARC : {dmarc_policy} (configuration recommandee)'
            })
        elif dmarc_policy == 'quarantine':
            out['checks'].append({
                'name': '[Email] DMARC - Politique',
                'status': 'warn',
                'severity': 'low',
                'detail': f'Politique DMARC : {dmarc_policy} (mode de transition, preferer reject)'
            })
            out['tickets'].append({
                'title': '[Email] DMARC - Politique quarantine',
                'description': 'La politique DMARC est en mode quarantine. Preferer reject pour une protection maximale.',
                'severity': 'low',
                'evidence': EVIDENCE_MISSING_CONTROL,
                'remediation': 'Passer la politique DMARC en mode reject.\n'
                               'Modifier l\'enregistrement DMARC : p=reject'
            })
        else:
            out['checks'].append({
                'name': '[Email] DMARC - Politique',
                'status': 'warn',
                'severity': 'medium',
                'detail': f'Politique DMARC : {dmarc_policy} (mode monitoring, ne bloque pas les emails usurpes)'
            })
            out['tickets'].append({
                'title': '[Email] DMARC - Politique none',
                'description': 'La politique DMARC est en mode monitoring (none). Les emails usurpes ne sont pas bloques.',
                'severity': 'medium',
                'evidence': EVIDENCE_MISSING_CONTROL,
                'remediation': 'Passer la politique DMARC en mode quarantine puis reject.\n'
                               '1. DMARC p=quarantine (phase de test)\n'
                               '2. DMARC p=reject (phase finale)'
            })

    return out


def _add_email_check_detailed(out, name, ok, severity, detail):
    out['checks'].append({
        'name': name,
        'status': 'pass' if ok else 'warn',
        'severity': severity,
        'detail': detail
    })
    if not ok:
        penalty = {'critical': 15, 'high': 10, 'medium': 5, 'low': 2}.get(severity, 5)
        out['score_penalty'] += penalty
        out['tickets'].append({
            'title': f'{name} manquant',
            'description': detail,
            'severity': severity,
            'evidence': EVIDENCE_MISSING_CONTROL,
            'remediation': f'Ajouter un enregistrement {name.split(" ")[1]} dans la configuration DNS.\n'
                           f'SPF : v=spf1 mx -all\n'
                           f'DKIM : generer une cle DKIM et ajouter l\'enregistrement TXT\n'
                           f'DMARC : _dmarc.votredomaine.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@votredomaine.com"'
        })

# ============================================================
# HSTS PRELOAD (détection via Chrome preload list)
# ============================================================

def _check_hsts_preload(domain):
    """
    Vérifie si le domaine est dans la liste de préchargement HSTS de Chrome.
    """
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    
    try:
        # Utiliser l'API de préchargement de Chrome
        url = f"https://hstspreload.org/api/v2/status?domain={domain}"
        response = requests.get(url, timeout=10, verify=True)
        
        if response.status_code == 200:
            data = response.json()
            preloaded = data.get('preloaded', False)
            
            if preloaded:
                out['checks'].append({
                    'name': '[HSTS] Preload',
                    'status': 'pass',
                    'severity': 'low',
                    'detail': f"{domain} est préchargé dans la liste HSTS de Chrome."
                })
                out['score_penalty'] += 0  # Bonus (pas de pénalité)
            else:
                out['checks'].append({
                    'name': '[HSTS] Preload',
                    'status': 'warn',
                    'severity': 'low',
                    'detail': f"{domain} n'est pas préchargé. "
                              f"Pour être préchargé, ajoutez 'preload' à HSTS et soumettez à https://hstspreload.org/"
                })
                out['tickets'].append({
                    'title': 'HSTS non préchargé',
                    'description': f"Le domaine {domain} n'est pas dans la liste de préchargement HSTS de Chrome. "
                                   f"Soumettre le domaine à https://hstspreload.org/ pour une protection renforcée.",
                    'severity': 'low',
                    'evidence': EVIDENCE_MISSING_CONTROL,
                    'remediation': '1. Ajouter "preload" à la directive HSTS : max-age=31536000; includeSubDomains; preload\n'
                                   '2. Soumettre le domaine : https://hstspreload.org/\n'
                                   '3. Attendre la validation (généralement 1-2 semaines)'
                })
        else:
            out['checks'].append({
                'name': '[HSTS] Preload',
                'status': 'warn',
                'severity': 'low',
                'detail': 'Impossible de vérifier le préchargement HSTS (API indisponible).'
            })
    except Exception as e:
        out['checks'].append({
            'name': '[HSTS] Preload',
            'status': 'warn',
            'severity': 'low',
            'detail': f'Erreur de vérification HSTS preload : {str(e)[:80]}'
        })
    
    return out


# ============================================================
# METHODES HTTP DANGEREUSES
# ============================================================

def _check_dangerous_methods(base):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    dangerous_found = []

    for method in ['PUT', 'DELETE']:
        try:
            r = requests.request(method, base, timeout=4, verify=True,
                                 headers={'User-Agent': 'DevShield-Scanner/1.0'})
            if r.status_code in (200, 201, 204):
                dangerous_found.append(method)
        except Exception:
            pass

    try:
        r = requests.options(base, timeout=4, verify=True,
                             headers={'User-Agent': 'DevShield-Scanner/1.0'})
        allow = r.headers.get('Allow', '')
        if any(m in allow.upper() for m in ('PUT', 'DELETE', 'TRACE', 'CONNECT')):
            out['checks'].append({
                'name': '[HTTP] Methodes autorisees (OPTIONS)',
                'status': 'warn',
                'severity': 'low',
                'detail': f'Le serveur annonce accepter : {allow}. Verifier que ces methodes '
                          f'sont bien protegees par authentification si elles modifient des donnees.'
            })
        else:
            out['checks'].append({
                'name': '[HTTP] Methodes autorisees (OPTIONS)',
                'status': 'pass',
                'severity': 'low',
                'detail': f'Methodes annoncees : {allow or "non communique"}.'
            })
    except Exception:
        pass

    if dangerous_found:
        out['checks'].append({
            'name': '[HTTP] Methodes PUT/DELETE',
            'status': 'warn',
            'severity': 'medium',
            'detail': f'Le serveur repond positivement a : {", ".join(dangerous_found)}. '
                      f'Verifier qu\'une authentification est bien exigee pour ces operations.'
        })
        out['score_penalty'] += 6
        out['tickets'].append({
            'title': '[HTTP] Methodes de modification potentiellement ouvertes',
            'description': f'{", ".join(dangerous_found)} semble(nt) accepte(s) sans erreur claire. '
                           f'Si ces methodes modifient des donnees, s\'assurer qu\'elles exigent une authentification.',
            'severity': 'medium',
            'evidence': EVIDENCE_SIGNATURE,
            'remediation': 'Restreindre les methodes HTTP autorisees sur le serveur.\n'
                           'Nginx : limit_except GET HEAD { deny all; }\n'
                           'Apache : <LimitExcept GET HEAD POST> Require all denied </LimitExcept>'
        })
    else:
        out['checks'].append({
            'name': '[HTTP] Methodes PUT/DELETE',
            'status': 'pass',
            'severity': 'low',
            'detail': 'PUT/DELETE non exploitables directement sans authentification apparente.'
        })

    return out


# ============================================================
# TESTS OWASP ACTIFS — SQLi / XSS reflechi / CSRF
# ============================================================

SQL_ERROR_SIGNATURES = [
    'sql syntax', 'mysql_fetch', 'you have an error in your sql syntax',
    'warning: mysql', 'unclosed quotation mark', 'quoted string not properly terminated',
    'ora-01756', 'ora-00933', 'sqlite3::', 'sqlite_error',
    'postgresql.*error', 'pg_query', 'psql:', 'syntax error at or near',
    'microsoft odbc', 'odbc sql server driver', 'mssql_query',
]

SQLI_PAYLOADS = ["'", "1' OR '1'='1", "1 OR 1=1--", '" OR "1"="1']
XSS_MARKER = 'dvshld_xss_test_9f21'
XSS_PAYLOADS = [f'<script>alert("{XSS_MARKER}")</script>', f'"><img src=x onerror=alert("{XSS_MARKER}")>']

CSRF_TOKEN_HINTS = ['csrf', 'token', '_token', 'authenticity_token', 'csrfmiddlewaretoken']


def _check_owasp_active(url, parsed, html_content, headers_data):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}

    sqli = _test_sql_injection(url, parsed)
    out['checks'].extend(sqli['checks'])
    out['tickets'].extend(sqli['tickets'])
    out['score_penalty'] += sqli['score_penalty']

    xss = _test_xss_reflected(url, parsed)
    out['checks'].extend(xss['checks'])
    out['tickets'].extend(xss['tickets'])
    out['score_penalty'] += xss['score_penalty']

    csrf = _test_csrf(html_content, headers_data)
    out['checks'].extend(csrf['checks'])
    out['tickets'].extend(csrf['tickets'])
    out['score_penalty'] += csrf['score_penalty']

    return out


def _build_test_urls(url, parsed):
    if parsed.query:
        params = [p.split('=')[0] for p in parsed.query.split('&') if '=' in p]
    else:
        params = ['id']
    base_no_query = url.split('?')[0]
    return base_no_query, params


def _test_sql_injection(url, parsed):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    base_no_query, params = _build_test_urls(url, parsed)
    findings = []

    for param in params[:3]:
        for payload in SQLI_PAYLOADS:
            try:
                test_url = f'{base_no_query}?{param}={payload}'
                r = requests.get(test_url, timeout=5, verify=True,
                                 headers={'User-Agent': 'DevShield-Scanner/1.0'})
                body_lower = r.text.lower()
                if any(re.search(sig, body_lower) for sig in SQL_ERROR_SIGNATURES):
                    findings.append((param, payload))
                    break
            except Exception:
                continue

    if findings:
        out['checks'].append({
            'name': '[OWASP-ACTIF] SQL Injection',
            'status': 'fail',
            'severity': 'critical',
            'detail': f'Signature d\'erreur SQL detectee sur : '
                      + ', '.join(f'parametre "{p}"' for p, _ in findings[:3])
        })
        out['score_penalty'] += 25
        for param, payload in findings[:3]:
            out['tickets'].append({
                'title': f'[CRITIQUE] SQL Injection potentielle — parametre "{param}"',
                'description': f'Une erreur SQL est apparue dans la reponse suite a l\'injection '
                               f'd\'un payload sur le parametre "{param}".',
                'severity': 'critical',
                'evidence': EVIDENCE_CONFIRMED,
                'remediation': 'Utiliser des requetes parametrees (prepared statements) pour toutes les requetes SQL.\n'
                               'Exemple Python : cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
                               'Exemple PHP : $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);\n'
                               'Utiliser un ORM (SQLAlchemy, Doctrine) qui parametre automatiquement les requetes.'
            })
    else:
        out['checks'].append({
            'name': '[OWASP-ACTIF] SQL Injection',
            'status': 'pass',
            'severity': 'low',
            'detail': f'Aucune signature d\'erreur SQL detectee sur {len(params[:3])} parametre(s) teste(s). '
                      f'Ne garantit pas l\'absence d\'injection aveugle (blind SQLi).'
        })

    return out


def _test_xss_reflected(url, parsed):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    base_no_query, params = _build_test_urls(url, parsed)
    findings = []

    for param in params[:3]:
        for payload in XSS_PAYLOADS:
            try:
                test_url = f'{base_no_query}?{param}={payload}'
                r = requests.get(test_url, timeout=5, verify=True,
                                 headers={'User-Agent': 'DevShield-Scanner/1.0'})
                if payload in r.text:
                    findings.append(param)
                    break
            except Exception:
                continue

    if findings:
        out['checks'].append({
            'name': '[OWASP-ACTIF] XSS reflechi',
            'status': 'fail',
            'severity': 'high',
            'detail': f'Payload XSS reflete sans echappement sur : '
                      + ', '.join(f'"{p}"' for p in findings[:3])
        })
        out['score_penalty'] += 20
        for param in findings[:3]:
            out['tickets'].append({
                'title': f'[ELEVE] XSS reflechi potentiel — parametre "{param}"',
                'description': f'Un payload de test est renvoye sans echappement HTML sur le parametre '
                               f'"{param}".',
                'severity': 'high',
                'evidence': EVIDENCE_CONFIRMED,
                'remediation': 'Echapper toutes les sorties utilisateur dans le HTML.\n'
                               'Flask/Jinja : utiliser l\'auto-escaping ({{ variable }}) qui est active par defaut.\n'
                               'Pour les sorties non echappees : utiliser |safe UNIQUEMENT si vous etes sur du contenu fiable.\n'
                               'PHP : htmlspecialchars($variable, ENT_QUOTES, "UTF-8")\n'
                               'Ajouter une CSP avec des nonces pour renforcer la protection.'
            })
    else:
        out['checks'].append({
            'name': '[OWASP-ACTIF] XSS reflechi',
            'status': 'pass',
            'severity': 'low',
            'detail': f'Aucun payload reflete sans echappement sur {len(params[:3])} parametre(s) teste(s). '
                      f'Ne couvre pas le XSS stocke ou base DOM.'
        })

    return out


def _test_csrf(html_content, headers_data):
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}

    forms = re.findall(r'<form[^>]*method=["\']?post["\']?[^>]*>(.*?)</form>',
                       html_content, re.IGNORECASE | re.DOTALL)

    if not forms:
        out['checks'].append({
            'name': '[OWASP-ACTIF] Protection CSRF',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Aucun formulaire POST detecte sur la page analysee.'
        })
        return out

    forms_without_token = 0
    for form_html in forms:
        has_token = any(hint in form_html.lower() for hint in CSRF_TOKEN_HINTS)
        if not has_token:
            forms_without_token += 1

    cookie = headers_data.get('Set-Cookie', '')
    samesite_match = re.search(r'samesite=(\w+)', cookie, re.IGNORECASE)
    samesite_protected = bool(samesite_match) and samesite_match.group(1).lower() in ('strict', 'lax')

    if forms_without_token > 0 and not samesite_protected:
        out['checks'].append({
            'name': '[OWASP-ACTIF] Protection CSRF',
            'status': 'fail',
            'severity': 'medium',
            'detail': f'{forms_without_token} formulaire(s) POST sans token CSRF visible, '
                      f'et cookie sans SameSite=Strict/Lax en protection de secours.'
        })
        out['score_penalty'] += 12
        out['tickets'].append({
            'title': '[MOYEN] Protection CSRF absente ou incomplete',
            'description': f'{forms_without_token} formulaire(s) POST ne contiennent pas de champ '
                           f'ressemblant a un token CSRF, et le cookie de session n\'a pas SameSite=Strict/Lax.',
            'severity': 'medium',
            'evidence': EVIDENCE_MISSING_CONTROL,
            'remediation': 'Ajouter une protection CSRF sur tous les formulaires POST.\n'
                           'Flask-WTF : {{ form.csrf_token }} dans le template et app.config[\'WTF_CSRF_ENABLED\'] = True\n'
                           'Django : {%% csrf_token %%} dans le template et django.middleware.csrf.CsrfViewMiddleware\n'
                           'Cookie SameSite : configurer les cookies avec SameSite=Lax ou Strict'
        })
    elif forms_without_token > 0:
        out['checks'].append({
            'name': '[OWASP-ACTIF] Protection CSRF',
            'status': 'warn',
            'severity': 'low',
            'detail': f'{forms_without_token} formulaire(s) sans token visible, mais cookie SameSite '
                      f'protege partiellement contre le CSRF cross-site.'
        })
        out['score_penalty'] += 4
    else:
        out['checks'].append({
            'name': '[OWASP-ACTIF] Protection CSRF',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Tous les formulaires POST testes contiennent un champ ressemblant a un token CSRF.'
        })

    return out


# ============================================================
# SOUS-DOMAINES (DNS ENUMERATION)
# ============================================================

def _check_subdomains(hostname):
    """
    Énumère les sous-domaines courants pour détecter des surfaces d'attaque.
    """
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    
    # Extraire le domaine racine
    parts = hostname.split('.')
    if len(parts) >= 2:
        root_domain = '.'.join(parts[-2:])
    else:
        root_domain = hostname
    
    found_subdomains = []
    
    for sub in COMMON_SUBDOMAINS:
        test_domain = f"{sub}.{root_domain}"
        try:
            socket.gethostbyname(test_domain)
            found_subdomains.append(test_domain)
        except socket.gaierror:
            continue
        except Exception:
            continue
    
    if found_subdomains:
        out['checks'].append({
            'name': '[DNS] Sous-domaines detectes',
            'status': 'warn',
            'severity': 'medium',
            'detail': f"{len(found_subdomains)} sous-domaine(s) trouvé(s) : {', '.join(found_subdomains[:10])}"
        })
        out['score_penalty'] += 5
        
        out['tickets'].append({
            'title': f'{len(found_subdomains)} sous-domaine(s) détecté(s)',
            'description': f"Sous-domaines trouvés : {', '.join(found_subdomains[:10])}. "
                           f"Vérifiez que ces sous-domaines ne sont pas oubliés ou exposés inutilement. "
                           f"Chaque sous-domaine expose une surface d'attaque supplémentaire.",
            'severity': 'medium',
            'evidence': EVIDENCE_CONFIRMED,
            'remediation': 'Passer en revue chaque sous-domaine détecté.\n'
                           '1. Vérifier que chaque sous-domaine est légitime et à jour.\n'
                           '2. Supprimer les sous-domaines non utilisés ou obsolètes.\n'
                           '3. Assurer une configuration de sécurité cohérente sur tous les sous-domaines (HTTPS, headers, etc.).\n'
                           '4. Pour les sous-domaines sensibles (admin, api, etc.), renforcer l\'authentification.'
        })
    else:
        out['checks'].append({
            'name': '[DNS] Sous-domaines detectes',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Aucun sous-domaine courant trouvé pour ce domaine.'
        })
    
    return out


# ============================================================
# PORTS OUVERTS (SCAN TCP)
# ============================================================

def _check_open_ports(hostname):
    """
    Scanne les ports courants pour détecter des services exposés.
    """
    out = {'checks': [], 'tickets': [], 'score_penalty': 0}
    
    open_ports = []
    service_names = {
        21: 'FTP (File Transfer Protocol)',
        22: 'SSH (Secure Shell)',
        23: 'Telnet (non chiffré)',
        25: 'SMTP (Mail)',
        53: 'DNS (Domain Name System)',
        80: 'HTTP',
        110: 'POP3 (Mail)',
        143: 'IMAP (Mail)',
        443: 'HTTPS',
        465: 'SMTPS (Mail sécurisé)',
        587: 'SMTP (Submission)',
        636: 'LDAPS',
        993: 'IMAPS (Mail sécurisé)',
        995: 'POP3S (Mail sécurisé)',
        1433: 'MSSQL (Base de données)',
        3306: 'MySQL (Base de données)',
        3389: 'RDP (Remote Desktop)',
        5432: 'PostgreSQL (Base de données)',
        5900: 'VNC (Remote Desktop)',
        6379: 'Redis (Base de données / Cache)',
        8080: 'HTTP Proxy / Tomcat',
        8443: 'HTTPS Proxy / Tomcat',
        9090: 'Prometheus / Monitoring',
        9200: 'Elasticsearch',
        9300: 'Elasticsearch',
        9999: 'Divers',
        27017: 'MongoDB (Base de données)',
    }
    
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((hostname, port))
            sock.close()
            
            if result == 0:
                service = service_names.get(port, f'Port {port}')
                open_ports.append({
                    'port': port,
                    'service': service
                })
        except Exception:
            continue
    
    if open_ports:
        port_list = ', '.join([f"{p['port']} ({p['service']})" for p in open_ports[:10]])
        out['checks'].append({
            'name': '[Network] Ports ouverts',
            'status': 'warn' if len(open_ports) > 3 else 'pass',
            'severity': 'medium' if any(p['port'] in [21, 22, 23, 3306, 5432, 1433, 6379, 27017] for p in open_ports) else 'low',
            'detail': f"{len(open_ports)} port(s) ouvert(s) : {port_list}"
        })
        
        # Ajouter un ticket si des ports sensibles sont ouverts
        sensitive_ports = [p for p in open_ports if p['port'] in [21, 22, 23, 3306, 5432, 1433, 6379, 27017]]
        if sensitive_ports:
            sensitive_list = ', '.join([f"{p['port']} ({p['service']})" for p in sensitive_ports])
            out['score_penalty'] += 8
            out['tickets'].append({
                'title': f'Ports sensibles ouverts',
                'description': f"Des ports sensibles sont ouverts sur le serveur : {sensitive_list}. "
                               f"Ils peuvent exposer des services à risque.",
                'severity': 'high',
                'evidence': EVIDENCE_CONFIRMED,
                'remediation': 'Fermer les ports inutiles sur le pare-feu / serveur.\n'
                               'UFW : sudo ufw deny <port> (ex: sudo ufw deny 22)\n'
                               'iptables : iptables -A INPUT -p tcp --dport <port> -j DROP\n'
                               'Nginx/Apache : ne pas écouter sur les ports non utilisés.\n'
                               'Vérifier les règles du pare-feu : sudo ufw status\n'
                               'Pour les ports nécessaires, restreindre l\'accès aux IP autorisées.'
            })
        elif len(open_ports) > 5:
            out['score_penalty'] += 4
            out['tickets'].append({
                'title': 'Trop de ports ouverts',
                'description': f"{len(open_ports)} ports ouverts détectés. Plus de ports ouverts = plus de surface d'attaque.",
                'severity': 'medium',
                'evidence': EVIDENCE_CONFIRMED,
                'remediation': 'Fermer les ports inutiles sur le pare-feu / serveur.\n'
                               'UFW : sudo ufw deny <port>\n'
                               'iptables : iptables -A INPUT -p tcp --dport <port> -j DROP\n'
                               'Auditer régulièrement les ports ouverts avec nmap ou netstat.'
            })
    else:
        out['checks'].append({
            'name': '[Network] Ports ouverts',
            'status': 'pass',
            'severity': 'low',
            'detail': 'Aucun port ouvert détecté sur le serveur (ou pare-feu bloquant).'
        })
    
    return out


# ============================================================
# CALCUL CONFORMITE NIS2
# ============================================================

NIS2_CRITERIA = [
    {
        'id': 'nis2_https',
        'label': 'Chiffrement des communications (Art. 21.2.h)',
        'check_names': ['HTTPS active', 'HSTS (Strict-Transport-Security)', '[TLS] Version du protocole'],
        'description': 'Les communications doivent etre protegees par un chiffrement robuste. '
                       'HTTPS, TLS 1.2+ et HSTS constituent des mesures recommandees pour repondre a cet objectif.'
    },
    {
        'id': 'nis2_access',
        'label': 'Controle d\'acces et authentification (Art. 21.2.i)',
        'check_names': ['[OWASP] CORS — controle des origines', '[API] Endpoints sensibles exposes'],
        'description': 'Les APIs et endpoints doivent etre proteges par authentification. CORS correctement configure.'
    },
    {
        'id': 'nis2_data',
        'label': 'Protection des donnees personnelles (Art. 21.2 + RGPD)',
        'check_names': ['[RGPD] Securite des cookies', '[HTML] Fuites d\'information dans le code source'],
        'description': 'Les donnees clients doivent etre protegees conformement au RGPD Art. 32.'
    },
    {
        'id': 'nis2_integrity',
        'label': 'Integrite des systemes (Art. 21.2.e)',
        'check_names': ['Content-Security-Policy (CSP)', 'X-Content-Type-Options', '[OWASP] Permissions-Policy'],
        'description': 'Mesures de reduction du risque d\'injection de contenu malveillant (XSS, clickjacking).'
    },
    {
        'id': 'nis2_config',
        'label': 'Securite de la configuration (Art. 21.2.b)',
        'check_names': ['X-Frame-Options (anti-clickjacking)',
                        'Fuite version serveur (Server / X-Powered-By)',
                        '[Fichiers] Fichiers sensibles exposes'],
        'description': 'Configuration securisee des serveurs, aucun fichier sensible confirme expose.'
    },
    {
        'id': 'nis2_vuln',
        'label': 'Gestion des vulnerabilites (Art. 21.2.e)',
        'check_names': ['[Tech] Fingerprinting technologique', '[TLS] Expiration du certificat'],
        'description': 'Technologies a jour, certificats valides, vulnerabilites connues corrigees.'
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
    if status == 'conforme': return 'Conforme'
    elif status == 'partiel': return 'Partiel'
    else: return 'Non conforme'


def nis2_status_color(status):
    if status == 'conforme': return 'green'
    elif status == 'partiel': return 'orange'
    else: return 'red'