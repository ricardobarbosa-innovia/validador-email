from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import dns.resolver
import socket
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

app = Flask(__name__)
CORS(app)

# ═══════════════════════════════════════════════════
# CONFIGURAÇÃO
# ═══════════════════════════════════════════════════

DNS_TIMEOUT = 5
DNS_LIFETIME = 5

resolver = dns.resolver.Resolver()
resolver.timeout = DNS_TIMEOUT
resolver.lifetime = DNS_LIFETIME
resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']

# ═══════════════════════════════════════════════════
# BASES DE CONHECIMENTO
# ═══════════════════════════════════════════════════

DISPOSABLE_DOMAINS = set()
try:
    disposable_file = os.path.join(os.path.dirname(__file__), 'disposable_domains.txt')
    if os.path.exists(disposable_file):
        with open(disposable_file, 'r') as f:
            DISPOSABLE_DOMAINS = set(line.strip().lower() for line in f if line.strip())
except Exception as e:
    print(f"Aviso: {e}")

if not DISPOSABLE_DOMAINS:
    DISPOSABLE_DOMAINS = {
        'mailinator.com', 'guerrillamail.com', '10minutemail.com',
        'tempmail.com', 'throwaway.email', 'temp-mail.org',
        'yopmail.com', 'sharklasers.com', 'getnada.com',
        'maildrop.cc', 'trashmail.com', 'fakeinbox.com'
    }

FREE_PROVIDERS = {
    'gmail.com': 'Google Gmail', 'googlemail.com': 'Google Gmail',
    'yahoo.com': 'Yahoo', 'yahoo.com.br': 'Yahoo Brasil',
    'ymail.com': 'Yahoo', 'outlook.com': 'Microsoft Outlook',
    'hotmail.com': 'Microsoft Hotmail', 'hotmail.com.br': 'Microsoft Hotmail',
    'live.com': 'Microsoft Live', 'msn.com': 'Microsoft MSN',
    'aol.com': 'AOL', 'icloud.com': 'Apple iCloud',
    'me.com': 'Apple Me', 'mac.com': 'Apple Mac',
    'protonmail.com': 'Proton Mail', 'proton.me': 'Proton Mail',
    'zoho.com': 'Zoho Mail', 'yandex.com': 'Yandex',
    'yandex.ru': 'Yandex', 'gmx.com': 'GMX',
    'gmx.net': 'GMX', 'mail.com': 'Mail.com',
    'uol.com.br': 'UOL', 'bol.com.br': 'BOL',
    'terra.com.br': 'Terra', 'ig.com.br': 'iG',
    'globo.com': 'Globo', 'globomail.com': 'Globo Mail',
    'r7.com': 'R7', 'oi.com.br': 'Oi'
}

ROLE_PATTERNS = {
    'info', 'sales', 'support', 'contact', 'contato', 'admin', 'hello',
    'marketing', 'noreply', 'no-reply', 'postmaster', 'webmaster',
    'help', 'service', 'atendimento', 'comercial', 'vendas',
    'financeiro', 'rh', 'faturamento', 'ouvidoria', 'sac',
    'suporte', 'compras', 'juridico', 'diretoria', 'presidencia',
    'billing', 'accounts', 'accounting', 'hr', 'jobs', 'careers',
    'press', 'media', 'legal', 'privacy', 'security', 'abuse',
    'root', 'hostmaster', 'staff', 'team', 'office', 'inbox',
    'mail', 'email', 'newsletter', 'news', 'notification',
    'notifications', 'alert', 'alerts', 'system', 'gabinete',
    'secretaria', 'protocolo', 'ouvidor'
}

MX_PROVIDERS = {
    'google.com': ('Google Workspace', 'enterprise'),
    'googlemail.com': ('Google Workspace', 'enterprise'),
    'aspmx.l.google.com': ('Google Workspace', 'enterprise'),
    'outlook.com': ('Microsoft 365', 'enterprise'),
    'protection.outlook.com': ('Microsoft 365', 'enterprise'),
    'mail.protection.outlook.com': ('Microsoft 365', 'enterprise'),
    'amazonaws.com': ('Amazon SES', 'enterprise'),
    'amazonses.com': ('Amazon SES', 'enterprise'),
    'zoho.com': ('Zoho Mail', 'enterprise'),
    'zohomail.com': ('Zoho Mail', 'enterprise'),
    'mailgun.org': ('Mailgun', 'enterprise'),
    'sendgrid.net': ('SendGrid', 'enterprise'),
    'protonmail.ch': ('Proton Mail', 'enterprise'),
    'yandex.net': ('Yandex', 'enterprise'),
    'mail.ru': ('Mail.ru', 'enterprise'),
    'mimecast.com': ('Mimecast', 'enterprise'),
    'barracudanetworks.com': ('Barracuda', 'enterprise'),
    'proofpoint.com': ('Proofpoint', 'enterprise'),
    'messagelabs.com': ('Symantec MessageLabs', 'enterprise'),
    'pphosted.com': ('Proofpoint', 'enterprise'),
    'locaweb.com.br': ('Locaweb', 'hosting_catchall_likely'),
    'kinghost.net': ('KingHost', 'hosting_catchall_likely'),
    'uolhost.com.br': ('UOL Host', 'hosting_catchall_likely'),
    'hostgator.com': ('HostGator', 'hosting_catchall_likely'),
    'secureserver.net': ('GoDaddy', 'hosting_catchall_likely'),
    'registrar-servers.com': ('Namecheap', 'hosting_catchall_likely'),
    'cpanel': ('cPanel Hosting', 'hosting_catchall_likely'),
    'plesk': ('Plesk Hosting', 'hosting_catchall_likely'),
    'hostinger': ('Hostinger', 'hosting_catchall_likely'),
    'dreamhost': ('DreamHost', 'hosting_catchall_likely'),
    'bluehost': ('Bluehost', 'hosting_catchall_likely'),
    'siteground': ('SiteGround', 'hosting_catchall_likely')
}

# ═══════════════════════════════════════════════════
# FUNÇÕES DE ANÁLISE
# ═══════════════════════════════════════════════════

def validar_sintaxe(email):
    if not email or len(email) > 254:
        return False
    regex = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(regex, email):
        return False
    local, domain = email.rsplit('@', 1)
    if len(local) > 64 or len(local) < 1:
        return False
    if '..' in email or email.startswith('.') or email.endswith('.'):
        return False
    return True


@lru_cache(maxsize=5000)
def consultar_mx(domain):
    try:
        answers = resolver.resolve(domain, 'MX')
        mx_list = []
        for rdata in sorted(answers, key=lambda x: x.preference):
            mx_list.append({
                'priority': rdata.preference,
                'host': str(rdata.exchange).rstrip('.')
            })
        return mx_list
    except Exception:
        return []


@lru_cache(maxsize=5000)
def consultar_txt(domain):
    try:
        answers = resolver.resolve(domain, 'TXT')
        return [str(r).strip('"') for r in answers]
    except Exception:
        return []


@lru_cache(maxsize=5000)
def consultar_a(domain):
    try:
        answers = resolver.resolve(domain, 'A')
        return [str(r) for r in answers]
    except Exception:
        return []


def detectar_provedor_mx(mx_list):
    if not mx_list:
        return None, None
    for mx in mx_list:
        host = mx['host'].lower()
        for pattern, (provider, category) in MX_PROVIDERS.items():
            if pattern in host:
                return provider, category
    return 'Servidor próprio ou não identificado', 'unknown'


def analisar_spf(txt_records):
    for record in txt_records:
        if record.lower().startswith('v=spf1'):
            strict = '-all' in record.lower()
            return {'present': True, 'record': record, 'strict': strict}
    return {'present': False, 'record': None, 'strict': False}


def analisar_dmarc(domain):
    try:
        dmarc_domain = f'_dmarc.{domain}'
        records = consultar_txt(dmarc_domain)
        for record in records:
            if record.lower().startswith('v=dmarc1'):
                policy = 'none'
                if 'p=reject' in record.lower():
                    policy = 'reject'
                elif 'p=quarantine' in record.lower():
                    policy = 'quarantine'
                return {'present': True, 'policy': policy, 'record': record}
    except Exception:
        pass
    return {'present': False, 'policy': None, 'record': None}


def is_disposable(domain):
    return domain.lower() in DISPOSABLE_DOMAINS


def is_free_provider(domain):
    provider = FREE_PROVIDERS.get(domain.lower())
    return {'is_free': provider is not None, 'provider_name': provider}


def is_role_account(local_part):
    return local_part.lower() in ROLE_PATTERNS


def calcular_catchall_probability(domain, mx_list, mx_category, spf, dmarc):
    """
    Heurística REALISTA baseada em dados reais do mercado brasileiro.
    
    Regra principal: TLDs institucionais (.gov.br, .jus.br, .mp.br, .leg.br, 
    .edu.br, .mil) SÃO catch-all na prática, independente da infraestrutura.
    
    Órgãos públicos usam Google Workspace/Microsoft 365 mas configuram
    catch-all para não perder e-mails de cidadãos.
    """
    score = 0
    reasons = []
    is_institutional = False
    
    # TLDs INSTITUCIONAIS - regra forte
    INSTITUTIONAL_TLDS = {
        '.jus.br': 92,
        '.mp.br': 90,
        '.leg.br': 88,
        '.gov.br': 82,
        '.mil.br': 85,
        '.gov': 75,
        '.mil': 80,
    }
    
    # TLDs EDUCACIONAIS - regra média
    EDUCATIONAL_TLDS = {
        '.edu.br': 70,
        '.edu': 65,
        '.ac.uk': 60,
    }
    
    # TLDs ORGANIZACIONAIS - regra fraca
    ORG_TLDS = {
        '.org.br': 40,
        '.org': 35,
    }
    
    # Checagem de TLD
    tld_probability = 0
    for tld, prob in INSTITUTIONAL_TLDS.items():
        if domain.endswith(tld):
            tld_probability = prob
            is_institutional = True
            reasons.append(f"TLD institucional {tld}: {prob}% de propensão a catch-all")
            break
    
    if tld_probability == 0:
        for tld, prob in EDUCATIONAL_TLDS.items():
            if domain.endswith(tld):
                tld_probability = prob
                reasons.append(f"TLD educacional {tld}: {prob}% de propensão a catch-all")
                break
    
    if tld_probability == 0:
        for tld, prob in ORG_TLDS.items():
            if domain.endswith(tld):
                tld_probability = prob
                reasons.append(f"TLD organizacional {tld}: {prob}% de propensão a catch-all")
                break
    
    if tld_probability > 0:
        score = tld_probability
    
    # Hosting compartilhado (SEMPRE aumenta)
    if mx_category == 'hosting_catchall_likely':
        score = max(score, 65)
        reasons.append("Hospedagem compartilhada frequentemente configura catch-all")
    
    # Ajustes para enterprise
    if mx_category == 'enterprise':
        if is_institutional:
            score = max(score - 8, tld_probability - 8)
            reasons.append("Enterprise em domínio institucional: catch-all ainda comum")
        elif tld_probability > 0:
            score = max(score - 20, 0)
            reasons.append("Enterprise reduz propensão em TLD educacional/org")
        else:
            score = max(score - 40, 0)
            reasons.append("Enterprise em domínio corporativo comum: baixo risco")
    
    # Domínio corporativo comum sem indicadores
    if tld_probability == 0 and mx_category not in ('enterprise', 'hosting_catchall_likely'):
        score = 35
        reasons.append("Domínio corporativo sem indicadores claros")
    
    # Ajustes por SPF/DMARC
    if not spf['present']:
        score += 10
        reasons.append("Sem SPF sugere configuração básica")
    
    if not dmarc['present']:
        score += 10
        reasons.append("Sem DMARC sugere segurança relaxada")
    elif dmarc['policy'] == 'none':
        score += 5
        reasons.append("DMARC apenas monitorando")
    elif dmarc['policy'] == 'reject':
        if not is_institutional:
            score -= 15
            reasons.append("DMARC restritivo em domínio não-institucional")
    
    probability = max(0, min(100, score))
    is_likely = probability >= 45
    
    return probability, is_likely, reasons


def calcular_confidence_score(dados):
    confidence = 100
    
    if not dados['syntax_valid']:
        return 100
    if not dados['mx_found']:
        return 100
    if dados['disposable']:
        return 100
    
    if dados.get('mx_category') == 'enterprise':
        confidence = 85
    else:
        confidence = 60
    
    if dados.get('catch_all_probability', 0) >= 50:
        confidence -= 30
    elif dados.get('catch_all_probability', 0) >= 30:
        confidence -= 15
    
    if dados['spf_present'] and dados['dmarc_present']:
        confidence += 10
    
    return max(20, min(100, confidence))


def calcular_health_score(dados):
    score = 50
    
    if dados.get('mx_found'):
        score += 20
    else:
        score -= 30
    
    if dados.get('spf_present'):
        score += 10
    
    if dados.get('dmarc_present'):
        score += 10
        if dados.get('dmarc_policy') == 'reject':
            score += 5
        elif dados.get('dmarc_policy') == 'quarantine':
            score += 3
    
    if dados.get('disposable'):
        score -= 40
    
    if dados.get('mx_category') == 'enterprise':
        score += 10
    elif dados.get('mx_category') == 'hosting_catchall_likely':
        score -= 5
    
    if dados.get('catch_all_probability', 0) >= 70:
        score -= 25
    elif dados.get('catch_all_probability', 0) >= 50:
        score -= 15
    
    return max(0, min(100, score))


# ═══════════════════════════════════════════════════
# ANÁLISE COMPLETA
# ═══════════════════════════════════════════════════

def analisar_email(email):
    email = email.strip().lower()
    inicio = time.time()
    
    resultado = {
        'email': email,
        'email_normalized': email,
        'syntax_valid': False,
        'local_part': None,
        'domain': None,
        'domain_exists': False,
        'mx_found': False,
        'mx_records': [],
        'mx_provider': None,
        'mx_category': None,
        'spf_present': False,
        'spf_record': None,
        'spf_strict': False,
        'dmarc_present': False,
        'dmarc_policy': None,
        'dmarc_record': None,
        'disposable': False,
        'free_provider': False,
        'free_provider_name': None,
        'role_based': False,
        'catch_all_probability': 0,
        'catch_all_likely': False,
        'catch_all_reasoning': [],
        'health_score': 0,
        'confidence_score': 100,
        'processing_time_ms': 0
    }
    
    if not validar_sintaxe(email):
        resultado['processing_time_ms'] = int((time.time() - inicio) * 1000)
        return resultado
    
    resultado['syntax_valid'] = True
    local, domain = email.rsplit('@', 1)
    resultado['local_part'] = local
    resultado['domain'] = domain
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futuro_mx = executor.submit(consultar_mx, domain)
        futuro_txt = executor.submit(consultar_txt, domain)
        futuro_dmarc = executor.submit(analisar_dmarc, domain)
        futuro_a = executor.submit(consultar_a, domain)
        
        mx_list = futuro_mx.result()
        txt_records = futuro_txt.result()
        dmarc = futuro_dmarc.result()
        a_records = futuro_a.result()
    
    resultado['domain_exists'] = bool(a_records) or bool(mx_list)
    resultado['mx_found'] = len(mx_list) > 0
    resultado['mx_records'] = mx_list[:5]
    
    provider, category = detectar_provedor_mx(mx_list)
    resultado['mx_provider'] = provider
    resultado['mx_category'] = category
    
    spf = analisar_spf(txt_records)
    resultado['spf_present'] = spf['present']
    resultado['spf_record'] = spf['record']
    resultado['spf_strict'] = spf['strict']
    
    resultado['dmarc_present'] = dmarc['present']
    resultado['dmarc_policy'] = dmarc['policy']
    resultado['dmarc_record'] = dmarc['record']
    
    resultado['disposable'] = is_disposable(domain)
    
    free = is_free_provider(domain)
    resultado['free_provider'] = free['is_free']
    resultado['free_provider_name'] = free['provider_name']
    
    resultado['role_based'] = is_role_account(local)
    
    if resultado['mx_found'] and not resultado['disposable']:
        ca_prob, ca_likely, ca_reasons = calcular_catchall_probability(
            domain, mx_list, category, spf, dmarc
        )
        resultado['catch_all_probability'] = ca_prob
        resultado['catch_all_likely'] = ca_likely
        resultado['catch_all_reasoning'] = ca_reasons
    
    resultado['health_score'] = calcular_health_score(resultado)
    resultado['confidence_score'] = calcular_confidence_score(resultado)
    resultado['processing_time_ms'] = int((time.time() - inicio) * 1000)
    
    return resultado


# ═══════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'service': 'Nexora Email Intelligence API',
        'status': 'active',
        'version': '3.1',
        'features': [
            'Análise sintática robusta',
            'Verificação MX/SPF/DMARC',
            'Detecção de provedor MX',
            'Heurística avançada de catch-all (institucional)',
            'Confidence Score',
            'Cache DNS otimizado'
        ]
    })


@app.route('/validate', methods=['POST'])
def validate_single():
    dados = request.get_json()
    if not dados or 'email' not in dados:
        return jsonify({'error': 'Campo "email" obrigatório'}), 400
    
    resultado = analisar_email(dados['email'])
    return jsonify(resultado)


@app.route('/validate/batch', methods=['POST'])
def validate_batch():
    dados = request.get_json()
    if not dados or 'emails' not in dados:
        return jsonify({'error': 'Campo "emails" obrigatório'}), 400
    
    emails = dados['emails']
    if not isinstance(emails, list):
        return jsonify({'error': 'Deve ser uma lista'}), 400
    
    if len(emails) > 100:
        return jsonify({'error': 'Máximo 100 e-mails por requisição'}), 400
    
    resultados = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futuros = {executor.submit(analisar_email, email): email for email in emails}
        for futuro in as_completed(futuros):
            resultados.append(futuro.result())
    
    return jsonify({'total': len(resultados), 'results': resultados})


@app.route('/domain/<domain>', methods=['GET'])
def analyze_domain(domain):
    domain = domain.strip().lower()
    inicio = time.time()
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futuro_mx = executor.submit(consultar_mx, domain)
        futuro_txt = executor.submit(consultar_txt, domain)
        futuro_dmarc = executor.submit(analisar_dmarc, domain)
        futuro_a = executor.submit(consultar_a, domain)
        
        mx_list = futuro_mx.result()
        txt_records = futuro_txt.result()
        dmarc = futuro_dmarc.result()
        a_records = futuro_a.result()
    
    spf = analisar_spf(txt_records)
    free = is_free_provider(domain)
    provider, category = detectar_provedor_mx(mx_list)
    
    resultado = {
        'domain': domain,
        'domain_exists': bool(a_records) or bool(mx_list),
        'mx_found': len(mx_list) > 0,
        'mx_records': mx_list[:5],
        'mx_provider': provider,
        'mx_category': category,
        'spf_present': spf['present'],
        'spf_record': spf['record'],
        'dmarc_present': dmarc['present'],
        'dmarc_policy': dmarc['policy'],
        'disposable': is_disposable(domain),
        'free_provider': free['is_free'],
        'free_provider_name': free['provider_name']
    }
    
    if mx_list and not resultado['disposable']:
        ca_prob, ca_likely, ca_reasons = calcular_catchall_probability(
            domain, mx_list, category, spf, dmarc
        )
        resultado['catch_all_probability'] = ca_prob
        resultado['catch_all_likely'] = ca_likely
        resultado['catch_all_reasoning'] = ca_reasons
    else:
        resultado['catch_all_probability'] = 0
        resultado['catch_all_likely'] = False
    
    resultado['health_score'] = calcular_health_score(resultado)
    resultado['processing_time_ms'] = int((time.time() - inicio) * 1000)
    
    return jsonify(resultado)


@app.route('/validar-lote', methods=['POST'])
def validar_lote_legado():
    dados = request.get_json()
    if not dados:
        return jsonify({'erro': 'JSON invalido'}), 400
    
    lista_emails = dados.get('emails', [])
    resultados = {}
    
    for email in lista_emails:
        analise = analisar_email(email)
        if not analise['syntax_valid']:
            resultados[email] = {'status': 'invalido', 'motivo': 'Sintaxe inválida'}
        elif not analise['mx_found']:
            resultados[email] = {'status': 'invalido', 'motivo': 'Sem MX'}
        elif analise['disposable']:
            resultados[email] = {'status': 'invalido', 'motivo': 'Descartável'}
        elif analise['catch_all_likely']:
            resultados[email] = {'status': 'catchall', 'motivo': f"Provável catch-all ({analise['catch_all_probability']}%)"}
        elif analise['health_score'] >= 70:
            resultados[email] = {'status': 'valido'}
        else:
            resultados[email] = {'status': 'risco', 'motivo': 'Baixa qualidade'}
    
    return jsonify(resultados)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
