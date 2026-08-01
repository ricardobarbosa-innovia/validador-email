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

# Configurar resolver DNS
resolver = dns.resolver.Resolver()
resolver.timeout = DNS_TIMEOUT
resolver.lifetime = DNS_LIFETIME
resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']

# ═══════════════════════════════════════════════════
# BASES DE CONHECIMENTO
# ═══════════════════════════════════════════════════

# Carrega domínios descartáveis do arquivo
DISPOSABLE_DOMAINS = set()
try:
    disposable_file = os.path.join(os.path.dirname(__file__), 'disposable_domains.txt')
    if os.path.exists(disposable_file):
        with open(disposable_file, 'r') as f:
            DISPOSABLE_DOMAINS = set(line.strip().lower() for line in f if line.strip())
except Exception as e:
    print(f"Aviso: não foi possível carregar disposable_domains.txt: {e}")

# Fallback mínimo se arquivo não existir
if not DISPOSABLE_DOMAINS:
    DISPOSABLE_DOMAINS = {
        'mailinator.com', 'guerrillamail.com', '10minutemail.com', 
        'tempmail.com', 'throwaway.email', 'temp-mail.org', 
        'yopmail.com', 'sharklasers.com', 'getnada.com', 
        'maildrop.cc', 'trashmail.com', 'fakeinbox.com',
        'dispostable.com', 'mailnesia.com', 'mintemail.com'
    }

# Provedores gratuitos conhecidos
FREE_PROVIDERS = {
    'gmail.com': 'Google Gmail',
    'googlemail.com': 'Google Gmail',
    'yahoo.com': 'Yahoo',
    'yahoo.com.br': 'Yahoo Brasil',
    'ymail.com': 'Yahoo',
    'outlook.com': 'Microsoft Outlook',
    'hotmail.com': 'Microsoft Hotmail',
    'hotmail.com.br': 'Microsoft Hotmail',
    'live.com': 'Microsoft Live',
    'msn.com': 'Microsoft MSN',
    'aol.com': 'AOL',
    'icloud.com': 'Apple iCloud',
    'me.com': 'Apple Me',
    'mac.com': 'Apple Mac',
    'protonmail.com': 'Proton Mail',
    'proton.me': 'Proton Mail',
    'zoho.com': 'Zoho Mail',
    'yandex.com': 'Yandex',
    'yandex.ru': 'Yandex',
    'gmx.com': 'GMX',
    'gmx.net': 'GMX',
    'mail.com': 'Mail.com',
    'uol.com.br': 'UOL',
    'bol.com.br': 'BOL',
    'terra.com.br': 'Terra',
    'ig.com.br': 'iG',
    'globo.com': 'Globo',
    'globomail.com': 'Globo Mail',
    'r7.com': 'R7',
    'oi.com.br': 'Oi'
}

# Padrões de role accounts
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
    'notifications', 'alert', 'alerts', 'system'
}

# Detecção de provedor pelo hostname MX
MX_PROVIDERS = {
    'google.com': 'Google Workspace',
    'googlemail.com': 'Google Workspace',
    'aspmx.l.google.com': 'Google Workspace',
    'outlook.com': 'Microsoft 365',
    'protection.outlook.com': 'Microsoft 365',
    'mail.protection.outlook.com': 'Microsoft 365',
    'amazonaws.com': 'Amazon SES',
    'amazonses.com': 'Amazon SES',
    'zoho.com': 'Zoho Mail',
    'zohomail.com': 'Zoho Mail',
    'mailgun.org': 'Mailgun',
    'sendgrid.net': 'SendGrid',
    'protonmail.ch': 'Proton Mail',
    'mail.locaweb.com.br': 'Locaweb',
    'locaweb.com.br': 'Locaweb',
    'kinghost.net': 'KingHost',
    'uolhost.com.br': 'UOL Host',
    'hostgator.com': 'HostGator',
    'secureserver.net': 'GoDaddy',
    'registrar-servers.com': 'Namecheap',
    'yandex.net': 'Yandex',
    'mail.ru': 'Mail.ru',
    'mimecast.com': 'Mimecast',
    'barracudanetworks.com': 'Barracuda',
    'proofpoint.com': 'Proofpoint',
    'messagelabs.com': 'Symantec MessageLabs',
    'pphosted.com': 'Proofpoint'
}

# ═══════════════════════════════════════════════════
# FUNÇÕES DE ANÁLISE
# ═══════════════════════════════════════════════════

def validar_sintaxe(email):
    """Validação sintática robusta."""
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
    """Consulta registros MX com cache."""
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
    """Consulta registros TXT com cache."""
    try:
        answers = resolver.resolve(domain, 'TXT')
        return [str(r).strip('"') for r in answers]
    except Exception:
        return []


@lru_cache(maxsize=5000)
def consultar_a(domain):
    """Verifica se o domínio resolve para algum IP."""
    try:
        answers = resolver.resolve(domain, 'A')
        return [str(r) for r in answers]
    except Exception:
        return []


def detectar_provedor_mx(mx_list):
    """Identifica o provedor de e-mail pelo hostname MX."""
    if not mx_list:
        return None
    for mx in mx_list:
        host = mx['host'].lower()
        for pattern, provider in MX_PROVIDERS.items():
            if pattern in host:
                return provider
    return 'Servidor próprio ou não identificado'


def analisar_spf(txt_records):
    """Analisa se há SPF configurado."""
    for record in txt_records:
        if record.lower().startswith('v=spf1'):
            return {'present': True, 'record': record}
    return {'present': False, 'record': None}


def analisar_dmarc(domain):
    """Analisa política DMARC do domínio."""
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
                return {
                    'present': True,
                    'policy': policy,
                    'record': record
                }
    except Exception:
        pass
    return {'present': False, 'policy': None, 'record': None}


def is_disposable(domain):
    """Verifica se o domínio é descartável."""
    return domain.lower() in DISPOSABLE_DOMAINS


def is_free_provider(domain):
    """Verifica se é provedor gratuito."""
    provider = FREE_PROVIDERS.get(domain.lower())
    return {'is_free': provider is not None, 'provider_name': provider}


def is_role_account(local_part):
    """Verifica se é caixa genérica."""
    return local_part.lower() in ROLE_PATTERNS


def detectar_catch_all_heuristica(domain, mx_list):
    """
    Heurística para catch-all (sem SMTP).
    Baseia-se em: provedor conhecido por catch-all + configuração.
    """
    if not mx_list:
        return False
    # Provedores que frequentemente configuram catch-all
    catch_all_indicators = ['secureserver.net', 'registrar-servers.com', 'parkingcrew.net']
    for mx in mx_list:
        for indicator in catch_all_indicators:
            if indicator in mx['host'].lower():
                return True
    return False


def calcular_health_score(dados):
    """Calcula score de saúde do domínio (0-100)."""
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
    
    if dados.get('mx_provider') and dados['mx_provider'] not in ['Servidor próprio ou não identificado', None]:
        score += 5
    
    return max(0, min(100, score))


# ═══════════════════════════════════════════════════
# ANÁLISE COMPLETA
# ═══════════════════════════════════════════════════

def analisar_email(email):
    """Análise completa de um único e-mail."""
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
        'spf_present': False,
        'spf_record': None,
        'dmarc_present': False,
        'dmarc_policy': None,
        'dmarc_record': None,
        'disposable': False,
        'free_provider': False,
        'free_provider_name': None,
        'role_based': False,
        'catch_all': False,
        'health_score': 0,
        'processing_time_ms': 0
    }
    
    # 1. Sintaxe
    if not validar_sintaxe(email):
        resultado['processing_time_ms'] = int((time.time() - inicio) * 1000)
        return resultado
    
    resultado['syntax_valid'] = True
    local, domain = email.rsplit('@', 1)
    resultado['local_part'] = local
    resultado['domain'] = domain
    
    # 2. Verificações paralelas
    with ThreadPoolExecutor(max_workers=4) as executor:
        futuro_mx = executor.submit(consultar_mx, domain)
        futuro_txt = executor.submit(consultar_txt, domain)
        futuro_dmarc = executor.submit(analisar_dmarc, domain)
        futuro_a = executor.submit(consultar_a, domain)
        
        mx_list = futuro_mx.result()
        txt_records = futuro_txt.result()
        dmarc = futuro_dmarc.result()
        a_records = futuro_a.result()
    
    # 3. Consolidar
    resultado['domain_exists'] = bool(a_records) or bool(mx_list)
    resultado['mx_found'] = len(mx_list) > 0
    resultado['mx_records'] = mx_list[:5]
    resultado['mx_provider'] = detectar_provedor_mx(mx_list)
    
    spf = analisar_spf(txt_records)
    resultado['spf_present'] = spf['present']
    resultado['spf_record'] = spf['record']
    
    resultado['dmarc_present'] = dmarc['present']
    resultado['dmarc_policy'] = dmarc['policy']
    resultado['dmarc_record'] = dmarc['record']
    
    resultado['disposable'] = is_disposable(domain)
    
    free = is_free_provider(domain)
    resultado['free_provider'] = free['is_free']
    resultado['free_provider_name'] = free['provider_name']
    
    resultado['role_based'] = is_role_account(local)
    resultado['catch_all'] = detectar_catch_all_heuristica(domain, mx_list)
    
    resultado['health_score'] = calcular_health_score(resultado)
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
        'version': '2.0',
        'endpoints': {
            'GET /': 'Status',
            'POST /validate': 'Validar um único e-mail',
            'POST /validate/batch': 'Validar múltiplos e-mails',
            'GET /domain/<domain>': 'Analisar apenas um domínio'
        }
    })


@app.route('/validate', methods=['POST'])
def validate_single():
    """Valida um único e-mail com análise completa."""
    dados = request.get_json()
    if not dados or 'email' not in dados:
        return jsonify({'error': 'Campo "email" obrigatório'}), 400
    
    resultado = analisar_email(dados['email'])
    return jsonify(resultado)


@app.route('/validate/batch', methods=['POST'])
def validate_batch():
    """Valida múltiplos e-mails com processamento paralelo."""
    dados = request.get_json()
    if not dados or 'emails' not in dados:
        return jsonify({'error': 'Campo "emails" obrigatório'}), 400
    
    emails = dados['emails']
    if not isinstance(emails, list):
        return jsonify({'error': 'Campo "emails" deve ser uma lista'}), 400
    
    if len(emails) > 100:
        return jsonify({'error': 'Máximo 100 e-mails por requisição'}), 400
    
    resultados = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futuros = {executor.submit(analisar_email, email): email for email in emails}
        for futuro in as_completed(futuros):
            resultados.append(futuro.result())
    
    return jsonify({
        'total': len(resultados),
        'results': resultados
    })


@app.route('/domain/<domain>', methods=['GET'])
def analyze_domain(domain):
    """Analisa apenas um domínio (sem e-mail)."""
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
    
    resultado = {
        'domain': domain,
        'domain_exists': bool(a_records) or bool(mx_list),
        'mx_found': len(mx_list) > 0,
        'mx_records': mx_list[:5],
        'mx_provider': detectar_provedor_mx(mx_list),
        'spf_present': spf['present'],
        'spf_record': spf['record'],
        'dmarc_present': dmarc['present'],
        'dmarc_policy': dmarc['policy'],
        'disposable': is_disposable(domain),
        'free_provider': free['is_free'],
        'free_provider_name': free['provider_name'],
        'catch_all': detectar_catch_all_heuristica(domain, mx_list),
        'processing_time_ms': int((time.time() - inicio) * 1000)
    }
    resultado['health_score'] = calcular_health_score(resultado)
    
    return jsonify(resultado)


# Manter endpoint antigo pra compatibilidade
@app.route('/validar-lote', methods=['POST'])
def validar_lote_legado():
    """Endpoint legado - redireciona para novo formato."""
    dados = request.get_json()
    if not dados:
        return jsonify({'erro': 'JSON invalido'}), 400
    
    lista_emails = dados.get('emails', [])
    resultados = {}
    
    for email in lista_emails:
        analise = analisar_email(email)
        if analise['syntax_valid'] and analise['mx_found']:
            if analise['disposable']:
                resultados[email] = {'status': 'invalido', 'motivo': 'Dominio descartavel'}
            elif analise['health_score'] >= 65:
                resultados[email] = {'status': 'valido'}
            else:
                resultados[email] = {'status': 'risco', 'motivo': 'Baixa qualidade'}
        else:
            resultados[email] = {'status': 'invalido', 'motivo': 'MX nao encontrado ou sintaxe invalida'}
    
    return jsonify(resultados)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
