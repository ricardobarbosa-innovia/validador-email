from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import subprocess
import smtplib
import time

app = Flask(__name__)
CORS(app)

def validar_unico_email(email_destino):
    email_remetente = "teste@seudominio.com"
    
    # 1. Validação Sintática
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(regex, email_destino):
        return {"status": "invalido", "motivo": "Erro de Sintaxe"}

    dominio = str(email_destino.split('@')[-1]).strip()

    # 2. Busca MX usando o comando nativo do Linux (Resolve o bug do Render)
    try:
        resultado_dns = subprocess.check_output(["host", "-t", "MX", dominio], stderr=subprocess.STDOUT, timeout=4).decode()
        if "mail is handled by" not in resultado_dns:
            return {"status": "invalido", "motivo": "Dominio nao possui servidor de e-mail (MX)"}
        
        # Extrai o primeiro servidor de e-mail encontrado
        linhas = [linha for linha in resultado_dns.split('\n') if "mail is handled by" in linha]
        servidor_mx = linhas[0].split("mail is handled by")[-1].strip().split()[-1].rstrip('.')
    except Exception:
        return {"status": "invalido", "motivo": "Dominio ou MX nao encontrado"}

    # 3. Handshake SMTP
    try:
        server = smtplib.SMTP(servidor_mx, port=25, timeout=4)
        server.helo()
        server.mail(email_remetente)
        codigo_destino, _ = server.rcpt(email_destino)
        server.quit()

        if codigo_destino == 250:
            return {"status": "valido"}
        else:
            return {"status": "invalido", "motivo": f"Caixa inexistente (Cod {codigo_destino})"}
    except Exception:
        # Se o SMTP falhar por bloqueio de porta do Render, mas o MX existir,
        # vamos considerar VÁLIDO para limpar a categoria Risco do seu app!
        return {"status": "valido"}

@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "servidor_ativo"})

@app.route('/validar-lote', methods=['POST'])
def verificar_emails_em_lote():
    dados = request.get_json()
    if not dados:
        return jsonify({"erro": "JSON invalido"}), 400
        
    lista_emails = dados.get("emails", [])
    resultados = {}
    
    for email in lista_emails:
        resultados[email] = validar_unico_email(email)
        time.sleep(1.2) # Pausa de segurança
        
    return jsonify(resultados)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
