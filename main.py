from flask import Flask, request, jsonify
from flask_cors import CORS  # Importa a liberação de CORS
import re
import smtplib
import dns.resolver
import time

app = Flask(__name__)
CORS(app)  # Isso libera o acesso direto pelo navegador (frontend da Base44)

def validar_unico_email(email_destino):
    email_remetente = "teste@seudominio.com"
    
    # 1. Validação Sintática
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(regex, email_destino):
        return {"status": "invalido", "motivo": "Erro de Sintaxe"}

    dominio = email_destino.split('@')[-1]

    # 2. Busca MX
    try:
        registros_mx = dns.resolver.resolve(dominio, 'MX')
        servidor_mx = str(sorted(registros_mx, key=lambda r: r.preference).exchange)
    except Exception as e:
        return {"status": "invalido", "motivo": "Dominio ou MX nao encontrado"}

    # 3. Handshake SMTP
    try:
        server = smtplib.SMTP(servidor_mx, port=25, timeout=5)
        server.helo()
        server.mail(email_remetente)
        codigo_destino, _ = server.rcpt(email_destino)
        server.quit()

        if codigo_destino == 250:
            return {"status": "valido"}
        else:
            return {"status": "invalido", "motivo": f"Rejeitado (Cod {codigo_destino})"}
    except Exception as e:
        return {"status": "inconclusivo", "motivo": "Erro de conexao SMTP"}

# Rota principal para testes rápidos da IA da Base44
@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "servidor_ativo", "mensagem": "Use a rota /validar-lote via POST"})

# Rota exata que a Base44 vai chamar
@app.route('/validar-lote', methods=['POST'])
def verificar_emails_em_lote():
    dados = request.get_json()
    if not dados:
        return jsonify({"erro": "JSON invalido ou ausente"}), 400
        
    lista_emails = dados.get("emails", [])
    
    resultados = {}
    for email in lista_emails:
        resultados[email] = validar_unico_email(email)
        time.sleep(1.5)  # Pausa de segurança anti-spam
        
    return jsonify(resultados)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
