from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import subprocess
import time

app = Flask(__name__)
CORS(app)

def validar_unico_email(email_destino):
    # 1. Validação Sintática
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(regex, email_destino):
        return {"status": "invalido", "motivo": "Erro de Sintaxe"}

    dominio = str(email_destino.split('@')[-1]).strip()

    # 2. Busca MX usando o comando nativo do Linux
    try:
        resultado_dns = subprocess.check_output(["host", "-t", "MX", dominio], stderr=subprocess.STDOUT, timeout=4).decode()
        if "mail is handled by" not in resultado_dns:
            return {"status": "invalido", "motivo": "Dominio nao possui MX"}
    except Exception:
        return {"status": "invalido", "motivo": "Dominio ou MX nao encontrado"}

    # Se o domínio possui MX válido no Linux do Render, consideramos VÁLIDO!
    # Isso resolve o sumiço da categoria Risco sem quebrar o script com o SMTP bloqueado.
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
        time.sleep(0.5) # Pausa rápida e segura
        
    return jsonify(resultados)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
