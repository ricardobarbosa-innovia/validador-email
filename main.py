from flask import Flask, request, jsonify
import re
import smtplib
import dns.resolver

app = Flask(__name__)

@app.route('/validar', methods=['POST'])
def verificar_email_smtp():
    dados = request.get_json()
    email_destino = dados.get("email")
    email_remetente = "teste@seudominio.com"

    # 1. Validação Sintática
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(regex, email_destino):
        return jsonify({"status": "invalido", "motivo": "Erro de Sintaxe"})

    dominio = email_destino.split('@')[1]

    # 2. Busca MX
    try:
        registros_mx = dns.resolver.resolve(dominio, 'MX')
        servidor_mx = str(sorted(registros_mx, key=lambda r: r.preference).exchange)
    except Exception as e:
        return jsonify({"status": "invalido", "motivo": "Dominio ou MX nao encontrado"})

    # 3. Handshake SMTP
    try:
        server = smtplib.SMTP(servidor_mx, port=25, timeout=7)
        server.helo()
        server.mail(email_remetente)
        codigo_destino, _ = server.rcpt(email_destino)
        server.quit()

        if codigo_destino == 250:
            return jsonify({"status": "valido"})
        else:
            return jsonify({"status": "invalido", "motivo": f"Rejeitado pelo servidor (Código {codigo_destino})"})
    except Exception as e:
        return jsonify({"status": "inconclusivo", "motivo": f"Erro de conexao SMTP: {str(e)}"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
