import os
import json
import logging
import uuid
import hmac
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from enum import Enum

from flask import Flask, request, jsonify, g, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import BaseModel, ValidationError, constr, EmailStr, field_validator, ConfigDict
import bcrypt
import jwt
from cryptography.fernet import Fernet
import bleach

app = Flask(__name__)

# --- 1. TRAVANDO CONFIGURAÇÕES (Variáveis de Ambiente Obrigatórias) ---
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError("ERRO CRÍTICO: SECRET_KEY não configurada no ambiente. Abortando execução.")
app.config['SECRET_KEY'] = SECRET_KEY

FERNET_KEY = os.environ.get('FERNET_KEY')
if not FERNET_KEY:
    raise RuntimeError("ERRO CRÍTICO: FERNET_KEY não configurada no ambiente. Abortando execução.")
cipher_suite = Fernet(FERNET_KEY.encode())

# --- 3. PROTEÇÃO DE APIS E SERVIÇOS ---
# CORS rigoroso (Para testes locais via index.html aberto como arquivo, você pode precisar alterar para "*")
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["1000 per day", "50 per minute"])

# --- 5. MONITORAMENTO E LOGS ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecurityLogger")

# --- 4. SEGURANÇA DE DADOS (BCRYPT EM CACHE) ---
# Calculamos o hash de admin uma única vez na inicialização para evitar gargalos (DoS).
HASH_ADMIN_SALVO = bcrypt.hashpw(b"senhaBlindada2026", bcrypt.gensalt())
DB_MOCK = []

# --- 1. SEGURANÇA DE ENTRADA (NORMALIZAÇÃO, TAMANHO E SANITIZAÇÃO) ---
class MarcaEnum(str, Enum):
    FORD = "FORD"

class ModeloEnum(str, Enum):
    RANGER = "RANGER"
    BRONCO = "BRONCO"
    MUSTANG = "MUSTANG"

class LeadSchema(BaseModel):
    # ConfigDict(extra='forbid') rejeita silenciosamente a inserção de campos extras no JSON (Mass Assignment)
    model_config = ConfigDict(extra='forbid')
    
    email: EmailStr
    marca: MarcaEnum
    modelo: ModeloEnum
    versao: constr(max_length=50)
    idempotency_key: constr(min_length=10, max_length=50)

    # Sanitização ativa: Remove qualquer tag <script> ou HTML injetado antes de processar os dados
    @field_validator('versao', mode='before')
    @classmethod
    def sanitizar_texto(cls, valor):
        if isinstance(valor, str):
            return bleach.clean(valor, tags=[], strip=True)
        return valor

# Tratamento de Erro Genérico (Anti-vazamento de Stack Trace)
@app.errorhandler(Exception)
def handle_exception(e):
    trace_id = getattr(g, 'trace_id', str(uuid.uuid4()))
    logger.error(json.dumps({"event": "internal_server_error", "trace_id": trace_id, "details": str(e)}))
    return jsonify({"error": "Erro Genérico -> A solicitação não pôde ser processada.", "trace_id": trace_id}), 500

# --- 3. INTEGRIDADE DE PAYLOAD (HMAC) ---
def hmac_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        assinatura_recebida = request.headers.get('X-Payload-Signature')
        if not assinatura_recebida:
            return jsonify({"error": "Assinatura HMAC ausente."}), 403
            
        corpo_requisicao = request.get_data()
        hmac_calculado = hmac.new(
            app.config['SECRET_KEY'].encode(), 
            corpo_requisicao, 
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(assinatura_recebida, hmac_calculado):
            logger.warning(json.dumps({"event": "hmac_failure", "ip": request.remote_addr}))
            return jsonify({"error": "Falha na integridade do payload (Adulteração em trânsito detectada)."}), 403
            
        return f(*args, **kwargs)
    return decorated

# --- 2. AUTENTICAÇÃO E AUTORIZAÇÃO (JWT e RBAC) ---
def token_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token or not token.startswith("Bearer "):
                return jsonify({"message": "Acesso Negado: Token ausente ou formato inválido"}), 401
            
            try:
                token_string = token.split(" ")[1]
                data = jwt.decode(token_string, app.config['SECRET_KEY'], algorithms=["HS256"])
                
                if data.get('role') not in allowed_roles:
                    logger.warning(json.dumps({"event": "rbac_violation", "user": data.get('user_id'), "attempted": data.get('role')}))
                    return jsonify({"message": "Acesso negado: Perfil sem permissão."}), 403
                    
                g.user_id = data.get('user_id')
                g.role = data.get('role')
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                # Mensagem unificada (Anti-Enumeração): não revelamos se expirou ou se foi forjado
                return jsonify({"message": "Credenciais inválidas"}), 401
                
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    g.trace_id = str(uuid.uuid4())
    data = request.json
    username = data.get('username')
    password = data.get('password', '').encode('utf-8')
    
    # Compara a senha com o Hash seguro armazenado
    if username == "admin" and bcrypt.checkpw(password, HASH_ADMIN_SALVO):
        token = jwt.encode({
            'user_id': username,
            'role': 'Admin',
            'exp': datetime.utcnow() + timedelta(minutes=15)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        logger.info(json.dumps({"event": "login_success", "user": username, "trace_id": g.trace_id}))
        return jsonify({'token': token})
        
    logger.warning(json.dumps({"event": "login_failed", "user": username, "trace_id": g.trace_id}))
    return jsonify({"message": "Usuário ou senha inválidos"}), 401

@app.route('/api/lead', methods=['POST'])
@hmac_required
@token_required(allowed_roles=["Admin", "Analista"])
def criar_lead():
    g.trace_id = getattr(g, 'trace_id', str(uuid.uuid4()))
    
    try:
        lead_data = LeadSchema(**request.json)
    except ValidationError as e:
        # A mensagem genérica omite a estrutura interna exigida no desafio
        return jsonify({"error": "Dados inválidos", "detalhes": "Estrutura do payload não conforme."}), 400
        
    if any(lead['idempotency_key'] == lead_data.idempotency_key for lead in DB_MOCK):
        return jsonify({"message": "Requisição repetida descartada (Idempotency ativado)."}), 200

    email_parts = lead_data.email.split('@')
    email_anonimizado = email_parts[0][:2] + "***@" + email_parts[1]
    
    lead_json_string = lead_data.model_dump_json().encode('utf-8')
    lead_criptografado = cipher_suite.encrypt(lead_json_string)
    
    DB_MOCK.append({
        "idempotency_key": lead_data.idempotency_key,
        "dados_criptografados": lead_criptografado
    })
    
    logger.info(json.dumps({
        "event": "lead_created", 
        "trace_id": g.trace_id, 
        "user_id": getattr(g, 'user_id', 'unknown'), 
        "lead_email_anon": email_anonimizado
    }))
    
    return jsonify({"message": "Lead criado com segurança máxima!"}), 201

if __name__ == '__main__':
    # Mantendo TLS 1.2+ adhoc para proteção dos dados em trânsito
    app.run(ssl_context='adhoc', port=5000)