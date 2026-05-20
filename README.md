# CPCyber

# Integrantes
 Paulo Poças – RM556080
 André Luiz Fernandes De Queiroz - RM554503
 Rafael Bocchi – RM557603
 Marcos Vinicius da Silva Costa - RM555490
 Rafael Federici de Oliveira - RM554736


<img src="/home/boki/vscode/Cyber1.png" alt="imagem" width="500">
 
 <img src="/home/boki/vscode/Cyber2.png" alt="imagem" width="500">


# 🛡️ Ford Leads Security API - Challenge SpeedRunners

Este projeto é uma API de alta segurança desenvolvida em Python/Flask, projetada para gerenciar o fluxo de leads com foco total em blindagem digital. A aplicação implementa todos os requisitos técnicos do desafio **SpeedRunners**, garantindo a integridade, confidencialidade e disponibilidade dos dados, ideal para compor um portfólio robusto de um Desenvolvedor Full Stack Júnior.

---

## 🏛️ Arquitetura de Segurança (Mapeamento de Objetivos)

### 1. Segurança de Entrada e Validação de Dados (20 pts)
* **Validação Estrita:** Uso da biblioteca `Pydantic` para garantir tipagem forte e conformidade de campos (E-mail, Marca, Modelo), prevenindo payload flooding e buffer overflow.
* **Sanitização Ativa:** Implementação do `bleach` para filtrar entradas malformadas e prevenir ataques de **XSS (Cross-Site Scripting)** e injeções de comandos.
* **Normalização de Parâmetros:** Uso de `Enums` para restringir marcas e modelos a padrões estritos definidos pela montadora.
* **Tratamento Seguro de Erros:** Interceptação global de exceções (Erro 500) que oculta stack traces e tecnologias, devolvendo mensagens genéricas com um `trace_id` para auditoria.

### 2. Autenticação e Autorização (20 pts)
* **JWT (JSON Web Token):** Autenticação baseada em tokens com assinatura forte (algoritmo HS256) e tempo de expiração controlado de 15 minutos.
* **RBAC (Role-Based Access Control):** Controle de acesso estruturado utilizando decorators customizados para diferenciar permissões estritas entre **Admin** e **Analistas**.
* **Segurança de Credenciais:** Uso de `Bcrypt` com hashes pré-computados em memória para evitar ataques de força bruta e DoS no endpoint de login.

### 3. Proteção de APIs e Serviços (20 pts)
* **HTTPS/TLS 1.2+:** Comunicação criptografada ponta a ponta utilizando certificados SSL (`adhoc` para testes locais) e arquitetura Same-Origin.
* **Rate Limiting e Idempotência:** Proteção via `Flask-Limiter` (máximo de 5 requisições por minuto no login) e bloqueio de envios duplicados descartando chaves de idempotência repetidas.
* **Integridade de Payload (HMAC):** Verificação rigorosa do cabeçalho `X-Payload-Signature` (HMAC-SHA256) gerado no frontend (via Crypto-JS) para garantir que os dados não sofreram manipulação em trânsito.
* **CORS Configurado:** Controle de origens para permitir requisições apenas de domínios confiáveis.

### 4. Segurança de Dados e Privacidade (25 pts)
* **Criptografia em Repouso:** Implementação de **AES-256 (Fernet)** para cifrar dados sensíveis de leads (clientes e histórico) antes de irem para o banco de dados.
* **Anonimização/Pseudonimização:** Mascaramento automático de PII (dados pessoais) em logs de monitoramento e painéis (ex: `cl***@ford.com`) visando a conformidade com a LGPD.
* **Proteção contra Exposição Acidental:** Arquitetura *Fail Secure* que exige a injeção de segredos criptográficos via variáveis de ambiente, prevenindo vazamentos de chaves hardcoded no código-fonte.

### 5. Monitoramento, Logs e Auditoria (15 pts)
* **Logs Estruturados:** Registros de sistema em formato JSON blindado, omitindo dados sensíveis em texto puro.
* **Monitoramento de Anomalias:** Alertas configurados para registrar violações de permissões (RBAC) e falhas em assinaturas HMAC (tentativas de fraude de payload).
* **Trilha de Auditoria:** Injeção de `trace_id` único em todas as interações para garantir a rastreabilidade completa das ações críticas, desde tentativas de login até a criação de leads.

---

## 🛠️ Stack Tecnológica
* **Backend:** Python 3, Flask
* **Segurança:** Pydantic, PyJWT, Bcrypt, Cryptography (Fernet), Bleach, Flask-Limiter, Flask-CORS
* **Frontend:** HTML5, CSS3, JavaScript (Crypto-JS para HMAC)
* **Ambiente Homologado em:** Linux (Pop!_OS)

---

## 🚀 Como Executar o Projeto

### 1. Configuração do Ambiente Virtual
No terminal, dentro da pasta raiz do projeto:
```
bash
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors flask-limiter bcrypt pyjwt cryptography pydantic bleach email-validator 
```

2. Injeção de Variáveis e Execução

O servidor Flask e o Frontend estão unificados sob a mesma origem servindo arquivos da pasta /templates. O servidor exige as chaves criptográficas na inicialização:
Bash

export SECRET_KEY="SuaChaveSecretaParaOJWT"
export FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
python3 app.py

3. Acessando e Testando a Blindagem

    Abra o navegador em: https://127.0.0.1:5000/

    Aceite o certificado de segurança autoassinado na tela de aviso.

    Para obter sua credencial JWT de Administrador, abra um terminal secundário e rode:

Bash

curl -k -X POST https://127.0.0.1:5000/api/login \
-H "Content-Type: application/json" \
-d '{"username": "admin", "password": "senhaBlindada2026"}'

    Copie o Token retornado e utilize na interface web.

    Verifique o terminal principal: os logs JSON mostrarão a auditoria completa do rastreamento criptográfico.
