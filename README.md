# 🔍 Match IP

**Scanner & Analisador de Ameaças em Tempo Real**

Uma ferramenta web leve e eficiente para análise de endereços IP, integrando dados do AbuseIPDB com análise de inteligência artificial para fornecer relatórios de segurança detalhados.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

---

## 📋 Funcionalidades

- **Verificação de IP em Tempo Real** – Consulta AbuseIPDB para obter score de confiança, reportes e histórico
- **Análise de IA Integrada** – Gera relatórios técnicos interpretados por LLM (Llama 3.1)
- **Interface Web Moderna** – UI responsiva com tema escuro e visualização intuitiva de dados
- **Rotação de API Keys** – Suporte a múltiplas chaves AbuseIPDB e Flow para evitar rate limits
- **Zero Dependências Complexas** – Apenas Python padrão + `python-dotenv`

---

## 🚀 Instalação

### Pré-requisitos

- Python 3.8 ou superior
- Chaves de API válidas (veja abaixo)

### Passos

```bash
# 1. Clone o repositório
git clone https://github.com/FlowTemperature/match-IP.git
cd match-ip

# 2. Instale as dependências
pip install python-dotenv

# 3. Configure as variáveis de ambiente
cp .env.example .env  # ou crie o arquivo .env manualmente
