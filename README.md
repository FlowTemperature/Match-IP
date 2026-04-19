<div align="center">

# 🛡 Match IP

**Scanner de Ameaças com IA — gratuito, sem login, sem chave de API**

[![npm](https://img.shields.io/npm/v/@flowtemperature/matchip?color=00aaff&label=npm&style=flat-square)](https://www.npmjs.com/package/@flowtemperature/matchip)
[![license](https://img.shields.io/badge/license-MIT-00e5a0?style=flat-square)](./LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D16-blue?style=flat-square)](https://nodejs.org)
[![made with](https://img.shields.io/badge/made%20with-Node.js-green?style=flat-square)](https://nodejs.org)

</div>

---

## O que é?

**Match IP** é uma CLI open source que analisa qualquer endereço IP em segundos:

- 🔍 Score de abuso via **AbuseIPDB**
- 🌍 País, ISP, domínio e tipo de uso
- 🧅 Detecção de **nós Tor**
- 🤖 **Análise de IA** com Llama 3.1 — nível de ameaça, perfil e recomendação
- 📋 Últimos reportes de abuso

Sem login. Sem cadastro. Sem chave de API. Só rodar.

---

## Instalação

```bash
npm install -g @flowtemperature/matchip
```

ou sem instalar:

```bash
npx @flowtemperature/matchip 8.8.8.8
```

---

## Uso

```bash
matchip <ip>       # Analisa um IP
matchip ping       # Verifica se a API está online
matchip help       # Ajuda
```

### Exemplos

```bash
matchip 8.8.8.8
matchip 185.220.101.1
matchip 1.1.1.1
```

---

## Output

```
════════════════════════════════════════════════════════
    🛡  Match IP  v1.0.1
    Scanner de Ameaças com IA · by FlowTemperature
════════════════════════════════════════════════════════

  🔍 185.220.101.1    ██ CRÍTICO ██

  ████████████████████████████████  100/100

  🗺  País          DE
  🏢 ISP            Artikel10 e.V.
  🔗 Domínio        artikel10.org
  📋 Reportes       135
  🧅 Nó Tor         SIM ⚠️
  📅 Último rep.    19/04/2026

  🤖 Análise de IA
  NÍVEL: Alto
  PERFIL: Exit node Tor com score máximo, infraestrutura usada para anonimizar tráfego malicioso
  AÇÃO: bloquear — score 100/100 com 135 reportes confirmados e nó Tor ativo

════════════════════════════════════════════════════════
  🔗 https://www.abuseipdb.com/check/185.220.101.1
════════════════════════════════════════════════════════
```

---

## Por que Match IP é diferente?

| Feature | Match IP | Outros |
|---|---|---|
| Sem login | ✅ | ❌ |
| Sem chave de API | ✅ | ❌ |
| Análise com IA | ✅ | ❌ |
| Open source | ✅ | ❌ |
| Gratuito | ✅ | ❌ |
| CLI + Web | ✅ | raramente |

---

## Website

Além da CLI, existe uma interface web completa disponível em:

> **[matchip.squareweb.app](https://matchip.squareweb.app)**

---

## Variável de ambiente

Se quiser apontar para outra instância da API:

```bash
MATCHIP_API=https://minha-api.com matchip 8.8.8.8
```

---

## Licença

[MIT](./LICENSE) — faça o que quiser, só mantém os créditos. 🤝

---

<div align="center">

Feito com 💙 por [FlowTemperature](https://github.com/FlowTemperature) · com ajuda de [Claude](https://claude.ai)

</div>
