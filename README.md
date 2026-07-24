# SQLiTool 🎯

Ferramenta de terminal (TUI) para automatizar testes de **SQL Injection**, construída com [Textual](https://textual.textualize.io/) e Python puro. Feita para praticar e agilizar os fluxos que normalmente seriam feitos manualmente com Burp Suite — como os labs do [PortSwigger Web Security Academy](https://portswigger.net/web-security).

![status](https://img.shields.io/badge/status-em%20desenvolvimento-yellow)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

---

## ⚠️ Aviso legal e ético

Esta ferramenta foi criada **exclusivamente para fins educacionais** e para uso em ambientes que você tem **autorização explícita** para testar — como labs do PortSwigger Academy, CTFs, ou aplicações próprias.

**Nunca** utilize esta ferramenta contra sistemas de terceiros sem permissão por escrito. Testes de invasão não autorizados são crime na maioria das jurisdições (no Brasil, ver Lei 12.737/2012 e o Marco Civil da Internet). O autor não se responsabiliza pelo uso indevido desta ferramenta.

---

## ✨ Funcionalidades

- **Configuração de alvo centralizada** — URL, endpoint, parâmetro, método (GET/POST) e cookie de sessão, reaproveitados por todas as abas de teste.
- **Descoberta do número de colunas** — via `ORDER BY` incremental ou `UNION SELECT NULL`.
- **Payload manual** — envia qualquer payload customizado direto no parâmetro configurado e mostra status, tamanho e preview da resposta.
- **Log em tempo real** — todo teste é registrado com indicação visual de sucesso (✅), erro HTTP (⚠️) ou erro de sintaxe SQL (❌).
- **Requisições assíncronas** — a interface nunca trava enquanto aguarda resposta do servidor (roda em threads separadas).

### 🚧 Em desenvolvimento
- Identificação automática de colunas que aceitam texto
- Fingerprint de SGBD (Oracle, MySQL, PostgreSQL, MSSQL) + extração de versão
- Extração de dados via UNION-based (ex: tabelas de usuários)
- Suporte a blind SQLi (boolean-based e time-based)

---

## 📦 Instalação

### Pré-requisitos
- Python 3.10 ou superior
- `python3-venv` instalado (`sudo apt install python3-venv` em distros baseadas em Debian/Ubuntu/Kali)

### Passo a passo

```bash
# clone o repositório
git clone https://github.com/SEU_USUARIO/sqlitool.git
cd sqlitool

# crie e ative um ambiente virtual
python3 -m venv venv
source venv/bin/activate

# instale as dependências
pip install -r requirements.txt
```

---

## 🚀 Uso

```bash
python3 sqlitool.py
```

1. Preencha os campos no painel **Configuração do Alvo** (URL base, endpoint, parâmetro vulnerável, método e cookie de sessão, se necessário).
2. Clique em **Salvar config** e depois **Testar conexão** para validar o alvo.
3. Navegue pelas abas para rodar cada tipo de teste.
4. Acompanhe os resultados no painel de **Log / Resultados**, à direita.

### Atalhos de teclado
| Atalho | Ação |
|---|---|
| `Ctrl+Q` | Sair da aplicação |
| `Ctrl+L` | Limpar o log |

---

## 🗂️ Estrutura do projeto

```
sqlitool/
├── sqlitool.py       # aplicação principal (UI + lógica)
├── sqlitool.tcss      # estilos da interface (tema Textual)
├── requirements.txt   # dependências Python
└── README.md
```

A lógica é organizada em camadas:
- **Estado** (`TargetState`) — guarda a configuração do alvo.
- **Rede** (`send_request`) — monta e envia as requisições HTTP.
- **Análise** (`analyze_response`) — heurísticas para classificar respostas como sucesso, erro HTTP ou erro de sintaxe SQL.
- **UI** (`SQLiToolApp` e componentes) — orquestra tudo, delegando trabalho de rede para *workers* assíncronos para não travar a interface.

---

## 🛠️ Tecnologias

- [Python 3](https://www.python.org/)
- [Textual](https://textual.textualize.io/) — framework de interfaces em terminal
- [Requests](https://requests.readthedocs.io/) — cliente HTTP

---

## 🤝 Contribuindo

Sugestões, issues e pull requests são bem-vindos! Este é um projeto de aprendizado, então feedback sobre boas práticas de segurança e código é especialmente apreciado.

---

## 📄 Licença

Distribuído sob a licença MIT. Veja `LICENSE` para mais detalhes.

---

## 🙏 Créditos

Inspirado nos labs do [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection).
