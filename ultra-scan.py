#!/usr/bin/env python3
import argparse
import re
import socket
import subprocess
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich import box

console = Console()

ASCII_ART = r"""
[bold cyan]███    █▄   ▄█           ███        ▄████████    ▄████████    ▄████████  ▄████████    ▄████████ ███▄▄▄▄[/]
[bold cyan]███    ███ ███       ▀█████████▄   ███    ███   ███    ███   ███    ███ ███    ███   ███    ███ ███▀▀▀██▄[/]
[bold cyan]███    ███ ███          ▀███▀▀██   ███    ███   ███    ███   ███    █▀  ███    █▀    ███    ███ ███   ███[/]
[bold cyan]███    ███ ███           ███   ▀  ▄███▄▄▄▄██▀   ███    ███   ███        ███          ███    ███ ███   ███[/]
[bold cyan]███    ███ ███           ███     ▀▀███▀▀▀▀▀   ▀███████████ ▀███████████ ███        ▀███████████ ███   ███[/]
[bold cyan]███    ███ ███           ███     ▀███████████   ███    ███          ███ ███    █▄    ███    ███ ███   ███[/]
[bold cyan]███    ███ ███▌    ▄     ███       ███    ███   ███    ███    ▄█    ███ ███    ███   ███    ███ ███   ███[/]
[bold cyan]████████▀  █████▄▄██    ▄████▀     ███    ███   ███    █▀   ▄████████▀  ████████▀    ███    █▀   ▀█   █▀[/]
"""

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# ---------------------------------------------------------------------------
# i18n — all user-facing strings live here. Add a new language by adding
# another top-level key (e.g. "es") with the same sub-keys as "en"/"pt".
# ---------------------------------------------------------------------------
TEXTS = {
    "en": {
        "labels": {
            "domain_info": "Domain info (WHOIS)",
            "ip": "IP resolution",
            "emails": "Registered emails",
            "subdomains": "Subdomains (subfinder)",
            "directories": "Directories (dirb)",
            "nmap": "Nmap — General scan",
            "vulnerabilities": "Nmap — Vulnerabilities",
            "nikto": "Nikto — Web vulnerabilities",
            "whatweb": "WhatWeb — Web technologies",
            "http": "HTTP services",
            "ssh": "SSH services",
            "mysql": "MySQL services",
            "postgres": "PostgreSQL services",
            "redis": "Redis services",
            "docker": "Docker services",
            "smb": "SMB services",
            "mqtt": "MQTT services",
        },
        "cli_description": "UltraScan — Reconnaissance & Security Scanning Tool",
        "cli_target": "IP or domain to scan",
        "cli_ports": "Specific ports to scan (comma separated)",
        "cli_all": "Run all scans",
        "cli_verbose": "Verbose output",
        "cli_dirb": "Use dirb for directory scanning",
        "cli_subfinder": "Use subfinder for subdomain discovery",
        "cli_lang": "Output language: en (default) or pt",
        "footer": "by CRyzen  ·  github.com/CRyzen-dev/ultra-scan",
        "config_title": "Configuration",
        "config_target": "Target:",
        "config_mode": "Mode:",
        "config_ports": "Ports:",
        "mode_full": "Full scan",
        "mode_default": "Default Nmap",
        "installing": "Installing dependencies: {tools}",
        "installed": "Dependencies installed.",
        "step_ip": "Resolving target IP...",
        "step_whois": "Querying WHOIS / registered emails...",
        "step_subfinder": "Discovering subdomains (subfinder)...",
        "step_dirb": "Scanning directories (dirb)...",
        "step_nmap": "Running general Nmap scan...",
        "step_vuln": "Checking vulnerabilities (Nmap)...",
        "step_nikto": "Checking web vulnerabilities (Nikto)...",
        "step_whatweb": "Identifying web technologies (WhatWeb)...",
        "step_http": "Checking HTTP services...",
        "step_ssh": "Checking SSH services...",
        "step_mysql": "Checking MySQL services...",
        "step_postgres": "Checking PostgreSQL services...",
        "step_redis": "Checking Redis services...",
        "step_docker": "Checking Docker containers...",
        "step_smb": "Checking SMB services...",
        "step_mqtt": "Checking MQTT services...",
        "step_nmap_default": "Running Nmap scan...",
        "no_results": "No results found.",
        "summary_title": "Scan Summary",
        "col_module": "Module",
        "col_status": "Status",
        "col_detail": "Detail",
        "status_ok": "OK",
        "status_none": "NO RESULT",
        "status_error": "ERROR",
        "detail_found": "{n} found",
        "detail_findings": "{n} possible findings",
        "detail_done": "done",
        "detail_none_found": "none found",
        "detail_items_reported": "{n} items reported",
        "detail_tech_identified": "technologies identified",
        "hostname_label": "Hostname:",
        "none_found_verbose": "(none found)",
        "no_output": "(no output)",
        "interrupted": "Scan interrupted by user.",
        "tool_not_installed": "{tool} not installed",
        "timeout": "timeout (>5min)",
    },
    "pt": {
        "labels": {
            "domain_info": "Informações do domínio (WHOIS)",
            "ip": "Resolução de IP",
            "emails": "E-mails registrados",
            "subdomains": "Subdomínios (subfinder)",
            "directories": "Diretórios (dirb)",
            "nmap": "Nmap — Scan geral",
            "vulnerabilities": "Nmap — Vulnerabilidades",
            "nikto": "Nikto — Vulnerabilidades web",
            "whatweb": "WhatWeb — Tecnologias web",
            "http": "Serviços HTTP",
            "ssh": "Serviços SSH",
            "mysql": "Serviços MySQL",
            "postgres": "Serviços PostgreSQL",
            "redis": "Serviços Redis",
            "docker": "Serviços Docker",
            "smb": "Serviços SMB",
            "mqtt": "Serviços MQTT",
        },
        "cli_description": "UltraScan — Ferramenta de Reconhecimento e Varredura de Segurança",
        "cli_target": "IP ou domínio a escanear",
        "cli_ports": "Portas específicas para escanear (separadas por vírgula)",
        "cli_all": "Executa todos os scans",
        "cli_verbose": "Saída detalhada",
        "cli_dirb": "Usa dirb para escaneamento de diretórios",
        "cli_subfinder": "Usa subfinder para descoberta de subdomínios",
        "cli_lang": "Idioma da saída: en (padrão) ou pt",
        "footer": "by CRyzen  ·  github.com/CRyzen-dev/ultra-scan",
        "config_title": "Configuração",
        "config_target": "Alvo:",
        "config_mode": "Modo:",
        "config_ports": "Portas:",
        "mode_full": "Scan completo",
        "mode_default": "Nmap padrão",
        "installing": "Instalando dependências: {tools}",
        "installed": "Dependências instaladas.",
        "step_ip": "Resolvendo IP do alvo...",
        "step_whois": "Consultando WHOIS / e-mails registrados...",
        "step_subfinder": "Descobrindo subdomínios (subfinder)...",
        "step_dirb": "Escaneando diretórios (dirb)...",
        "step_nmap": "Executando scan Nmap geral...",
        "step_vuln": "Verificando vulnerabilidades (Nmap)...",
        "step_nikto": "Verificando vulnerabilidades web (Nikto)...",
        "step_whatweb": "Identificando tecnologias web (WhatWeb)...",
        "step_http": "Verificando serviços HTTP...",
        "step_ssh": "Verificando serviços SSH...",
        "step_mysql": "Verificando serviços MySQL...",
        "step_postgres": "Verificando serviços PostgreSQL...",
        "step_redis": "Verificando serviços Redis...",
        "step_docker": "Verificando contêineres Docker...",
        "step_smb": "Verificando serviços SMB...",
        "step_mqtt": "Verificando serviços MQTT...",
        "step_nmap_default": "Executando scan Nmap...",
        "no_results": "Nenhum resultado encontrado.",
        "summary_title": "Resumo do Scan",
        "col_module": "Módulo",
        "col_status": "Status",
        "col_detail": "Detalhe",
        "status_ok": "OK",
        "status_none": "SEM RESULTADO",
        "status_error": "ERRO",
        "detail_found": "{n} encontrados",
        "detail_findings": "{n} possíveis achados",
        "detail_done": "concluído",
        "detail_none_found": "nenhum encontrado",
        "detail_items_reported": "{n} itens reportados",
        "detail_tech_identified": "tecnologias identificadas",
        "hostname_label": "Hostname:",
        "none_found_verbose": "(nenhum encontrado)",
        "no_output": "(sem saída)",
        "interrupted": "Scan interrompido pelo usuário.",
        "tool_not_installed": "{tool} não instalado",
        "timeout": "timeout (>5min)",
    },
}


class UltraScan:
    def __init__(self):
        # A minimal pre-parser just to read --lang before building the full
        # (already-translated) argparse parser.
        pre = argparse.ArgumentParser(add_help=False)
        pre.add_argument("-l", "--lang", choices=["en", "pt"], default="en")
        pre_args, _ = pre.parse_known_args()
        self.lang = pre_args.lang
        self.t = TEXTS[self.lang]
        self.labels = self.t["labels"]

        self.parser = argparse.ArgumentParser(
            prog="ultra-scan",
            description=self.t["cli_description"],
        )
        self.parser.add_argument("target", help=self.t["cli_target"])
        self.parser.add_argument("-p", "--ports", help=self.t["cli_ports"])
        self.parser.add_argument("-a", "--all", action="store_true", help=self.t["cli_all"])
        self.parser.add_argument("-v", "--verbose", action="store_true", help=self.t["cli_verbose"])
        self.parser.add_argument("-d", "--dirb", action="store_true", help=self.t["cli_dirb"])
        self.parser.add_argument("-s", "--subfinder", action="store_true", help=self.t["cli_subfinder"])
        self.parser.add_argument("-l", "--lang", choices=["en", "pt"], default="en", help=self.t["cli_lang"])
        self.results = {}
        self.status = {}  # key -> "ok" | "fail" | "error"

    # ---------- UI helpers ----------

    def print_banner(self):
        console.print(ASCII_ART)
        console.print(
            Panel.fit(
                f"[bold white]{self.t['footer']}[/]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        console.print()

    def print_target_info(self, target):
        table = Table.grid(padding=(0, 2))
        table.add_row(f"[bold]{self.t['config_target']}[/]", f"[bold yellow]{target}[/]")
        mode = self.t["mode_full"] if self.args.all else self.t["mode_default"]
        table.add_row(f"[bold]{self.t['config_mode']}[/]", f"[green]{mode}[/]")
        if self.args.ports:
            table.add_row(f"[bold]{self.t['config_ports']}[/]", self.args.ports)
        console.print(Panel(table, title=f"[bold cyan]{self.t['config_title']}[/]", border_style="blue", box=box.ROUNDED))
        console.print()

    def run_with_spinner(self, description, func, *args):
        """Run a scan function while showing a spinner + elapsed time."""
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None, style="grey37", complete_style="cyan"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(description, total=None)
            result = func(*args)
            progress.update(task, completed=1, total=1)
        return result

    # ---------- Tool installation ----------

    def install_tools(self):
        tools = ["subfinder", "dirb", "whois", "nikto", "whatweb"]
        missing = []
        for tool in tools:
            check = subprocess.run(["which", tool], capture_output=True)
            if check.returncode != 0:
                missing.append(tool)

        if not missing:
            return

        console.print(f"[yellow][...][/] {self.t['installing'].format(tools=', '.join(missing))}")
        subprocess.run(["apt-get", "update"], capture_output=True)
        for tool in missing:
            subprocess.run(["apt-get", "-y", "install", tool], capture_output=True)
        console.print(f"[green][✓][/] {self.t['installed']}\n")

    # ---------- Scans ----------

    def run_subfinder(self, target):
        try:
            cmd = ["subfinder", "-d", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.results["subdomains"] = [l for l in result.stdout.splitlines() if l.strip()]
                self.status["subdomains"] = "ok"
                return True
            self.status["subdomains"] = "fail"
            return False
        except Exception as e:
            self.status["subdomains"] = "error"
            self.results["subdomains_error"] = str(e)
            return False

    def run_dirb(self, target):
        try:
            cmd = ["dirb", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.results["directories"] = result.stdout
                self.status["directories"] = "ok"
                return True
            self.status["directories"] = "fail"
            return False
        except Exception as e:
            self.status["directories"] = "error"
            self.results["directories_error"] = str(e)
            return False

    def run_ip_resolution(self, target):
        """Resolve the target's IP address(es)."""
        try:
            hostname, aliases, ip_list = socket.gethostbyname_ex(target)
            self.results["ip"] = {
                "hostname": hostname,
                "aliases": aliases,
                "ips": ip_list,
            }
            self.status["ip"] = "ok"
            return True
        except Exception as e:
            self.status["ip"] = "error"
            self.results["ip_error"] = str(e)
            return False

    def run_whois(self, target):
        """Query WHOIS: domain registration data + emails found in the raw text."""
        try:
            cmd = ["whois", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout

            if not output.strip():
                self.status["domain_info"] = "fail"
                return False

            self.results["domain_info"] = output
            self.status["domain_info"] = "ok"

            found_emails = sorted(set(EMAIL_REGEX.findall(output)))
            junk_markers = ("redacted", "privacy", "whoisguard", "proxy", "abuse")
            clean_emails = [
                e for e in found_emails
                if not any(m in e.lower() for m in junk_markers)
            ]

            self.results["emails"] = clean_emails if clean_emails else found_emails
            self.status["emails"] = "ok" if self.results["emails"] else "fail"

            return True
        except FileNotFoundError:
            self.status["domain_info"] = "error"
            self.results["domain_info_error"] = self.t["tool_not_installed"].format(tool="whois")
            return False
        except Exception as e:
            self.status["domain_info"] = "error"
            self.results["domain_info_error"] = str(e)
            return False

    def run_nikto(self, target):
        """Run Nikto — web vulnerability scanner."""
        try:
            cmd = ["nikto", "-h", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.stdout.strip():
                self.results["nikto"] = result.stdout
                self.status["nikto"] = "ok"
                return True
            self.status["nikto"] = "fail"
            return False
        except FileNotFoundError:
            self.status["nikto"] = "error"
            self.results["nikto_error"] = self.t["tool_not_installed"].format(tool="nikto")
            return False
        except subprocess.TimeoutExpired:
            self.status["nikto"] = "error"
            self.results["nikto_error"] = self.t["timeout"]
            return False
        except Exception as e:
            self.status["nikto"] = "error"
            self.results["nikto_error"] = str(e)
            return False

    def run_whatweb(self, target):
        """Run WhatWeb — identifies technologies used on the site (CMS, frameworks, servers)."""
        try:
            cmd = ["whatweb", "-a", "3", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.stdout.strip():
                self.results["whatweb"] = result.stdout
                self.status["whatweb"] = "ok"
                return True
            self.status["whatweb"] = "fail"
            return False
        except FileNotFoundError:
            self.status["whatweb"] = "error"
            self.results["whatweb_error"] = self.t["tool_not_installed"].format(tool="whatweb")
            return False
        except Exception as e:
            self.status["whatweb"] = "error"
            self.results["whatweb_error"] = str(e)
            return False

    def _generic_nmap(self, key, target, extra_args):
        try:
            cmd = ["nmap"] + extra_args + [target]
            if self.args.ports and key in ("nmap", "vulnerabilities"):
                cmd.extend(["-p", self.args.ports])
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.results[key] = result.stdout
                self.status[key] = "ok"
                return True
            self.status[key] = "fail"
            return False
        except Exception as e:
            self.status[key] = "error"
            self.results[f"{key}_error"] = str(e)
            return False

    def run_nmap_scan(self, target):
        return self._generic_nmap("nmap", target, ["-sV", "-T4", "--script=default"])

    def run_vuln_scan(self, target):
        return self._generic_nmap("vulnerabilities", target, ["--script=vuln"])

    def run_http_scan(self, target):
        return self._generic_nmap("http", target, ["-sV", "-p80,443,8080"])

    def run_ssh_scan(self, target):
        return self._generic_nmap("ssh", target, ["-sV", "-p22"])

    def run_mysql_scan(self, target):
        return self._generic_nmap("mysql", target, ["-sV", "-p3306"])

    def run_postgres_scan(self, target):
        return self._generic_nmap("postgres", target, ["-sV", "-p5432"])

    def run_redis_scan(self, target):
        return self._generic_nmap("redis", target, ["-sV", "-p6379"])

    def run_docker_scan(self, target):
        return self._generic_nmap("docker", target, ["-sV", "-p2375,2376"])

    def run_smb_scan(self, target):
        return self._generic_nmap("smb", target, ["-sV", "-p445"])

    def run_mqtt_scan(self, target):
        return self._generic_nmap("mqtt", target, ["-sV", "-p1883,8883"])

    # ---------- Orchestration ----------

    def run_all_scans(self, target):
        self.install_tools()

        scans = [
            (self.t["step_ip"], self.run_ip_resolution),
            (self.t["step_whois"], self.run_whois),
            (self.t["step_subfinder"], self.run_subfinder),
            (self.t["step_dirb"], self.run_dirb),
            (self.t["step_nmap"], self.run_nmap_scan),
            (self.t["step_vuln"], self.run_vuln_scan),
            (self.t["step_nikto"], self.run_nikto),
            (self.t["step_whatweb"], self.run_whatweb),
            (self.t["step_http"], self.run_http_scan),
            (self.t["step_ssh"], self.run_ssh_scan),
            (self.t["step_mysql"], self.run_mysql_scan),
            (self.t["step_postgres"], self.run_postgres_scan),
            (self.t["step_redis"], self.run_redis_scan),
            (self.t["step_docker"], self.run_docker_scan),
            (self.t["step_smb"], self.run_smb_scan),
            (self.t["step_mqtt"], self.run_mqtt_scan),
        ]

        for description, func in scans:
            ok = self.run_with_spinner(description, func, target)
            icon = "[green][+][/]" if ok else "[red][-][/]"
            console.print(f"{icon} {description.rstrip('.')}")

    # ---------- Results ----------

    def print_results(self):
        console.print()
        if not self.results:
            console.print(Panel(f"[yellow]{self.t['no_results']}[/]", border_style="yellow"))
            return

        summary = Table(title=self.t["summary_title"], box=box.ROUNDED, border_style="cyan", show_lines=False)
        summary.add_column(self.t["col_module"], style="bold white")
        summary.add_column(self.t["col_status"], justify="center")
        summary.add_column(self.t["col_detail"], style="dim")

        for key, label in self.labels.items():
            if key not in self.status:
                continue
            state = self.status[key]
            if state == "ok":
                status_text = f"[green]{self.t['status_ok']}[/]"
                if key == "subdomains":
                    detail = self.t["detail_found"].format(n=len(self.results.get("subdomains", [])))
                elif key == "vulnerabilities":
                    vuln_hits = self.results.get("vulnerabilities", "").count("VULNERABLE")
                    detail = self.t["detail_findings"].format(n=vuln_hits) if vuln_hits else self.t["detail_done"]
                elif key == "ip":
                    ips = self.results.get("ip", {}).get("ips", [])
                    detail = ", ".join(ips) if ips else "-"
                elif key == "emails":
                    emails = self.results.get("emails", [])
                    detail = self.t["detail_found"].format(n=len(emails)) if emails else self.t["detail_none_found"]
                elif key == "nikto":
                    hits = self.results.get("nikto", "").count("+ ")
                    detail = self.t["detail_items_reported"].format(n=hits)
                elif key == "whatweb":
                    detail = self.t["detail_tech_identified"]
                else:
                    detail = self.t["detail_done"]
            elif state == "fail":
                status_text = f"[yellow]{self.t['status_none']}[/]"
                detail = "-"
            else:
                status_text = f"[red]{self.t['status_error']}[/]"
                detail = self.results.get(f"{key}_error", "-")[:40]
            summary.add_row(label, status_text, detail)

        console.print(summary)
        console.print()

        if self.args.verbose:
            for key, value in self.results.items():
                if key.endswith("_error"):
                    continue
                console.rule(f"[bold cyan]{self.labels.get(key, key).upper()}[/]")
                if key == "ip" and isinstance(value, dict):
                    console.print(f"  {self.t['hostname_label']} {value.get('hostname', '-')}")
                    for ip in value.get("ips", []):
                        console.print(f"  [green]•[/] {ip}")
                elif isinstance(value, list):
                    if not value:
                        console.print(f"  [dim]{self.t['none_found_verbose']}[/]")
                    for item in value:
                        console.print(f"  [green]•[/] {item}")
                else:
                    console.print(value.strip() or f"[dim]{self.t['no_output']}[/]")
                console.print()

    # ---------- Entry point ----------

    def run(self):
        self.args = self.parser.parse_args()

        self.print_banner()

        if not self.args.target:
            self.parser.print_help()
            return

        self.print_target_info(self.args.target)

        try:
            if self.args.all:
                self.run_all_scans(self.args.target)
            else:
                ok = self.run_with_spinner(self.t["step_nmap_default"], self.run_nmap_scan, self.args.target)
                icon = "[green][+][/]" if ok else "[red][-][/]"
                console.print(f"{icon} Nmap")
        except KeyboardInterrupt:
            console.print(f"\n[red][-] {self.t['interrupted']}[/]")
            sys.exit(1)

        self.print_results()


if __name__ == "__main__":
    tool = UltraScan()
    tool.run()
