
#!/usr/bin/env python3
import argparse
import subprocess
import socket
import json
import os
import sys
import time
import threading
import requests
from urllib.parse import urlparse

# Cores ANSI
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

# ASCII Art
ASCII_ART = """
███    █▄   ▄█           ███        ▄████████    ▄████████    ▄████████  ▄████████    ▄████████ ███▄▄▄▄
███    ███ ███       ▀█████████▄   ███    ███   ███    ███   ███    ███ ███    ███   ███    ███ ███▀▀▀██▄
███    ███ ███          ▀███▀▀██   ███    ███   ███    ███   ███    █▀  ███    █▀    ███    ███ ███   ███
███    ███ ███           ███   ▀  ▄███▄▄▄▄██▀   ███    ███   ███        ███          ███    ███ ███   ███
███    ███ ███           ███     ▀▀███▀▀▀▀▀   ▀███████████ ▀███████████ ███        ▀███████████ ███   ███
███    ███ ███           ███     ▀███████████   ███    ███          ███ ███    █▄    ███    ███ ███   ███
███    ███ ███▌    ▄     ███       ███    ███   ███    ███    ▄█    ███ ███    ███   ███    ███ ███   ███
████████▀  █████▄▄██    ▄████▀     ███    ███   ███    █▀   ▄████████▀  ████████▀    ███    █▀   ▀█   █▀
           ▀                       ███    ███

by CRyzen
---------------------------------------------------------------------------------------------------------------------------------
"""

class UltraScan:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description='Ultra Scan Tool')
        self.parser.add_argument('target', help='IP or domain to scan')
        self.parser.add_argument('-p', '--ports', help='Specific ports to scan (comma separated)')
        self.parser.add_argument('-a', '--all', action='store_true', help='Run all scans')
        self.parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
        self.results = {}
        
    def print_ascii(self):
        """Imprime ASCII Art"""
        print(ASCII_ART)
        
    def print_status(self, status, message):
        """Exibe status com cores"""
        if status == "FOUND":
            print(f"{GREEN}[+] {message}{RESET}")
        elif status == "NOT_FOUND":
            print(f"{RED}[-] {message}{RESET}")
        elif status == "PROCESSING":
            print(f"{YELLOW}[...] {message}{RESET}")
        elif status == "VULNERABLE":
            print(f"{RED}[!] {message}{RESET}")
        elif status == "SAFE":
            print(f"{GREEN}[✓] {message}{RESET}")
            
    def run_nmap_scan(self, target):
        """Executa scan NMAP"""
        try:
            self.print_status("PROCESSING", "Executando scan NMAP...")
            
            cmd = ["nmap", "-sV", "-T4", "--script=default", target]
            if self.args.ports:
                cmd.extend(["-p", self.args.ports])
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results['nmap'] = result.stdout
                self.print_status("FOUND", "NMAP scan completo")
                return True
            else:
                self.print_status("NOT_FOUND", "Erro no NMAP scan")
                return False
        except Exception as e:
            self.print_status("NOT_FOUND", f"Erro: {str(e)}")
            return False
            
    def run_vuln_scan(self, target):
        """Executa scan de vulnerabilidades"""
        try:
            self.print_status("PROCESSING", "Verificando vulnerabilidades...")
            
            cmd = ["nmap", "--script=vuln", target]
            if self.args.ports:
                cmd.extend(["-p", self.args.ports])
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results['vulnerabilities'] = result.stdout
                self.print_status("FOUND", "Vulnerabilidades detectadas")
                return True
            else:
                self.print_status("NOT_FOUND", "Nenhuma vulnerabilidade encontrada")
                return False
        except Exception as e:
            self.print_status("NOT_FOUND", f"Erro: {str(e)}")
            return False
            
    def run_http_scan(self, target):
        """Executa scan HTTP"""
        try:
            self.print_status("PROCESSING", "Verificando serviços HTTP...")
            
            cmd = ["nmap", "-sV", "-p80,443,8080", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results['http'] = result.stdout
                self.print_status("FOUND", "Serviços HTTP encontrados")
                return True
            else:
                self.print_status("NOT_FOUND", "Nenhum serviço HTTP encontrado")
                return False
        except Exception as e:
            self.print_status("NOT_FOUND", f"Erro: {str(e)}")
            return False
            
    def run_ssh_scan(self, target):
        """Executa scan SSH"""
        try:
            self.print_status("PROCESSING", "Verificando serviços SSH...")
            
            cmd = ["nmap", "-sV", "-p22", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results['ssh'] = result.stdout
                self.print_status("FOUND", "Serviços SSH encontrados")
                return True
            else:
                self.print_status("NOT_FOUND", "Nenhum serviço SSH encontrado")
                return False
        except Exception as e:
            self.print_status("NOT_FOUND", f"Erro: {str(e)}")
            return False
            
    def run_mysql_scan(self, target):
        """Executa scan MySQL"""
        try:
            self.print_status("PROCESSING", "Verificando serviços MySQL...")
            
            cmd = ["nmap", "-sV", "-p3306", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results['mysql'] = result.stdout
                self.print_status("FOUND", "Serviços MySQL encontrados")
                return True
            else:
                self.print_status("NOT_FOUND", "Nenhum serviço MySQL encontrado")
                return False
        except Exception as e:
            self.print_status("NOT_FOUND", f"Erro: {str(e)}")
            return False
            
    def run_postgres_scan(self, target):
        """Executa scan PostgreSQL"""
        try:
            self.print_status("PROCESSING", "Verificando serviços PostgreSQL...")
            
            cmd = ["nmap", "-sV", "-p5432", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results['postgres'] = result.stdout
                self.print_status("FOUND", "Serviços PostgreSQL encontrados")
                return True
            else:
                self.print_status("NOT_FOUND", "Nenhum serviço PostgreSQL encontrado")
                return False
        except Exception as e:
            self.print_status("NOT_FOUND", f"Erro: {str(e)}")
            return False
            
    def run_redis_scan(self, target):
        """Executa scan Redis"""
        try:
            self.print_status("PROCESSING", "Verificando serviços Redis...")
            
            cmd = ["nmap", "-sV", "-p6379", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results['redis'] = result.stdout
                self.print_status("FOUND", "Serviços Redis encontrados")
                return True
            else:
                self.print_status("NOT_FOUND", "Nenhum serviço Redis encontrado")
                return False
        except Exception as e:
            self.print_status("NOT_FOUND", f"Erro: {str(e)}")
            return False
            
    def run_docker_scan(self, target):
        """Executa scan Docker"""
        try:
            self.print_status("PROCESSING", "Verificando contêineres Docker...")
            
            cmd = ["nmap", "-sV", "-p2375,2376", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results['docker'] = result.stdout
                self.print_status("FOUND", "Contêineres Docker encontrados")
                return True
            else:
                self.print_status("NOT_FOUND", "Nenhum contêiner Docker encontrado")
                return False
        except Exception as e:
            self.print_status("NOT_FOUND", f"Erro: {str(e)}")
            return False
            
    def run_smb_scan(self, target):
        """Executa scan SMB"""
        try:
            self.print_status("PROCESSING", "Verificando serviços SMB...")
            
            cmd = ["nmap", "-sV", "-p445", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results['smb'] = result.stdout
                self.print_status("FOUND", "Serviços SMB encontrados")
                return True
            else:
                self.print_status("NOT_FOUND", "Nenhum serviço SMB encontrado")
                return False
        except Exception as e:
            self.print_status("NOT_FOUND", f"Erro: {str(e)}")
            return False
            
    def run_mqtt_scan(self, target):
        """Executa scan MQTT"""
        try:
            self.print_status("PROCESSING", "Verificando serviços MQTT...")
            
            cmd = ["nmap", "-sV", "-p1883,8883", target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.results['mqtt'] = result.stdout
                self.print_status("FOUND", "Serviços MQTT encontrados")
                return True
            else:
                self.print_status("NOT_FOUND", "Nenhum serviço MQTT encontrado")
                return False
        except Exception as e:
            self.print_status("NOT_FOUND", f"Erro: {str(e)}")
            return False
            
    def run_all_scans(self, target):
        """Executa todos os scans"""
        scans = [
            self.run_nmap_scan,
            self.run_vuln_scan,
            self.run_http_scan,
            self.run_ssh_scan,
            self.run_mysql_scan,
            self.run_postgres_scan,
            self.run_redis_scan,
            self.run_docker_scan,
            self.run_smb_scan,
            self.run_mqtt_scan
        ]
        
        for scan in scans:
            scan(target)
            
    def print_results(self):
        """Exibe resultados"""
        if not self.results:
            print("Nenhum resultado encontrado.")
            return
            
        print("\n=== RESULTADOS ===")
        for key, value in self.results.items():
            print(f"\n{BLUE}{key.upper()}{RESET}:")
            print(value)
            
    def run(self):
        """Executa a ferramenta"""
        self.args = self.parser.parse_args()
        
        # Mostra ASCII art
        self.print_ascii()
        
        # Verifica alvo
        if not self.args.target:
            self.parser.print_help()
            return
            
        # Executa scans
        if self.args.all:
            self.run_all_scans(self.args.target)
        else:
            self.run_nmap_scan(self.args.target)
            
        # Exibe resultados
        self.print_results()

if __name__ == "__main__":
    tool = UltraScan()
    tool.run()
