#!/usr/bin/env python3
"""Scanner de exemplo (nmap caseiro) — script de demonstração.

Este arquivo simula um scanner simples que aceita argumentos e imprime
um relatório no stdout. A interface GUI pode chamar este script via
subprocess ou usar a função `run_scan` diretamente quando disponível.
"""
import argparse
import time
import random

def run_scan(target: str, ports: str, scan_type: str):
    # ports: texto como "1-1024" ou lista
    results = []
    # Simula alguns resultados
    port_list = []
    if '-' in ports:
        start, end = ports.split('-', 1)
        try:
            start = int(start)
            end = int(end)
            port_list = list(range(max(1, start), max(start+1, end+1)))[:50]
        except Exception:
            port_list = [22, 80, 443]
    else:
        try:
            port_list = [int(p.strip()) for p in ports.split(',') if p.strip()]
        except Exception:
            port_list = [22, 80, 443]

    report_lines = [f"Iniciando scan em {target} (tipo: {scan_type})...\n"]
    for p in port_list:
        time.sleep(0.05)
        state = random.choice(['open', 'closed', 'filtered'])
        service = 'unknown'
        if p == 22:
            service = 'ssh'
        elif p == 80:
            service = 'http'
        elif p == 443:
            service = 'https'
        report_lines.append(f"Port {p}/tcp {state}\tService: {service}\n")

    report_lines.append('\nScan completo.  \n')
    return ''.join(report_lines)

def main():
    parser = argparse.ArgumentParser(description='Scanner de exemplo (nmap caseiro)')
    parser.add_argument('target', help='alvo (ex: 192.168.0.1 or example.com)')
    parser.add_argument('-p', '--ports', default='22,80,443', help='portas ou faixa ex: 1-1024 or 22,80,443')
    parser.add_argument('-s', '--scan', default='quick', help='tipo de scan (quick, full, tcp)')
    args = parser.parse_args()
    out = run_scan(args.target, args.ports, args.scan)
    print(out)

if __name__ == '__main__':
    main()
