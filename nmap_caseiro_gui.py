#!/usr/bin/env python3
"""Interface gráfica simples para o "nmap caseiro".

Funcionalidades:
- Campo para alvo (IP ou hostname)
- Campo para portas/faixa
- Seleção de tipo de scan
- Caminho para script externo (opcional)
- Botão "Run" que executa o scanner (externo via subprocess ou interno)
- Área de texto para mostrar o relatório
- Botão "Explain" que mostra explicação sobre opções
- Salvar relatório em arquivo

Empacotamento: usar `pyinstaller --onefile nmap_caseiro_gui.py`
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import threading
import sys
import os
from datetime import datetime

try:
    # import interno se disponível
    from scanner.nmap_caseiro import run_scan as internal_run_scan
except Exception:
    internal_run_scan = None

class NmapGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Nmap Caseiro - Interface')
        self.geometry('800x600')
        self._build()

    def _build(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill='x')

        ttk.Label(frm, text='Alvo:').grid(row=0, column=0, sticky='w')
        self.target_var = tk.StringVar(value='127.0.0.1')
        ttk.Entry(frm, textvariable=self.target_var, width=30).grid(row=0, column=1, sticky='w')

        ttk.Label(frm, text='Portas / Faixa:').grid(row=1, column=0, sticky='w')
        self.ports_var = tk.StringVar(value='22,80,443')
        ttk.Entry(frm, textvariable=self.ports_var, width=30).grid(row=1, column=1, sticky='w')

        ttk.Label(frm, text='Tipo de Scan:').grid(row=2, column=0, sticky='w')
        self.scan_var = tk.StringVar(value='quick')
        ttk.Combobox(frm, textvariable=self.scan_var, values=['quick','full','tcp'], width=27).grid(row=2, column=1, sticky='w')

        ttk.Label(frm, text='Script externo (opcional):').grid(row=3, column=0, sticky='w')
        self.script_var = tk.StringVar(value='')
        ttk.Entry(frm, textvariable=self.script_var, width=40).grid(row=3, column=1, sticky='w')
        ttk.Button(frm, text='Browse', command=self.browse_script).grid(row=3, column=2, sticky='w')

        btn_frame = ttk.Frame(frm)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=8)
        ttk.Button(btn_frame, text='Run', command=self.run_scan).pack(side='left', padx=6)
        ttk.Button(btn_frame, text='Explain', command=self.show_explain).pack(side='left', padx=6)
        ttk.Button(btn_frame, text='Save Report', command=self.save_report).pack(side='left', padx=6)

        # Output
        self.output = tk.Text(self, wrap='none')
        self.output.pack(fill='both', expand=True, padx=10, pady=6)

    def browse_script(self):
        path = filedialog.askopenfilename(title='Selecione o script do scanner', filetypes=[('Python','*.py'),('All files','*.*')])
        if path:
            self.script_var.set(path)

    def append_output(self, text: str):
        self.output.insert('end', text)
        self.output.see('end')

    def run_scan(self):
        target = self.target_var.get().strip()
        ports = self.ports_var.get().strip()
        scan_type = self.scan_var.get().strip()
        script = self.script_var.get().strip()

        if not target:
            messagebox.showwarning('Falha', 'Informe o alvo')
            return

        self.output.delete('1.0', 'end')

        def worker():
            start_time = datetime.utcnow()
            self.append_output(f'[{start_time.isoformat()}] Iniciando scan em {target}...\n')
            try:
                if script:
                    # chamar script externo
                    cmd = [sys.executable, script, target, '-p', ports, '-s', scan_type]
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    for line in proc.stdout:
                        self.append_output(line)
                    proc.wait()
                elif internal_run_scan is not None:
                    out = internal_run_scan(target, ports, scan_type)
                    self.append_output(out)
                else:
                    self.append_output('Nenhum scanner disponível (nenhum script informado e import interno falhou).\n')
            except Exception as e:
                self.append_output(f'Erro ao executar o scanner: {e}\n')
            end_time = datetime.utcnow()
            self.append_output(f'[{end_time.isoformat()}] Scan finalizado. Duração: {end_time - start_time}\n')

        threading.Thread(target=worker, daemon=True).start()

    def show_explain(self):
        explain = (
            'Campos:\n'
            '- Alvo: IP ou hostname do host a ser escaneado.\n'
            '- Portas / Faixa: ex: "22,80,443" ou "1-1024".\n'
            '- Tipo de Scan: modos simples para demonstração (quick, full, tcp).\n'
            '\nUse um script externo se quiser integrar seu próprio "nmap caseiro".\n')
        messagebox.showinfo('Explicação', explain)

    def save_report(self):
        content = self.output.get('1.0', 'end').strip()
        if not content:
            messagebox.showinfo('Salvar', 'Nada para salvar')
            return
        path = filedialog.asksaveasfilename(title='Salvar relatório', defaultextension='.txt', filetypes=[('Text','*.txt')])
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo('Salvar', f'Relatório salvo em {path}')
            except Exception as e:
                messagebox.showerror('Erro', f'Falha ao salvar: {e}')

def main():
    app = NmapGUI()
    app.mainloop()

if __name__ == '__main__':
    main()
