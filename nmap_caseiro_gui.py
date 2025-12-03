#!/usr/bin/env python3
# coding: utf-8
"""
Interface gráfica para o "nmap caseiro".

Funcionalidades:
- Escolha entre Descoberta de Hosts (ARP) ou Varredura de Portas
- Campo para alvo e botão para descobrir IP local
- Executa scanner ou host-discovery e mostra resultado na tela
- Salva relatório em arquivo
- Explicação dos modos e do servidor de teste

Empacotamento: usar `pyinstaller --onefile nmap_caseiro_gui.py`
"""
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
import threading
import sys
import importlib
import webbrowser
import re
from datetime import datetime, timezone

try:
    host_discovery = importlib.import_module("host-discovery")
except Exception as e:
    host_discovery = None
    # Imprime o erro no terminal para depuração
    print(f"Aviso: Falha ao carregar o módulo 'host-discovery': {e}")
try:
    import test_server
except Exception:
    test_server = None
try:
    # Importa o módulo com hífen no nome
    varredura_portas = importlib.import_module("varredura-portas")
except Exception:
    varredura_portas = None

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class TextRedirector:
    def __init__(self, widget):
        self.widget = widget

    def write(self, text):
        self.widget.insert(ctk.END, text)
        self.widget.see(ctk.END)

    def flush(self):
        pass

class NmapGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('Nmap Caseiro - Interface')
        self.discovered_hosts = []

        self.geometry('1100x720')
        self.minsize(900, 620)

        self.default_font = ("Helvetica", 14)
        self.header_font = ("Helvetica", 18, "bold")

        self._build()

    def _build(self):
        container = ctk.CTkFrame(self, corner_radius=0)
        container.pack(fill='both', expand=True)

        top_frame = ctk.CTkFrame(container, fg_color=("gray17", "#071428"), corner_radius=12)
        top_frame.pack(fill='x', padx=14, pady=(14, 6), ipady=9)

        # 4 colunas na mesma linha
        top_frame.grid_columnconfigure((0,1,2,3,4,5,6,7), weight=1)

        # ---------- MODO ----------
        lbl_modo = ctk.CTkLabel(top_frame, text="Modo:", font=self.default_font)
        lbl_modo.grid(row=0, column=0, sticky="w", padx=(18, 6), pady=8)

        self.mode_var = tk.StringVar(value='scan')
        self.mode_menu = ctk.CTkOptionMenu(
            top_frame, values=['scan', 'host-discovery'], variable=self.mode_var,
            width=160, corner_radius=12
        )
        self.mode_menu.grid(row=0, column=1, sticky="ew", padx=6, pady=8)

        # ---------- ALVO ----------
        lbl_alvo = ctk.CTkLabel(top_frame, text="Alvo:", font=self.default_font)
        lbl_alvo.grid(row=0, column=2, sticky="w", padx=(18, 6), pady=8)

        self.target_var = tk.StringVar(value='127.0.0.1')
        self.target_entry = ctk.CTkEntry(
            top_frame, textvariable=self.target_var, height=38, corner_radius=10
        )
        self.target_entry.grid(row=0, column=3, sticky="ew", padx=6, pady=8)

        # ---------- PORTA INICIAL ----------
        lbl_p_ini = ctk.CTkLabel(top_frame, text="Porta inicial:", font=self.default_font)
        lbl_p_ini.grid(row=0, column=4, sticky="w", padx=(18, 6), pady=8)

        self.start_port_var = tk.StringVar(value='1')
        self.start_port_entry = ctk.CTkEntry(
            top_frame, textvariable=self.start_port_var, width=100,
            height=36, corner_radius=10
        )
        self.start_port_entry.grid(row=0, column=5, sticky="ew", padx=6, pady=8)

        # ---------- PORTA FINAL ----------
        lbl_p_fim = ctk.CTkLabel(top_frame, text="Porta final:", font=self.default_font)
        lbl_p_fim.grid(row=0, column=6, sticky="w", padx=(18, 6), pady=8)

        self.end_port_var = tk.StringVar(value='1024')
        self.end_port_entry = ctk.CTkEntry(
            top_frame, textvariable=self.end_port_var, width=100,
            height=36, corner_radius=10
        )
        self.end_port_entry.grid(row=0, column=7, sticky="ew", padx=6, pady=8)

        # botões principais
        btn_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        btn_frame.grid(row=2, column=0, columnspan=8, pady=(18,6), padx=12, sticky="ew")
        btn_frame.grid_columnconfigure((0,1,2), weight=1)

        self.discover_btn = ctk.CTkButton(btn_frame, text="Descobrir IP", height=36, corner_radius=14, command=self.show_local_ip)
        self.discover_btn.grid(row=0, column=0, padx=12, pady=6, sticky="ew")

        self.run_btn = ctk.CTkButton(btn_frame, text="Run Scan", height=36, corner_radius=14, command=self.run_operation)
        self.run_btn.grid(row=0, column=1, padx=12, pady=6, sticky="ew")

        self.scan_all_btn = ctk.CTkButton(btn_frame, text="Scan All Found", height=36, corner_radius=14, command=self.scan_all_discovered_hosts)
        self.scan_all_btn.grid(row=0, column=2, padx=12, pady=6, sticky="ew")

        # ações rápidas
        quick_frame = ctk.CTkFrame(container, fg_color=("gray16","#061523"), corner_radius=12)
        quick_frame.pack(fill='x', padx=14, pady=(14, 6), ipady=9)
        quick_frame.grid_columnconfigure((0,1), weight=1)

        lbl_quick = ctk.CTkLabel(quick_frame, text="Ações Rápidas", font=self.header_font)
        lbl_quick.grid(row=0, column=0, columnspan=2, sticky="w", padx=18, pady=(12,6))

        # Linha de botões 1
        btn_q1 = ctk.CTkButton(quick_frame, text="Analisar Servidor", height=36, corner_radius=14, command=self.analyze_test_server)
        btn_q1.grid(row=1, column=0, padx=18, pady=(6,10), sticky="ew")
        btn_q2 = ctk.CTkButton(quick_frame, text="Abrir Servidor", height=36, corner_radius=14, command=self.start_test_server)
        btn_q2.grid(row=1, column=1, padx=18, pady=(6,10), sticky="ew")

        # Linha de botões 2
        btn_q3 = ctk.CTkButton(quick_frame, text="Abrir Web", height=36, corner_radius=14, command=self.open_test_webpage)
        btn_q3.grid(row=2, column=0, padx=18, pady=(6,18), sticky="ew")
        btn_q4 = ctk.CTkButton(quick_frame, text="Save Report", height=36, corner_radius=14, command=self.save_report)
        btn_q4.grid(row=2, column=1, padx=18, pady=(6,18), sticky="ew")
        # Botão Explain
        btn_explain = ctk.CTkButton(quick_frame, text="Explain", height=36, corner_radius=14, command=self.show_explain)
        btn_explain.grid(row=3, column=0, columnspan=2, padx=18, pady=(6, 18), sticky="ew")


        # Área de resultados (Label + box)
        result_frame = ctk.CTkFrame(container, fg_color=("gray15","#04121a"), corner_radius=12)
        result_frame.pack(fill='both', expand=True, padx=14, pady=(14, 6), ipady=9)

        lbl_result = ctk.CTkLabel(result_frame, text="Resultados do scan", font=self.header_font)
        lbl_result.pack(anchor="nw", padx=18, pady=(18,6))

        text_outer = ctk.CTkFrame(result_frame, fg_color=("gray11","#02121a"), corner_radius=12)
        text_outer.pack(fill='both', expand=True, padx=18, pady=(6,18))

        # Barra de rolagem do lado direito (tk.Scrollbar pode ser usado)
        text_scroll_y = tk.Scrollbar(text_outer, orient='vertical')
        text_scroll_x = tk.Scrollbar(text_outer, orient='horizontal')

        self.output = tk.Text(text_outer, wrap='none', yscrollcommand=text_scroll_y.set, xscrollcommand=text_scroll_x.set, bg='#0b1b26', fg='#e6f1f8', insertbackground='white', relief='flat', padx=12, pady=12, font=("Helvetica", 16))
        self.output.pack(fill='both', expand=True, side='left')

        # configura scrollbars
        text_scroll_y.config(command=self.output.yview)
        text_scroll_y.pack(side='right', fill='y')
        text_scroll_x.config(command=self.output.xview)
        text_scroll_x.pack(side='bottom', fill='x')

        # Configuração de tags para texto clicável
        self.output.tag_configure("clickable_ip", foreground="#63b3ff", underline=True)
        self.output.tag_bind("clickable_ip", "<Enter>", self._on_enter_ip)
        self.output.tag_bind("clickable_ip", "<Leave>", self._on_leave_ip)
        self.output.tag_bind("clickable_ip", "<Button-1>", self._on_ip_click)

        self.on_mode_change()

    def on_mode_change(self, event=None):
        mode = self.mode_var.get()
        if mode == 'scan':
            self.run_btn.configure(text='Run Scan')
        elif mode == 'host-discovery':
            self.run_btn.configure(text='Run Discovery')

    def _on_enter_ip(self, event):
        self.output.config(cursor="hand2")

    def _on_leave_ip(self, event):
        self.output.config(cursor="")

    def _on_ip_click(self, event):
        # Pega o texto da tag na posição do clique
        index = self.output.index(f"@{event.x},{event.y}")
        tag_ranges = self.output.tag_ranges("clickable_ip")
        for i in range(0, len(tag_ranges), 2):
            if self.output.compare(tag_ranges[i], "<=", index) and self.output.compare(index, "<", tag_ranges[i+1]):
                ip = self.output.get(tag_ranges[i], tag_ranges[i+1])
                self.target_var.set(ip)
                self.mode_var.set('scan')
                self.on_mode_change()
                self.run_operation()
                break

    def show_local_ip(self):
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = '127.0.0.1'
        
        network_part = ip.rsplit('.', 1)[0]
        
        msg = (
            f"Seu IP local é: {ip}\n\n"
            f"Para descobrir todos os dispositivos na sua rede (celulares, TVs, etc.), você precisa escanear a 'faixa de rede'. A forma mais comum é usando a notação CIDR.\n\n"
            f"Exemplo para a sua rede: **{network_part}.0/24**\n\n"
            f"**O que isso significa?**\n"
            f"- `{network_part}`: Identifica a sua rede local.\n"
            f"- `.0`: É uma convenção para se referir à rede inteira, e não a um dispositivo específico.\n"
            f"- `/24`: Diz ao programa para testar todos os 254 endereços possíveis dentro da sua rede (de `{network_part}.1` a `{network_part}.254`).\n\n"
            f"**Instrução:** Para escanear sua rede, selecione o modo 'host-discovery' e use `{network_part}.0/24` como alvo."
        )
        messagebox.showinfo('Como Escanear sua Rede', msg)

    def append_output(self, text: str):
        self.output.insert('end', text)
        self.output.see('end')

    def run_operation(self):
        mode = self.mode_var.get()
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning('Falha', 'Informe o alvo')
            return
        
        # Limpa a lista de hosts e desabilita o botão de scan em massa
        self.discovered_hosts.clear()
        self.scan_all_btn.configure(state='disabled')
        self.output.delete('1.0', 'end')
        def worker():
            start_time = datetime.now(timezone.utc)
            self.append_output(f'[{start_time.isoformat()}] Iniciando operação: {mode} em {target}...\n')
            try:
                if mode == 'host-discovery':
                    if host_discovery is not None:
                        self._run_host_discovery(target)
                    else:
                        self.append_output('host-discovery não disponível.\n')
                else:
                    # Modo 'scan' padrão usa varredura_portas com intervalo 1-1024
                    if varredura_portas is not None:
                        try:
                            start_port = int(self.start_port_var.get())
                            end_port = int(self.end_port_var.get())
                            if start_port <= 0 or end_port > 65535 or start_port > end_port:
                                raise ValueError("Intervalo de portas inválido.")
                            self._run_port_scan(target, start_port=start_port, end_port=end_port)
                        except ValueError as ve:
                            messagebox.showerror("Erro de Entrada", f"Intervalo de portas inválido. Verifique os valores.\nDetalhe: {ve}")
                    else:
                        self.append_output('Módulo varredura_portas não disponível.\n')
            except Exception as e:
                self.append_output(f'Erro ao executar: {e}\n')
            end_time = datetime.now(timezone.utc)
            self.append_output(f'[{end_time.isoformat()}] Operação finalizada. Duração: {end_time - start_time}\n')
        threading.Thread(target=worker, daemon=True).start()

    def _run_host_discovery(self, target):
        """Executa a descoberta de hosts e formata a saída com IPs clicáveis."""
        # A função hostDiscovery retorna o resultado como uma string.
        # Não precisamos mais redirecionar o stdout para esta função específica.
        
        # Captura a saída que a função retorna
        result_content = host_discovery.hostDiscovery(target)
        
        # Encontra e armazena os IPs
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.discovered_hosts = ip_pattern.findall(result_content)
        
        # Limpa a tela antes de adicionar o novo conteúdo
        self.output.delete("1.0", tk.END)
        
        # Adiciona o conteúdo e o torna clicável
        self._make_ips_clickable(result_content)

        # Habilita o botão se algum host foi encontrado
        if self.discovered_hosts:
            self.scan_all_btn.configure(state='normal')

    def _run_port_scan(self, target, start_port=None, end_port=None, port_list=None):
        """Função auxiliar para executar o scanner de portas e redirecionar a saída."""
        if not varredura_portas:
            self.append_output('Módulo varredura_portas não disponível.\n')
            return

        # Redireciona stdout para o widget de texto
        original_stdout = sys.stdout
        sys.stdout = TextRedirector(self.output)
        
        try:
            varredura_portas.main_scanner(target, start_port, end_port, port_list)
        finally:
            # Garante que stdout seja restaurado mesmo se ocorrer um erro
            sys.stdout = original_stdout

    def _make_ips_clickable(self, content):
        """Encontra IPs no texto e os torna clicáveis."""
        self.output.delete("1.0", tk.END)
        
        # Regex para encontrar IPs no formato X.X.X.X
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        last_end = 0
        for match in ip_pattern.finditer(content):
            start, end = match.span()
            self.output.insert(tk.END, content[last_end:start])
            self.output.insert(tk.END, match.group(0), ("clickable_ip",))
            last_end = end
        self.output.insert(tk.END, content[last_end:])

    def scan_all_discovered_hosts(self):
        """Inicia uma varredura de portas em todos os hosts descobertos."""
        if not self.discovered_hosts:
            messagebox.showinfo("Info", "Nenhum host descoberto para escanear.")
            return

        self.output.delete('1.0', 'end')
        
        def worker():
            start_time = datetime.now(timezone.utc)
            
            # Obtém e valida o intervalo de portas da GUI
            try:
                start_port = int(self.start_port_var.get())
                end_port = int(self.end_port_var.get())
                if start_port <= 0 or end_port > 65535 or start_port > end_port:
                    raise ValueError("Intervalo de portas inválido.")
            except ValueError as ve:
                messagebox.showerror("Erro de Entrada", f"Intervalo de portas inválido para a varredura em massa.\nDetalhe: {ve}")
                return

            self.append_output(f"[{start_time.isoformat()}] Iniciando varredura em {len(self.discovered_hosts)} hosts...\n\n")
            for host in self.discovered_hosts:
                self.append_output(f"--- Analisando host: {host} ---\n")
                self._run_port_scan(host, start_port=start_port, end_port=end_port)
                self.append_output(f"--- Análise de {host} concluída ---\n\n")
            end_time = datetime.now(timezone.utc)
            self.append_output(f'[{end_time.isoformat()}] Varredura em massa finalizada. Duração: {end_time - start_time}\n')
        threading.Thread(target=worker, daemon=True).start()

    def analyze_test_server(self):
        self.target_var.set('127.0.0.1')
        if test_server:
            ports_to_scan = list(test_server.get_test_server_ports().values())
            self.output.delete('1.0', 'end')
            threading.Thread(target=self._run_port_scan, args=('127.0.0.1',), kwargs={'port_list': ports_to_scan}, daemon=True).start()

    def start_test_server(self):
        if test_server is not None:
            test_server.start_test_servers()
            self.append_output('Servidor de teste iniciado nas portas: ' + str(test_server.get_test_server_ports()) + '\n')
        else:
            self.append_output('Módulo test_server não disponível.\n')

    def open_test_webpage(self):
        if test_server:
            port = test_server.get_test_server_ports().get('http', 8080)
            url = f"http://127.0.0.1:{port}"
            self.append_output(f"Abrindo {url} no navegador...\n")
            webbrowser.open(url)

    def show_explain(self):
        explain_window = ctk.CTkToplevel(self)
        explain_window.title("Explicação Detalhada")
        explain_window.geometry("700x550")

        explain_window.transient(self)
        explain_window.grab_set()

        textbox = ctk.CTkTextbox(
            explain_window,
            width=650,
            height=500,
            corner_radius=12,
            fg_color="#071927",
            text_color="white"
        )
        textbox.pack(fill='both', expand=True, padx=10, pady=10)

        explain_text = (
            "--- Como Usar a Ferramenta ---\n\n"
            "1. Descoberta de Hosts:\n"
            "   - Clique em 'Descobrir IP da rede' para saber o endereço da sua rede.\n"
            "   - No campo 'Alvo', insira o endereço da sua rede (ex: 192.168.1.0/24).\n"
            "   - Mude o 'Modo' para 'host-discovery' e clique em 'Run Discovery'.\n"
            "   - Os IPs encontrados aparecerão como links azuis.\n\n"
            "2. Varredura de Portas (Scan):\n"
            "   - Clique em um IP azul encontrado ou digite um alvo manualmente.\n"
            "   - O modo mudará para 'scan' automaticamente. Clique em 'Run Scan'.\n"
            "   - Para escanear todos os hosts encontrados de uma vez, clique em 'Scan All Found'.\n\n"
            "3. Servidor de Teste:\n"
            "   - 'Abrir servidor de teste': Inicia serviços falsos no seu PC para você poder escanear.\n"
            "   - 'Analisar Servidor de Teste': Escaneia seu próprio PC para encontrar esses serviços.\n"
            "   - 'Abrir Página Web de Teste': Abre a página web do servidor de teste no seu navegador.\n\n"
            "--- Protocolos de Rede Utilizados ---\n\n"
            "• ARP (Address Resolution Protocol) - (Usado no 'host-discovery')\n"
            "   Como funciona: O programa 'pergunta' na sua rede local: 'Quem tem o IP 192.168.1.5?'. Se um dispositivo tiver esse IP, ele responde com seu endereço físico (MAC Address). É como perguntar o nome de alguém em uma sala e esperar a pessoa levantar a mão. Se alguém responde, o host está ativo.\n\n"
            "• TCP (Transmission Control Protocol) - (Usado no 'scan' de portas)\n"
            "   Como funciona: TCP é um protocolo confiável que garante a entrega de dados. A varredura de portas usa o 'handshake' de 3 vias do TCP. O programa envia um pedido de conexão (SYN) para uma porta. Se o host responde com um aceite (SYN/ACK), a porta está aberta. Se responde com uma recusa (RST) ou não responde, a porta está fechada ou filtrada.\n\n"
            "• HTTP/HTTPS (Hypertext Transfer Protocol) - (Simulado no servidor de teste)\n"
            "   Como funciona: É o protocolo da web. Seu navegador usa HTTP para pedir páginas a um servidor. O servidor de teste simula isso na porta 8080 (HTTP) e 8443 (HTTPS), respondendo com uma página HTML simples.\n\n"
            "• SSH (Secure Shell) e SMTP (Simple Mail Transfer Protocol) - (Simulados no servidor de teste)\n"
            "   Como funcionam: São protocolos de aplicação que rodam sobre TCP. O SSH (porta 2222 no teste) é para acesso remoto seguro, e o SMTP (porta 2525 no teste) é para envio de e-mails. O scanner tenta se conectar a essas portas e lê a mensagem de boas-vindas ('banner') para identificar o serviço."
        )

        # insere o texto e deixa somente leitura
        textbox.insert("1.0", explain_text)
        textbox.configure(state="disabled")

        close_button = ctk.CTkButton(explain_window, text="Fechar", command=explain_window.destroy)
        close_button.pack(pady=10)



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
    main()    # Adicionando a integração com varredura-portas.py
    