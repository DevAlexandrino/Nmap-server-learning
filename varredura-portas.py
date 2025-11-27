import socket
import threading
from queue import Queue
import time
import sys

# Numero Max de threads
THREADS_MAX = 200

fila_portas = Queue()
ip_alvo_global = ""

# --- Funções ---

def varrer_porta(ip_alvo, porta):
    """
    Tenta estabelecer uma conexão TCP e, se for bem-sucedida,
    tenta ler o banner para identificar o serviço.
    """
    try:
        # Cria um novo objeto socket (AF_INET = IPv4, SOCK_STREAM = TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        resultado = s.connect_ex((ip_alvo, porta)) #retorna 0 se for bem sucedida        
        if resultado == 0:
            servico_identificado = ""
            
            # --- 1. Detecção Padrão (Fallback) ---
            try:
                # Tenta primeiro a detecção padrão pelo número da porta
                servico_identificado = socket.getservbyport(porta, 'tcp')
            except OSError:
                servico_identificado = "Desconhecido"
            
            # --- 2. Análise de Banner (Avançada) ---
            try:
                # Define um timeout ainda mais curto para a leitura
                s.settimeout(0.5) 
                # Tenta ler os primeiros 1024 bytes (o banner)
                banner = s.recv(1024)
                
                # Decodifica o banner (ignora erros de encoding)
                banner_str = banner.decode(errors='ignore').strip()
                print("Banner: " + banner_str)
                
                if banner_str:
                    
                    # Logica simples de identificação de serviço pelo conteúdo do banner:
                    # Pega apenas a primeira linha do banner para manter a saída limpa
                    primeira_linha = banner_str.splitlines()[0][:50]
                    
                    if primeira_linha.upper().startswith("SSH"):
                        servico_identificado = f"SSH (Banner: {primeira_linha}...)"
                    elif "HTTP" in primeira_linha.upper() or "APACHE" in primeira_linha.upper() or "NGINX" in primeira_linha.upper():
                        servico_identificado = f"HTTP/Web (Banner: {primeira_linha}...)"
                    elif "FTP" in primeira_linha.upper():
                        servico_identificado = f"FTP (Banner: {primeira_linha}...)"
                    elif "SMTP" in primeira_linha.upper() or "MAIL" in primeira_linha.upper():
                        servico_identificado = f"SMTP/Mail (Banner: {primeira_linha}...)"
                    elif "MYSQL" in primeira_linha.upper():
                         servico_identificado = f"MySQL (Banner: {primeira_linha}...)"
                    else:
                         # Se o banner não corresponder a um padrão, usa o banner encontrado
                         servico_identificado = f"Banner: {primeira_linha}..."
                
            except socket.timeout:
                # O servidor não respondeu com um banner a tempo (não é um erro grave)
                pass 
            except Exception:
                # Outros erros (ex: "Connection reset by peer")
                pass
            print(f"Porta {porta} está ABERTA ({servico_identificado})")
        
        # Fecha o socket
        s.close()
        
    except socket.gaierror:
        # Erro ao tentar resolver o nome de host
        print(f"\nErro: O nome de host '{ip_alvo}' não pôde ser resolvido.")
        sys.exit()
    except socket.error:
        pass

def worker():  # função na qual cada thread vai usar para executar
    while True:
        porta = fila_portas.get()
        varrer_porta(ip_alvo_global, porta)
        fila_portas.task_done()

def main_scanner(ip_alvo, portas_inicio=None, portas_fim=None, port_list=None):
    """
    Função principal para configurar e iniciar a varredura.
    Pode receber um intervalo (portas_inicio, portas_fim) ou uma lista (port_list).
    """
    global ip_alvo_global
    ip_alvo_global = ip_alvo
    
    print(f"Iniciando varredura de portas no alvo: **{ip_alvo}**")
    if port_list:
        print(f"Portas a serem varridas: {port_list}")
    elif portas_inicio is not None and portas_fim is not None:
        print(f"Portas a serem varridas: {portas_inicio} a {portas_fim}")
    else:
        print("Nenhuma porta especificada para varredura.")
        return
    print("-" * 50)
    
    # 1. Cria as Threads
    for _ in range(THREADS_MAX):
        t = threading.Thread(target=worker)
        # Permite que o programa feche mesmo com as threads ativas
        t.daemon = True 
        t.start()
        
    # 2. Preenche a Fila com as Portas
    if port_list:
        for porta in port_list:
            fila_portas.put(porta)
    else:
        for porta in range(portas_inicio, portas_fim + 1):
            fila_portas.put(porta)
        
    # 3. Espera o Fim da Varredura
    fila_portas.join()
    
    print("-" * 50)
    print(f"Varredura no alvo {ip_alvo} concluída.")

# --- Execução Principal ---
if __name__ == "__main__":
    
    # PEÇA ao usuário para inserir o alvo e o intervalo de portas
    try:
        target_ip = input("Digite o IP ou nome de host alvo (ex: 127.0.0.1): ").strip()
        start_port = int(input("Porta inicial (ex: 1): "))
        end_port = int(input("Porta final (ex: 1024): "))
    except ValueError:
        print("Entrada inválida.")
        sys.exit()
    
    if start_port > end_port or start_port < 1 or end_port > 65535:
        print("Intervalo de portas inválido.")
        sys.exit()
        
    tempo_inicial = time.time()
    main_scanner(target_ip, start_port, end_port)  # função responsável por procurar os serviços ativos 
    
    tempo_final = time.time()
    tempo_total = tempo_final - tempo_inicial
    
    print(f"Tempo total de execução: **{tempo_total:.2f} segundos**.")
