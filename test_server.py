import threading
import socket
import ssl
import time

# Porta e serviço
PORTS = {
    'ssh': 2222,      # SSH custom port
    'http': 8080,     # HTTP
    'https': 8443,    # HTTPS
    'smtp': 2525      # SMTP custom port
}

_threads = []

# Servidor genérico
class DummyServer(threading.Thread):
    def __init__(self, port, handler=None, use_ssl=False):
        super().__init__(daemon=True)
        self.port = port
        self.handler = handler or self.default_handler
        self.use_ssl = use_ssl
        self.running = True
        self.sock = None
    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.listen(5)
        if self.use_ssl:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(self.sock, server_side=True)
        while self.running:
            try:
                client, addr = self.sock.accept()
                threading.Thread(target=self.handler, args=(client, addr), daemon=True).start()
            except Exception:
                continue
    def default_handler(self, client, addr):
        try:
            # Simula um banner genérico
            if self.port == PORTS['ssh']:
                client.send(b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n")
            client.send(b"Bem-vindo ao servidor de teste generico!\n")
            time.sleep(0.5)
        except Exception:
            pass
        finally:
            client.close()

def http_handler(client, addr):
    try:
        req = client.recv(1024)
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n\r\n"
            "<html><body><h1>Servidor Nmap de Teste Caseiro</h1><p>Este servidor HTTP esta funcionando!</p></body></html>"
        )
        client.sendall(response.encode())
    except Exception:
        pass
    finally:
        client.close()

def https_handler(client, addr):
    try:
        req = client.recv(1024)
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n\r\n"
            "<html><body><h1>Servidor Nmap de Teste Caseiro</h1><p>Este servidor HTTPS esta funcionando via SSL!</p></body></html>"
        )
        client.sendall(response.encode())
    except Exception:
        pass
    finally:
        client.close()

def smtp_handler(client, addr):
    try:
        # Envia uma saudação SMTP padrão
        client.send(b"220 test-server ESMTP Postfix\r\n")
        time.sleep(0.5)
        client.recv(1024)
        client.send(b"250 Ok\r\n")
    except Exception:
        pass
    finally:
        client.close()

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass

def start_test_servers():
    global _threads
    stop_test_servers()
    _threads = []
    _threads.append(DummyServer(PORTS['ssh']))
    _threads.append(DummyServer(PORTS['http'], handler=http_handler))
    _threads.append(DummyServer(PORTS['https'], handler=https_handler, use_ssl=False)) # SSL pode dar erro sem certs
    _threads.append(DummyServer(PORTS['smtp'], handler=smtp_handler))
    for t in _threads:
        t.start()
    return PORTS

def stop_test_servers():
    global _threads
    for t in _threads:
        try:
            t.stop()
        except Exception:
            pass
    _threads = []

def get_test_server_ports():
    return PORTS

if __name__ == "__main__":
    print("Iniciando servidores de teste...")
    start_test_servers()
    print(f"Serviços abertos: {PORTS}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_test_servers()
        print("Servidores encerrados.")
