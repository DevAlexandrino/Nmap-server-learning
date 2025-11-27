
import scapy.all as scapy
import threading
import time
import io

# ------ FUNÇÕES ------
# Função que pega o ip (string), separa os octetos e a máscara de rede, e os coloca numa tupla.
# Exemplo de tuplaIP: (192, 168, 10, 0, 24)
def criaTuplaIP(ip: str):
    array = []
    temp = ""
    for caracter in ip:
        if caracter == '.' or  caracter == '/':
            array.append(int(temp))
            temp = ""
            continue
        temp += caracter
    array.append(int(temp))
    return (array[0], array[1], array[2], array[3], array[4])

# Essa função cria pacotes ARP, manda e espera resposta deles.
# Também guarda os endereços de resposta numa array.
def arp(ip_alvo: str, listaIPs):
    # Cria um quadro Ethernet para encapsular o pacote ARP.
    # 'ff:ff:ff:ff:ff:ff' é o endereço de broadcast, para perguntar a todos na rede.
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = scapy.ARP(pdst=ip_alvo)
    pacote = ether_frame/arp_request
    resposta = scapy.srp(pacote, timeout=2.5, verbose=0) # Usa srp para Camada 2
    if len(resposta[0]) > 0:
        ipResposta = resposta[0][0][1].psrc
        macResposta = resposta[0][0][1].hwsrc
        listaIPs.append((ipResposta, macResposta))
        return f"host ativo: {ipResposta}\nEndereço MAC: {macResposta}\n"
    return ""

def scan_network(network_prefix, start_host, end_host, listaIPs):
    output = io.StringIO()
    threads = []
    results = []

    def arp_thread(alvo):
        res = arp(alvo, listaIPs)
        if res:
            results.append(res)

    for i in range(start_host, end_host + 1):
        alvo = f"{network_prefix}.{i}"
        thread = threading.Thread(target=arp_thread, args=(alvo,), kwargs={})
        thread.start()
        threads.append(thread)

    for t in threads:
        t.join()

    results.sort() # Ordena os resultados por IP
    for r in results:
        output.write(r)
    return output.getvalue()

# Função principal que 
def hostDiscovery(ip: str):
    listaIPs = []
    inicio = time.time()
    output = io.StringIO()
    if '/' in ip:
        tuplaIP = criaTuplaIP(ip)
        mascara = tuplaIP[4]
        if mascara == 24:
            network_prefix = f"{tuplaIP[0]}.{tuplaIP[1]}.{tuplaIP[2]}"
            output.write(f"Varrendo rede {network_prefix}.0/24...\n")
            res = scan_network(network_prefix, 1, 254, listaIPs)
            output.write(res)
        else:
            output.write(f"Apenas máscaras /24 são suportadas no momento. Máscara fornecida: /{mascara}\n")
    else:
        res = arp(ip, listaIPs)
        output.write(res)
    fim = time.time()
    output.write(f"Varredura feita em: {fim - inicio:.3f} segundos\n")
    return output.getvalue()

# ------ PROGRAMA PRINCIPAL ------
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        ip = sys.argv[1]
        print(hostDiscovery(ip))
    else:
        print(hostDiscovery(input("IP ou rede: ")))
