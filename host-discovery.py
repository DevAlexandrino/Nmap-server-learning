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

# Função que recebe a tuplaIP e retorna, apenas, o IP da rede. Exemplo de retorno: "192.168."
def criaAlvo(tuplaIP: tuple):
    mascara = tuplaIP[4]
    octetos = int(mascara/8)
    ipRede = ""
    for i in range(0, octetos):
        ipRede += f"{tuplaIP[i]}."
    return ipRede

# Essa função cria pacotes ARP, manda e espera resposta deles.
def arp(ip_alvo: str):
    pacote = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip_alvo)# Monto o pacote ARP
    resposta = scapy.srp(pacote, timeout=2.5, verbose=0)# Envia o pacote e espera a resposta na camada 2(Enlace de dados)
    if len(resposta[0]) > 0: # Testa se houve resposta ou não.
        ipResposta = resposta[0][0][1].psrc
        macResposta = resposta[0][0][1].hwsrc
        return f"host ativo: {ipResposta}\nEndereço MAC: {macResposta}\n"
    return ""


# Função recursiva que faz todas as combinações possíveis de IPs, seguindo a máscara de rede.
# Ela pula de octeto em octeto combinando eles para formar um IP alvo.
def combinacaoIP(tuplaIP: tuple, ipRede: str, octetoAtual: int, inicio=0, fim=255):
    output = io.StringIO()
    resultados = []

    def arp_thread(alvo: str):
        res = arp(alvo)
        if res:
            resultados.append(res)

    for i in range(inicio, fim):
        if octetoAtual < len(tuplaIP)-2: # Testa se está não está no octeto final.
            combinacaoIP(tuplaIP, ipRede + f"{i}.", octetoAtual + 1) # Pula para o próximo octeto.
            continue
        alvo = ipRede + f"{i}"
        thread = threading.Thread(target=arp_thread, args=(alvo,), kwargs={}, daemon=True)
        thread.start()

    for resultado in resultados:
        output.write(resultado)
        
    return output.getvalue()

# Função principal que 
def hostDiscovery(ip: str):
    inicio = time.time()
    output = io.StringIO()
    if '/' in ip:
        tuplaIP = criaTuplaIP(ip)
        mascara = tuplaIP[4]
        if mascara <= 16:
            print("A máscara de rede é muito baixa. Vai demorar consideravelmente. Recomendável diminuir o escopo")
            resposta = input("Continuar? (y/n): ")
            if resposta.lower() == "n":
                exit(1)
        resto = mascara % 8
        ipRede = criaAlvo(tuplaIP)
        octeto = int(mascara / 8)#indíce da tupla que acaba o IP da rede
        if resto == 0: # Não há bits de rede e hosts num mesmo octeto.
            respostas = combinacaoIP(tuplaIP, ipRede, octeto)
            output.write(respostas)
        else:
            # Dividindo os números de bits de rede por 8, eu separo quantos octetos (8 bits) há de redes.                   rede host
            # Se tiver resto, significa que há bits dentro de um octeto que são de redes e o resto dos bits são de hosts.   00 | 00000                                  
            quantidadeHosts = pow(2, 8-resto) # 2 siginifica o bit, aqui eu calculo quantos hosts a rede contém, pois fica fácil depois separar as redes.
            delimitador = 0
            print(tuplaIP[octeto])
            # A ideia aqui é encontrar o intervalo que o usuário quer escanear, esse intervalo depende da máscara de rede.
            while tuplaIP[octeto] >= delimitador:
                delimitador += quantidadeHosts
            if delimitador == 0:
                inicio = 0
            else:
                inicio = delimitador - quantidadeHosts
            respostas = combinacaoIP(tuplaIP, ipRede, octeto, inicio, delimitador)
    else: # Se for só um IP, então um arp é enviado, apenas.
        resposta = arp(ip)
        output.write(resposta)

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
        
        
