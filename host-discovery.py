import scapy.all as scapy
import threading
import time

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
# Também guarda os endereços de resposta numa array.
def arp(ip_alvo: str, listaIPs):
    pacote = scapy.ARP(pdst=ip_alvo)# Monto o pacote ARP perguntando quem está com o IP que eu quero descobrir.
    resposta = scapy.sr(pacote, timeout=2.5, verbose=0)#scapy.sr envia e espera resposta de pacotes da camada 3(transporte)
    if len(resposta[0]) > 0: # Testa se houve resposta ou não.
        ipResposta = resposta[0][0][1].psrc
        macResposta = resposta[0][0][1].hwsrc
        listaIPs.append((ipResposta, macResposta))
        print(f"host ativo: {ipResposta}\nEndereço MAC: {macResposta}")


# Função recursiva que faz todas as combinações possíveis de IPs, seguindo a máscara de rede.
# Ela pula de octeto em octeto fazendo combinações entre eles.
def combinacaoIP(tuplaIP: tuple, ipRede: str, octetoAtual: int, inicio=0, fim=255):
    listaIPs = []
    print(f"Rede: {ipRede}")
    print(f"Inicio de host: {inicio}, final de host: {fim}")
    for i in range(inicio, fim):
        if octetoAtual < len(tuplaIP)-2:
            combinacaoIP(tuplaIP, ipRede + f"{i}.", octetoAtual + 1)
            continue
        alvo = ipRede + f"{i}"
        thread = threading.Thread(target=arp, args=(alvo, listaIPs,), kwargs={})
        thread.start()
    return listaIPs

# Função principal que 
def hostDiscovery(ip: str):
    listaIPs = []
    inicio = time.time()
    if ip[len(ip)-3] == '/':
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
            listaIPs = combinacaoIP(tuplaIP, ipRede, octeto)
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
            combinacaoIP(tuplaIP, ipRede, octeto, inicio, delimitador)
    else:
        arp(ip, listaIPs)
    fim = time.time()
    print(f"Varredura feita em: {fim - inicio:.3f} segundos")
    # Iteração somente para debugar, não ficará na versão final
    for tupla in listaIPs:
        print(tupla)

# ------ PROGRAMA PRINCIPAL ------
hostDiscovery(input())
