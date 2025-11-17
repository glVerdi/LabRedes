import socket  
import struct
import sys
import os
import time
STORAGE_DIR = "logs"
if not os.path.exists(STORAGE_DIR):
 os.makedirs(STORAGE_DIR)
log_internet = "camada_internet.csv" #IPV4, IPV6 e ICMP
log_transporte = "camada_transporte.csv"#TCP e UDP
log_aplicacao = "camada_aplicacao.csv"#DHCP, DNS, HTTP, HTTPS  e NTP
caminho_log_i = os.path.join(STORAGE_DIR, log_internet)
caminho_log_t = os.path.join(STORAGE_DIR, log_transporte)
caminho_log_a = os.path.join(STORAGE_DIR, log_aplicacao) 
protocolo, endereço_destino, endereço_origem, id, Ip = 0, "Não definido ", "Não definido ", 0, " " #inicializa as variáveis que serão usadas nos protocolos, para caso o pacote recebido não seja IPV4 ou IPV6, não dê erro.
dados_transporte_aplicacao, tamanho_cabeçalho_ip = None, 0 #Será usado para pegar os dados da camada de transporte (TCP e UDP)

def impressao(cont_IPV4, cont_IPV6, cont_TCP, cont_UDP, cont_ICMP4, cont_ICMP6, cont_HTTP, cont_HTTPS, cont_DHCP, cont_DNS, cont_NTP, interface):
  print("=========================================================")
  print("        MONITOR DE TRÁFEGO DE REDE EM TEMPO REAL         ")
  print("=========================================================")
  print(f"Interface: {interface}")
  print("=========================================================")

  total = cont_IPV4 + cont_IPV6 + cont_ICMP4 + cont_ICMP6
  app = cont_HTTP + cont_HTTPS + cont_DNS + cont_DHCP + cont_NTP
  outros = total - app
  print("\n")
  print("CAMADA DE INTERNET (Network Layer)")
  print("---------------------------------------------------------")
  print(f"  IPv4:   {cont_IPV4} pacotes")
  print(f"  IPv6:   {cont_IPV6} pacotes")
  print(f"  ICMP4:  {cont_ICMP4} pacotes")
  print(f"  ICMP6:  {cont_ICMP6} pacotes")


  print("\n")
  print("CAMADA DE TRANSPORTE (Transport Layer)")
  print("---------------------------------------------------------")
  print(f"  TCP:    {cont_TCP} pacotes")
  print(f"  UDP:    {cont_UDP} pacotes")

  print("\n")
  print("CAMADA DE APLICAÇÃO (Application Layer)")
  print("---------------------------------------------------------")
  print(f"  HTTP:   {cont_HTTP} pacotes")
  print(f"  HTTPS:  {cont_HTTPS} pacotes")
  print(f"  DHCP:   {cont_DHCP} pacotes")
  print(f"  DNS:    {cont_DNS} pacotes")
  print(f"  NTP:    {cont_NTP} pacotes")
  print(f"  Outros: {outros} pacotes")
  print("\n")
  print("=========================================================")
  print(f"TOTAL: {total} pacotes capturados")
  print("=========================================================")

interface = "tun0" 
cont_IPV4, cont_IPV6, cont_TCP, cont_UDP, cont_ICMP4, cont_ICMP6, cont_HTTP, cont_HTTPS, cont_DHCP, cont_DNS, cont_NTP = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 #contadores dos protocolos
socketM = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
socketM.bind((interface, 0))
print("Socket criado com sucesso, monitorando a interface " + interface)


try:#Escreve nos logs quando começa um novo monitoramento(inicia o programa)
 inicio = "\n------------------------INICIANDO NOVO MONITORAMENTO------------------------\n"
 with open(caminho_log_i, "a") as l:
  l.write(inicio)
  l.write("Nome do Protocolo, Data, Número do Protocolo, IP de Origem, IP de Destino, Id, Tamanho \n")
 with open(caminho_log_t, "a") as l:
  l.write(inicio)
  l.write("Nome do Protocolo, Data, Número do Protocolo, IP de Origem, Porta de Origem, IP de Destino, Porta de Destino, Tamanho \n")
 with open(caminho_log_a, "a") as l:
  l.write(inicio)
  l.write("Nome do Protocolo, Data, IP de Origem, IP de Destino, Tamanho \n")
except Exception as e:
 print("Erro ao escrever o cabeçalho do log" + str(e)) 
 exit()
try:
 while True:
  pacote, addr = socketM.recvfrom(65565) #tamanho máximo do pacote
  hora = time.ctime()
  print("Pacote recebido!")
  ether_header = pacote[:14]
  endereço_origem, endereço_destino, ether_type = struct.unpack('! 6s 6s H', ether_header)#Divide o pacote nos seus respectivos dados, primeiros 6 bytes para MAC de origem, próximos 6 para MAC destino e os últimos 2 para o tipo.

  if ether_type ==  0x0800:#IPV4
   print("O protocolo recebido é IPV4")
   versao_byte = pacote[14] #pega o primeiro byte do cabeçalho IP, version cujos últimos 4 bits são o ihl, internet header length
   ihl = versao_byte & 0x0F #zera os primeiros 4 bits, que são a versão, e pega o ihl para calcular o tamanho do IP
   tamanho_cabeçalho_ip = ihl * 4 #passando para bytes
   pacote_ip = pacote[14:14 + tamanho_cabeçalho_ip]#Pega as informações do cabeçalho IP, que são 20 bytes
   dados_transporte_aplicacao = pacote[14+tamanho_cabeçalho_ip:]#Pega os dados depois do cabeçalho IP, transporte e aplicação
   cont_IPV4 += 1
   print("Por enquanto foram recebidos " + str(cont_IPV4) +" pacotes IPV4")
   Ip = "IPV4" #B = 1 byte, H = 2 bytes, 4s = 4 bytes string 
   versao, tos, tamanho_total_Ip, id, offset, ttl, protocolo, checksum, endereço_origem, endereço_destino = struct.unpack('! B B H H H B B H 4s 4s', pacote_ip[:20])#Pega todas informações do cabeçalho IP. O tamanho é o cabeçalho IP + dados IP recebidos
   endereço_origem = socket.inet_ntoa(endereço_origem) # Traduz o endereço de bytes para string padrão(ex 192.168.8.0)
   endereço_destino = socket.inet_ntoa(endereço_destino)
   with open (caminho_log_i, "a") as l: 
    l.write("IPV4," + hora + ", " + str(protocolo) + ", " + str(endereço_origem) + ", " + str(endereço_destino) + ", " + str(id) + ", " + str(tamanho_total_Ip) + "\n")

  elif ether_type == 0x86DD:#IPV6
   print("O protocolo recebido é IPV6")
   pacote_ip = pacote[14:54]#Pega as informações do cabeçalho IP
   tamanho_cabeçalho_ip = 40 #Tamanho do cabeçalho de IPV6 sempre será 40
   dados_transporte_aplicacao = pacote[54:]
   cont_IPV6 += 1
   Ip = "IPV6"
   print("Por enquanto foram recebidos " + str(cont_IPV6) +" pacotes IPV6")
   campos_ipv6 = struct.unpack('! L H B B 16s 16s', pacote_ip) #agrupa os primeiros 32 bits(version, traffic class e flow_label), pois não são dividos em bytes inteiros 
   id = campos_ipv6[0] & 0x000FFFFF #zera os primeiros 12 bits (version e traffic class, que não serão usados) para pegar os últimos 20, que são o flow label, id = flow label, foi colocado como id para organização do código
   tamanho_total_Ip = campos_ipv6[1] + 40 #40 é o tamanho do cabeçalho IP, campos_ipv6[1] é o payload_length
   protocolo = campos_ipv6[2]#será o prox_header, colocado como protocolo para organização do código
   endereço_origem = socket.inet_ntop(socket.AF_INET6, campos_ipv6[4]) # Traduz o endereço de bytes para string padrão IPV6
   endereço_destino = socket.inet_ntop(socket.AF_INET6, campos_ipv6[5])
   with open(caminho_log_i, "a") as l:#O prox_header é o protocolo do próximo cabeçalho
    l.write("IPV6, " + hora + ", " + str(protocolo) + ", " + str(endereço_origem) + ", " + str(endereço_destino) + ", " + str(id) + ", " + str(tamanho_total_Ip) + "\n") 

  else: 
   print("O protocolo não é nem IPV4 nem IPV6") 
    
  if protocolo == 1:
   print("O protocolo recebido é ICMP4")
   cont_ICMP4 += 1
   header_icmp4 = dados_transporte_aplicacao[:4]#Pega apenas o cabeçalho ICMP
   if len(dados_transporte_aplicacao) < 4:
    print("Erro ao receber pacote ICMP4, cabeçalho + dados de aplicação é menor que 4 bytes. Ignorando-o ...")
    continue
   icmp_type, code, checksum = struct.unpack("! B B H", header_icmp4)
   info_icmp4 = f"Tipo: {icmp_type}, Código: {code}, Checksum: {checksum}"
   with open(caminho_log_i, "a") as l:
    l.write("ICMP4, " + hora + ", " + str(protocolo) + ", " + str(endereço_origem) + ", " + str(endereço_destino) + ", " + str(id) + ", " + str(tamanho_total_Ip) + ", " + info_icmp4 + "\n")

    
  elif protocolo == 58:
   print("O protocolo recebido é ICMP6")
   cont_ICMP6 += 1
   header_icmp6 = dados_transporte_aplicacao[:4] # Pega apenas o cabeçalho ICMP
   if len(dados_transporte_aplicacao) < 4:
    print("Erro ao receber pacote ICMP6, cabeçalho + dados de aplicação é menor que 4 bytes. Ignorando-o ...")
    continue
   icmp_type, code, checksum = struct.unpack("! B B H", header_icmp6)
   info_icmp6 = f"Tipo: {icmp_type}, Código: {code}, Checksum: {checksum}"
   with open(caminho_log_i, "a") as l: 
    l.write("ICMP6, " + hora + ", " + str(protocolo) + ", " + str(endereço_origem) + ", " + str(endereço_destino) + ", " + str(id) + ", " + str(tamanho_total_Ip) + ", " + info_icmp6 + "\n") 
    
  elif protocolo == 6:
   print("O protocolo recebido é TCP:") 
   cont_TCP += 1
   header_tcp = dados_transporte_aplicacao[:20]#Pega apenas o cabeçalho TCP, excluindo os dados da camada de aplicação. ASSUME QUE É 20 bytes!
   if(len(dados_transporte_aplicacao) < 20):
    print("Erro ao receber pacote TCP, cabeçalho + dados de aplicação é menor que 20 bytes. Ignorando-o ...")
    continue
   porta_origem, porta_destino, seq_number, ack_number, offset_reserved, flags, window, checksum, urg_pointer  = struct.unpack("! H H L L B B H H H", header_tcp)    
   tamanho_cabeçalho_tcp = (offset_reserved>>4) * 4 #Usado para ver onde começa os dados do protocolo de aplicação
   if(tamanho_cabeçalho_tcp < 20):
    print("Erro ao receber pacote TCP, cabeçalho é menor que 20 bytes. Ignorando-o ...")
    continue
   dados_aplicacao = dados_transporte_aplicacao[tamanho_cabeçalho_tcp:]
   tamanho_transporte = tamanho_total_Ip - tamanho_cabeçalho_ip #Tamanho do pacote TCP + dados TCP = Tamanho do pacote IP-Cabeçalho IP  
   with open(caminho_log_t, "a") as l:  
    l.write("TCP, " + hora + ", " + str(protocolo) + ", " + str(endereço_origem) + ", "  + str(porta_origem) + ", " + str(endereço_destino) + ", " + str(porta_destino) + ", " + str(tamanho_transporte) + "\n")

   protocolo_app = None 
   if porta_origem == 80 or porta_destino == 80:
    print("O protocolo recebido é HTTP:")
    protocolo_app = "HTTP"
    cont_HTTP += 1
    header_http = dados_aplicacao[:15]#Cabeçalho HTTP terá no mínimo 15 bytes (GET / HTTP/1.1\r\n)
    if(len(header_http)<15):
      print("Erro ao receber pacote HTTP, cabeçalho diferente de 15 bytes. Ignorando-o ... ") 
      continue
    elif header_http.startswith(b"GET") or header_http.startswith(b"POST") or header_http.startswith(b"HTTP/1.1"):
      info_http = header_http.decode(errors='ignore').replace('\r\n', ' ')
      with open(caminho_log_a, "a") as l:
       l.write("HTTP, " + hora + ", " + str(endereço_origem) + ", " +  str(endereço_destino) + ", " + info_http + "\n")

   elif porta_origem == 53 or porta_destino == 53:
    print("O protocolo recebido é DNS:")
    protocolo_app = "DNS"
    cont_DNS += 1
    # Precisa ter no mínimo 14 bytes (2 bytes de tamanho + 12 bytes de header DNS)
    if len(dados_aplicacao) < 14:
        print("Erro ao receber pacote DNS sobre TCP: tamanho insuficiente. Ignorando...")
        continue
    # primeiros 2 bytes do DNS = tamanho DNS
    tamanho_dns = struct.unpack("! H", dados_aplicacao[:2])[0]
    # agora sim cabeçalho DNS real (12 bytes)
    header_dns = dados_aplicacao[2:14]
    id_dns, flags_dns, qdcount, ancount, nscount, arcount = struct.unpack("! H H H H H H", header_dns)
    info_dns = (f"ID: {id_dns}, Flags: {flags_dns}, QDCOUNT: {qdcount}, ANCOUNT: {ancount}, NSCOUNT: {nscount}, ARCOUNT: {arcount}")
    with open(caminho_log_a, "a") as l:
        l.write("DNS (TCP), " + hora + ", " + str(endereço_origem) + ", " + str(endereço_destino) + ", " + info_dns + "\n")

   elif porta_origem == 443 or porta_destino == 443:
    print("O protocolo recebido é HTTPS:")
    protocolo_app = "HTTPS"
    cont_HTTPS += 1

  elif protocolo == 17:
   print("O protocolo recebido é UDP:") 
   cont_UDP += 1
   header_udp = dados_transporte_aplicacao[:8]#UDP sempre terá 8 bytes
   if(len(header_udp)!=8):
    print("Erro ao receber pacote UDP, cabeçalho diferente de 8 bytes. Ignorando-o ... ") 
    continue 
   porta_origem, porta_destino, tamanho_transporte, checksum = struct.unpack("! H H H H", header_udp)
   dados_aplicacao = dados_transporte_aplicacao[len(header_udp):]
   with open(caminho_log_t, "a") as l:  
    l.write("UDP, " + hora + ", " + str(protocolo) + ", " + str(endereço_origem) + ", "  + str(porta_origem) + ", " + str(endereço_destino) + ", " + str(porta_destino) + ", " + str(tamanho_transporte) + "\n") 

   protocolo_app = None 
   if porta_origem == 53 or porta_destino == 53:
    print("O protocolo recebido é DNS:")
    protocolo_app = "DNS"
    cont_DNS += 1
    header_dns = dados_aplicacao[:12]#Cabeçalho DNS sempre terá 12 bytes
    if(len(header_dns)<12):
      print("Erro ao receber pacote DNS sobre TCP, cabeçalho diferente de 12 bytes. Ignorando-o ... ") 
      continue
    id_dns, flags_dns, qdcount, ancount, nscount, arcount = struct.unpack("! H H H H H H", header_dns)
    info_dns = f"ID: {id_dns}, Flags: {flags_dns}, QDCOUNT: {qdcount}, ANCOUNT: {ancount}, NSCOUNT: {nscount}, ARCOUNT: {arcount}"
    with open(caminho_log_a, "a") as l:
      l.write("DNS, " + hora + ", " + str(endereço_origem) + ", " +  str(endereço_destino) + ", " + info_dns + "\n")
   
   elif porta_origem in (67, 68) and porta_destino in (67,68):
    print("O protocolo recebido é DHCP:")
    protocolo_app = "DHCP"
    cont_DHCP += 1
    heaadrer_dhcp = dados_aplicacao[:240]#Cabeçalho DHCP sempre terá 240 bytes
    if(len(heaadrer_dhcp)<240):
      print("Erro ao receber pacote DHCP, cabeçalho diferente de 240 bytes. Ignorando-o ... ") 
      continue
    op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr = struct.unpack("! B B B B I H H 4s 4s 4s 4s 16s", heaadrer_dhcp[:44])
    info_dhcp = f"Op: {op}, HType: {htype}, HLen: {hlen}, Hops: {hops}, Xid: {xid}, Secs: {secs}, Flags: {flags}"
    with open(caminho_log_a, "a") as l:
      l.write("DHCP, " + hora + ", " + str(endereço_origem) + ", " +  str(endereço_destino) + ", " + info_dhcp + "\n")

   elif porta_origem == 123 or porta_destino == 123:
    print("O protocolo recebido é NTP:")
    protocolo_app = "NTP"
    cont_NTP += 1
    header_ntp = dados_aplicacao[:48]#Cabeçalho NTP sempre terá 48 bytes
    if(len(header_ntp)<48):
      print("Erro ao receber pacote NTP, cabeçalho diferente de 48 bytes. Ignorando-o ... ") 
      continue
    li_vn_mode, stratum, poll, precision, root_delay, root_dispersion, ref_id = struct.unpack("! B B B B I I 4s", header_ntp[:16])
    info_ntp = f"LI_VN_Mode: {li_vn_mode}, Stratum: {stratum}, Poll: {poll}, Precision: {precision}, Root Delay: {root_delay}, Root Dispersion: {root_dispersion}"
    with open(caminho_log_a, "a") as l:
      l.write("NTP, " + hora + ", " + str(endereço_origem) + ", " +  str(endereço_destino) + ", " + info_ntp + "\n")

except KeyboardInterrupt:#Caso o usuário digite Control + C o programa encerra e imprime os resultados
 print("\n Monitoramento encerrado pelo usuário ")
 print("Fechando o socket ... \n")
 impressao(cont_IPV4, cont_IPV6, cont_TCP, cont_UDP, cont_ICMP4, cont_ICMP6, cont_HTTP, cont_HTTPS, cont_DHCP, cont_DNS, cont_NTP, interface)
 socketM.close() 
 exit(0) 
 