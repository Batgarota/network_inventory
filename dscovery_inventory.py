# -*- coding: utf-8 -*-
import pandas as pd
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor
import json
from threading import Lock
from netmiko import ConnectHandler
import re
import time
import paramiko.ssh_exception 
from netmiko.ssh_autodetect import SSHDetect
import paramiko

##############################################################################################
CREDENCIAIS = [
                {'username': '', 'password': ''},
                {'username': '', 'password': ''}
]


def verificar_erro_comando(output):
    padroes_erro = [
        r"command fail",
        r"command parse error",
        r"failed",
        r"error",
        r"invalid",
        r"not found",
        r"% ?(?:\w+|.+)",
        r"Pattern not detected",
        r"bad command",
        r"syntax error",
        r"command cannot be parsed"
    ]

    linhas = output.strip().splitlines()
    primeiras_linhas = linhas[:10]

    for linha in primeiras_linhas:
        for padrao in padroes_erro:
            if re.search(padrao, linha, re.IGNORECASE):
                return True
    return False




def carregar_arquivo1(arquivo_ativo1= r"/root/scripts/"):
    try:
        with open(arquivo_ativo1, "r") as f:
            return [linha.strip() for linha in f.readlines() if linha.strip()]
    except FileNotFoundError:
        print(f"Arquivo '{arquivo_ativo1}' não encontrado.")
        return []

##############################################################################################
def testar_conexao(ip, cred, metodo, porta):
    try:
        print(f"Testando conexão: {ip} via {metodo.upper()}:{porta} com {cred['username']}")

        device = {
            "host": ip,
            "username": cred["username"],
            "password": cred["password"],
            "port": int(porta),
            "timeout": 45,
            "banner_timeout": 30,
        }

        if metodo.lower() == "ssh":
            device["device_type"] = "generic"
        else:
            device["device_type"] = "generic_telnet"

        client = ConnectHandler(**device)
        print(f"Conectado com sucesso: {ip}")
        return True, client

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Falha na conexão via {metodo.upper()} com {ip}: {e}")
    except Exception as e:
        print(f"Erro inesperado na conexão com {ip}: {e}")

    return False, None



#conexao mikrotik
def testar_ssh_mk(ip, cred, metodo, porta):
    device = {
        'device_type': 'mikrotik_routeros',
        'host': ip,
        'username': cred['username'],
        'password': cred['password'],
        'port': int(porta),
        'timeout': 40,
        'banner_timeout': 30,
    }

    if metodo.lower() == 'ssh':
        try:
            client = ConnectHandler(**device)
            print(f"Mikrotik conectado com sucesso: {ip}")
            return True, client
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            print(f"Erro de autenticação ou timeout SSH Mikrotik {ip}: {e}")
        except Exception as e:
            print(f"Erro inesperado no SSH Mikrotik {ip}: {e}")
    return False, None



def testar_telnet_mk(ip, cred, metodo, porta):
    device = {
        'device_type': 'generic_telnet',
        'host': ip,
        'username': cred['username'],
        'password': cred['password'],
        'port': int(porta),
        'timeout': 40,
        'banner_timeout': 30,
    }

    if metodo.lower() == 'telnet':
        try:
            client = ConnectHandler(**device)
            print(f"Mikrotik conectado com sucesso via Telnet: {ip}")
            return True, client
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            print(f"Erro de autenticação ou timeout Telnet Mikrotik {ip}: {e}")
        except Exception as e:
            print(f"Erro inesperado no Telnet Mikrotik {ip}: {e}")
    return False, None



####################################################################################
def identificar_dispositivo(client):
    comandos = [
        "terminal length 0",
        "show version",
        "system routerboard print",
        "/system routerboard print",
        "get system status | grep Version:",
        "show system",
        "display version",
        "enable",
        "show version"
    ]

    regex_identificacao = {
        "cisco": r"(?i)Model\s+Number\s*:\s*([\w\-]+)|^cisco\s+([\w\-]+).*processor.*memory|cisco\s+Nexus[\w\-]*\s+(C\d+)",
        "datacom": r"(?i)\b(DmSwitch[\w\-]*|DM\d+)\b|Model:\s*([\w\-]+)|Machine\s+Type\s*[:\.]*\s*([\w\-]+)",
        "huawei": r"\b(S57|S67|S77|S127)\d+[\w\-]*\b",
        "alcatel": r"Description:.*\b(OS[\w-]*\d+)",
        "fortinet": r"(?i)Version:\s*(Forti[\w\-]+)\s+v?[\d.]+",
        "mikrotik": r"(?i)model:\s*([\w\-]+)",
        "aruba": r';\s*(J\d{4}A)\s.*?\nhostname\s',
    }

    try:
        for comando in comandos:
            try:
                output = client.send_command_timing(comando, delay_factor=6)
                time.sleep(2)

                if verificar_erro_comando(output):
                    print(f"Erro detectado no comando: '{comando}'")
                    continue

                for line in output.splitlines():
                    line = line.strip()
                    for device_type, pattern in regex_identificacao.items():
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            modelo = next((group for group in match.groups() if group), "Não identificado")
                            return modelo, device_type

            except Exception as e:
                print(f"Erro ao executar '{comando}': {e}")
                
    except Exception as e:
        print(f"Erro geral ao identificar dispositivo: {e}")

    return "Não identificado", "Não identificado"




##############################################################################################
def identificar_mk(client):
    try:
        output = client.send_command_timing("system routerboard print", delay_factor=6)
        time.sleep(3)
        
        if verificar_erro_comando(output):
            output = client.send_command_timing("/system routerboard print", delay_factor=6)
            time.sleep(3)
            if verificar_erro_comando(output):
                return "Não identificado", "Não identificado"

        regex_mk = {"mikrotik": r"(?i)model:\s*([\w\-]+)"}

        for line in output.splitlines():
            line = line.strip()
            for device_type, pattern in regex_mk.items():
                match = re.search(pattern, line)
                if match:
                    modelo = match.group(1)
                    return modelo, device_type

    except Exception as e:
        print(f"Erro ao executar identificar_mk: {e}")
        return "Não identificado", "Não identificado"
    
    return "Não identificado", "Não identificado"


##############################################################################################
def extrair_hostname(client, device_type):
    try:
        if device_type in ["cisco", "datacom", "huawei", "aruba"]:
            prompt = client.find_prompt()
            match = re.search(r"([\w\-_.|:]+)[#>:]", prompt, expect_string=r"#|>|:|\$", delay_factor=6)
            if match:
                return match.group(1)

        elif device_type == "alcatel":
            output = client.send_command_timing("show system", delay_factor=6)
            match = re.search(r"Name:\s*(.+)", output)
            if match:
                return match.group(1).strip()
            
        elif device_type == "mikrotik":
            output = client.send_command_timing("system identity print", delay_factor=6)
            if verificar_erro_comando(output):
                output = client.send_command_timing("/system routerboard print", delay_factor=6)
            match = re.search(r"name:\s*(.+)", output)
            if match:
                return match.group(1).strip()

        elif device_type == "fortinet":
            output = client.send_command("get system status | grep Hostname", expect_string=r"#|>|:|\$", delay_factor=6)
            match = re.search(r"Hostname:\s*(.+)", output)
            if match:
                return match.group(1).strip()
        
        else:
            prompt = client.find_prompt()
            match = re.search(r"([\w\-_.:]+)[#>:]", prompt, expect_string=r"#|>|:|\$", delay_factor=6)
            if match:
                return match.group(1)

        return "Hostname não identificado"
    
    except Exception as e:
        print(f"Erro ao extrair hostname: {e}")
        return "Hostname não identificado"
######################################################################################
def extrair_serial_number(output, device_type, model):
    try:
        if device_type == "cisco":
            lines = output.splitlines()
            for line in lines:
                match = re.search(r"SN:\s*([A-Z0-9]+)", line)
                if match:
                    return match.group(1)

        elif device_type == "alcatel":
            match = re.search(r"Serial Number:\s*([\w\-]+)", output, re.IGNORECASE)

        elif device_type == "huawei":
            match = re.search(r"Device serial number\s*:\s*([\w\-]+)", output, re.IGNORECASE)

        elif device_type == "fortinet":
            match = re.search(r"Serial-Number:\s*([\w\-]+)", output, re.IGNORECASE)

        elif device_type == "mikrotik":
            match = re.search(r"serial-number:\s*([^\s]+)", output, re.IGNORECASE)

        elif device_type == "datacom":
            if model.lower() in ["dm1200e", "dm1200"]:
                match = re.search(r"Serial Number\s*[:\-]?\s*(\d+)", output, re.IGNORECASE)
            elif "rear expansion board" in output.lower():
                match = re.search(r"Rear Expansion Board.*?Serial Number\s*[:\-]?\s*([\w\-]+)", output, re.IGNORECASE | re.DOTALL)
            else:
                match = re.search(
                    r"Serial Number\s*[:\-]?\s*(\d+)|Product ID\s*[:\-]?\s*(\d+)|ID\s*[:\-]?\s*(\d+)",  output, re.IGNORECASE)
        elif device_type == "aruba":
            match = re.search(r";\s*(J\d{4}A)\s.*?\nhostname\s", output, re.IGNORECASE)
        else:
            match = re.search(r"serial[\s\-_:]*number[:\s]*([\w\-]+)", output, re.IGNORECASE)

        return match.group(1)

    except Exception as e:
        print(f"Erro ao extrair número de série: {e}")
        return ""


def identificar_serial(device_type, client, ip, modelo):
            comandos_por_device = {
                "cisco": ["show inventory"],
                "alcatel": ["show chassis"],
                "huawei": ["display version"],
                "fortinet": ["get system status"],
                "mikrotik": ["system routerboard print", "/system routerboard print"],
                "datacom": ["show system", "enable", "show version"],
                "aruba":["show system"]
            }

            comandos = comandos_por_device.get(device_type, [])

            if not comandos:
                print(f"[{ip}] Tipo de dispositivo '{device_type}' sem comandos definidos.")
                return None

            output = ""
            serial_number = None

            try:
                if device_type == "mikrotik":
                    for cmd in comandos:
                        try:
                            output_tmp = client.send_command_timing(cmd, delay_factor=10)
                            serial_number = extrair_serial_number(output_tmp, device_type, modelo)
                            if serial_number:
                                output = output_tmp
                                break
                        except Exception as e:
                            print(f"[{ip}] Erro ao executar '{cmd}': {e}")

                elif device_type == "datacom":
                    for i, cmd in enumerate(comandos):
                        try:
                            output_tmp = client.send_command_timing(cmd, delay_factor=10)
                            output += f"\n{output_tmp}"
                            
                            if "show version" in cmd.lower():
                                serial_number = extrair_serial_number(output, device_type, modelo)
                                if serial_number:
                                    break
                        except Exception as e:
                            print(f"[{ip}] Erro ao executar '{cmd}': {e}")

                else:
                    cmd = comandos[0]
                    output = client.send_command_timing(cmd, delay_factor=10)
                    serial_number = extrair_serial_number(output, device_type, modelo)

            except Exception as e:
                print(f"[{ip}] Erro ao executar comandos para '{device_type}': {e}")
             
            return serial_number or ""



######################################################################################
def salvar_json(dicionario, nome_arquivo="inventory.json"):
    with open(nome_arquivo, "w", encoding="utf-8") as f:
        json.dump(dicionario, f, indent=4, ensure_ascii=False)
    print(f"\nArquivo '{nome_arquivo}' salvo com sucesso!\n")


def salvar_lista_timeout(timeout_lista):
    try:
        with open("timeout_lista.txt", "w") as file:
            for entry in timeout_lista:
                file.write(entry + "\n")
        print("Lista de timeout salva em 'timeout_lista.txt'.")
    except Exception as e:
        print(f"Erro ao salvar a lista de timeout: {e}")


timeout_lista = [] 
dicionario_eqt = {}

lock = Lock() 



def processar_ip_thread(linha, timeout_lista):
    try:
        linha = linha.strip()

        match = re.match(r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s*-\s*(?P<metodo>\w+)\s*-\s*Porta:\s*(?P<porta>\d+)\s*-\s*Vendor:\s*(?P<vendor>.+)', linha)
        if not match:
            return  

        ip = match.group('ip')
        metodo = match.group('metodo').upper()
        porta = match.group('porta')
        vendor = match.group('vendor').strip()


        conectado = False

        for cred in CREDENCIAIS:
            print(f"Testando {ip} usando {metodo}:{porta} com credenciais {cred['username']}/{cred['password']}")
            try:
                conectado, client = testar_conexao(ip, cred, metodo.lower(), int(porta))
                if conectado:
                    break  

            except paramiko.ssh_exception.SSHException as e:
                print(f"Erro SSH ao conectar no IP {ip}: {e}")
                timeout_lista.append(f"{ip} - {metodo} {porta} Erro SSH: {e}")

            except Exception as e:
                print(f"Erro geral ao conectar no IP {ip}: {e}")
                timeout_lista.append(f"{ip} - {metodo} {porta} Erro de conexão: {e}")

        if not conectado:
            salvar_lista_timeout(timeout_lista)
            return

        modelo, device_type = identificar_dispositivo(client)
        print(f"{ip} modelo encontrado: {modelo}/{device_type}")

        if device_type == "Não identificado":
            print(f"Tentando conexão Mikrotik em {ip}...")

            try:
                if metodo.lower() == "ssh":
                    conectado, client = testar_ssh_mk(ip, cred, metodo.lower(), porta)
                elif metodo.lower() == "telnet":
                    conectado, client = testar_telnet_mk(ip, cred, metodo.lower(), porta)

                if conectado:
                    modelo, device_type = identificar_mk(client)
                    print(f"Dispositivo Mikrotik identificado como: {modelo} - {device_type}")
                else:
                    salvar_lista_timeout(timeout_lista)
                    return
            except Exception as e:
                print(f"Falha também na tentativa Mikrotik: {e}")
                salvar_lista_timeout(timeout_lista)
                return

        if not conectado:
            salvar_lista_timeout(timeout_lista)
            return
        
        hostname = extrair_hostname(client, device_type)
        serial_number = identificar_serial(device_type, client, ip, modelo)


        with lock:
            dicionario_eqt[ip] = {
                "Hostname": hostname,
                "Device_Type": device_type,
                "Connection": metodo,
                "Port": porta,
                "Login_used": f"{cred['username']}/{cred['password']}",
                "Model": modelo,
                "Localidade": {"Estado":"", "Cidade": ""},
                "Tipo": "",
                "Backup_Filepath": "",
                "Backup_Date": "",
                "Backup_Interval": "",
                "Serial_Number": serial_number,
            }

        print(f"Dispositivo no IP {ip} identificado e salvo.")
        
        timeout_lista[:] = [entry for entry in timeout_lista if not entry.startswith(ip)]
        print(f"{ip} removido da timeout list")

        client.disconnect() 

    except Exception as e:
        print(f"Erro inesperado ao processar IP '{linha}': {e}")
        timeout_lista.append(f"{ip} - {metodo} {porta} Erro inesperado")
        salvar_lista_timeout(timeout_lista) 



##############################################################################################
def main():
    lista_ips = carregar_arquivo1()

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(processar_ip_thread, ip, timeout_lista) for ip in lista_ips]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Erro em uma das threads: {e}")

    if timeout_lista:
        salvar_lista_timeout(timeout_lista)

    if dicionario_eqt:
        salvar_json(dicionario_eqt)
    else:
        print("Nenhum dado válido identificado. JSON não foi gerado.")


if __name__ == "__main__":
    main()



