import argparse
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Optional, Tuple

COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_RED = "\033[31m"
COLOR_CYAN = "\033[36m"
COLOR_BLUE = "\033[34m"

BANNER = r"""
   ____                                  _
  / ___|  ___  _ __ ___   ___ _ __   __| |
  \___ \ / _ \| '_ ` _ \ / _ \ '_ \ / _` |
   ___) | (_) | | | | | |  __/ | | | (_| |
  |____/ \___/|_| |_| |_|\___|_| |_|\__,_|

  Escáner de puertos - terminal CLI
"""

COMMON_SERVICES = {
    20: "FTP data",
    21: "FTP control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-alt",
}


def parse_ports(port_arg: str) -> List[int]:
    ports = set()
    for part in port_arg.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            ports.update(range(min(start, end), max(start, end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def parse_targets(target_arg: str) -> List[str]:
    if "," in target_arg:
        return [target.strip() for target in target_arg.split(",") if target.strip()]
    if "-" in target_arg and target_arg.count(".") == 3:
        start, end = target_arg.split("-", 1)
        base = start.rsplit(".", 1)[0]
        first = int(start.rsplit(".", 1)[1])
        last = int(end)
        return [f"{base}.{i}" for i in range(min(first, last), max(first, last) + 1)]
    return [target_arg.strip()]


def get_local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("1.1.1.1", 80))
            return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def list_subnet_hosts(subnet: Optional[str] = None) -> List[str]:
    if subnet:
        network = ipaddress.ip_network(subnet, strict=False)
    else:
        local_ip = get_local_ip()
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return [str(ip) for ip in network.hosts()]


def probe_device(ip: str, timeout: float = 0.5, ports: Tuple[int, int, int] = (80, 443, 22)) -> Optional[str]:
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.connect((ip, port))
                return ip
            except ConnectionRefusedError:
                return ip
            except socket.timeout:
                continue
            except OSError:
                continue
    return None


def discover_network(subnet: Optional[str], timeout: float, workers: int) -> List[Tuple[str, str]]:
    hosts = list_subnet_hosts(subnet)
    found = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {executor.submit(probe_device, ip, timeout): ip for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    try:
                        name = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        name = "-"
                    found.append((ip, name))
            except Exception:
                pass
    return sorted(found, key=lambda item: item[0])


def resolve_host(host: str) -> str:
    return socket.gethostbyname(host)


def scan_port(host: str, port: int, timeout: float) -> Tuple[int, str, Optional[str]]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            detail = COMMON_SERVICES.get(port, "")
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()
                if banner:
                    detail = detail or banner.splitlines()[0]
            except Exception:
                pass
            return port, "open", detail
        except ConnectionRefusedError:
            return port, "closed", None
        except socket.timeout:
            return port, "filtered", None
        except OSError:
            return port, "closed", None


def scan_host(host: str, ports: List[int], timeout: float, workers: int) -> List[Tuple[int, str, Optional[str]]]:
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in as_completed(future_to_port):
            try:
                results.append(future.result())
            except KeyboardInterrupt:
                raise
            except Exception:
                port = future_to_port[future]
                results.append((port, "error", None))
    return sorted(results, key=lambda item: item[0])


def color_state(state: str, text: str) -> str:
    if state == "open":
        return f"{COLOR_GREEN}{text}{COLOR_RESET}"
    if state == "closed":
        return f"{COLOR_RED}{text}{COLOR_RESET}"
    if state == "filtered":
        return f"{COLOR_YELLOW}{text}{COLOR_RESET}"
    if state == "error":
        return f"{COLOR_CYAN}{text}{COLOR_RESET}"
    return text


def format_results(host: str, ip: str, results: List[Tuple[int, str, Optional[str]]], elapsed: float) -> None:
    title = f" Escaneo de {host} " 
    banner = "=" * max(40, len(title) + 4)
    print(f"\n{COLOR_BLUE}{banner}{COLOR_RESET}")
    print(f"{COLOR_BLUE}= {COLOR_RESET}{COLOR_CYAN}{title}{COLOR_RESET}{COLOR_BLUE} ={COLOR_RESET}")
    print(f"{COLOR_BLUE}{banner}{COLOR_RESET}")
    print(f"{COLOR_GREEN}Host:{COLOR_RESET} {host}")
    print(f"{COLOR_GREEN}IP:  {COLOR_RESET} {ip}")
    print(f"{COLOR_GREEN}Puertos escaneados:{COLOR_RESET} {len(results)}")
    print(f"{COLOR_GREEN}Tiempo:{COLOR_RESET} {elapsed:.2f} segundos")
    print(f"{COLOR_BLUE}{banner}{COLOR_RESET}")
    print(f"{'Puerto':>6}  {'Estado':>8}  Servicio / Banner")
    print("------  --------  --------------------")
    open_ports = []
    for port, state, detail in results:
        if state == "open":
            open_ports.append(port)
        detail_str = detail or "-"
        state_text = color_state(state, state)
        print(f"{port:6}  {state_text:>8}  {detail_str}")
    print(f"{COLOR_BLUE}{banner}{COLOR_RESET}")
    if open_ports:
        open_list = ", ".join(str(port) for port in open_ports)
        print(f"{COLOR_GREEN}Puertos abiertos ({len(open_ports)}):{COLOR_RESET} {open_list}")
    else:
        print(f"{COLOR_YELLOW}No se encontraron puertos abiertos.{COLOR_RESET}")
    print(f"{COLOR_BLUE}{banner}{COLOR_RESET}\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Escáner de puertos de terminal")
    parser.add_argument("target", nargs="?", default=None, help="Host, IP, rango de IPs o lista separada por comas")
    parser.add_argument("-p", "--ports", default="1-1024", help="Puertos o rango, ej. 22,80,443 o 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout por puerto en segundos")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Número de hilos concurrentes")
    parser.add_argument("-o", "--output", choices=["text", "csv", "json"], default="text", help="Formato de salida")
    parser.add_argument("--file", help="Guardar resultados a un archivo CSV o JSON")
    parser.add_argument("--discover", action="store_true", help="Detectar dispositivos activos en la red local")
    parser.add_argument("--subnet", help="Red local a escanear, ej. 192.168.1.0/24")
    return parser


def save_results(host: str, ip: str, results: List[Tuple[int, str, Optional[str]]], filename: str) -> None:
    if filename.endswith(".csv"):
        with open(filename, "w", encoding="utf-8") as out:
            out.write("host,ip,port,state,detail\n")
            for port, state, detail in results:
                detail_text = detail.replace('"', '""') if detail else ""
                out.write(f'"{host}","{ip}",{port},{state},"{detail_text}"\n')
    elif filename.endswith(".json"):
        import json

        data = [
            {"host": host, "ip": ip, "port": port, "state": state, "detail": detail or ""}
            for port, state, detail in results
        ]
        with open(filename, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=2, ensure_ascii=False)
    else:
        raise ValueError("El archivo debe terminar en .csv o .json")


def print_banner() -> None:
    print(f"{COLOR_BLUE}{BANNER}{COLOR_RESET}")


def run():
    print_banner()
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.target and not args.discover:
        user_input = input("Host o IP a escanear (o escribe --discover): ").strip()
        if not user_input:
            print("No se ingresó host o IP. Saliendo.")
            sys.exit(1)
        if user_input.startswith("-"):
            args = parser.parse_args(user_input.split())
        else:
            args.target = user_input

    if args.discover:
        print(f"{COLOR_BLUE}>>>{COLOR_RESET} Detectando dispositivos en la red local...")
        devices = discover_network(args.subnet, args.timeout, args.workers)
        if devices:
            print(f"\n{COLOR_GREEN}Dispositivos encontrados:{COLOR_RESET}")
            print(f"{'#':>2}  {'IP':>15}  Nombre")
            print(f"{'-'*2}  {'-'*15}  {'-'*20}")
            for index, (ip, name) in enumerate(devices, start=1):
                print(f"{index:2}  {ip:>15}  {name}")

            choice = input("\nElige número o IP para escanear (ENTER para salir): ").strip()
            if not choice:
                return

            selected_ip = None
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(devices):
                    selected_ip = devices[index][0]
                else:
                    print(f"{COLOR_YELLOW}Número inválido. Saliendo.{COLOR_RESET}")
                    return
            else:
                for ip, _ in devices:
                    if ip == choice:
                        selected_ip = ip
                        break
                if not selected_ip:
                    print(f"{COLOR_YELLOW}IP no encontrada en la lista. Saliendo.{COLOR_RESET}")
                    return

            ports = parse_ports(args.ports)
            if not ports:
                parser.error("No hay puertos válidos para escanear")

            print(f"\n{COLOR_BLUE}>>>{COLOR_RESET} Escaneando {COLOR_CYAN}{selected_ip}{COLOR_RESET} con {len(ports)} puertos y {args.workers} hilos...")
            start = time.time()
            try:
                results = scan_host(selected_ip, ports, args.timeout, args.workers)
            except KeyboardInterrupt:
                print("\nEscaneo cancelado por usuario.")
                sys.exit(1)
            elapsed = time.time() - start
            format_results(selected_ip, selected_ip, results, elapsed)

            if args.file:
                try:
                    save_results(selected_ip, selected_ip, results, args.file)
                    print(f"Resultados guardados en {args.file}")
                except Exception as exc:
                    print(f"ERROR guardando archivo: {exc}", file=sys.stderr)
        else:
            print(f"{COLOR_YELLOW}No se encontraron dispositivos activos en la red local.{COLOR_RESET}")
        return

    targets = parse_targets(args.target)
    ports = parse_ports(args.ports)
    if not ports:
        parser.error("No hay puertos válidos para escanear")

    for target in targets:
        try:
            ip = resolve_host(target)
        except socket.gaierror as exc:
            print(f"{COLOR_RED}ERROR:{COLOR_RESET} no se pudo resolver {target}: {exc}", file=sys.stderr)
            continue

        print(f"\n{COLOR_BLUE}>>>{COLOR_RESET} Escaneando {COLOR_CYAN}{target}{COLOR_RESET} ({COLOR_CYAN}{ip}{COLOR_RESET}) con {len(ports)} puertos y {args.workers} hilos...")
        start = time.time()
        try:
            results = scan_host(ip, ports, args.timeout, args.workers)
        except KeyboardInterrupt:
            print("\nEscaneo cancelado por usuario.")
            sys.exit(1)
        elapsed = time.time() - start
        format_results(target, ip, results, elapsed)

        if args.file:
            try:
                save_results(target, ip, results, args.file)
                print(f"Resultados guardados en {args.file}")
            except Exception as exc:
                print(f"ERROR guardando archivo: {exc}", file=sys.stderr)


if __name__ == "__main__":
    run()
