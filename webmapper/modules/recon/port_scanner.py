#!/usr/bin/env python3
# coding:utf-8
"""
modules/recon/port_scanner.py — Scan de ports sur les sous-domaines actifs.
"""
from __future__ import annotations

import logging
import socket
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Final, Generator

__all__ = [
    "PortScanner",
    "PortResult",
    "scan_ports",
]

logger = logging.getLogger("webmapper.recon.portscan")


# ── Constantes ───────────────────────────────────────────────────────

# Top 100 ports TCP les plus courants (nmap top-ports)
TOP_PORTS: Final[tuple[int, ...]] = (
    20, 21, 22, 23, 25, 42, 53, 67, 68, 69,
    80, 110, 111, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 389, 443, 445, 465, 514, 554, 587, 636,
    873, 993, 995, 1025, 1433, 1434, 1521, 1723, 2049, 2082,
    2083, 2086, 2087, 2096, 2181, 3000, 3128, 3268, 3306, 3389,
    3690, 4443, 4444, 4567, 4848, 5000, 5432, 5555, 5601, 5672,
    5800, 5900, 5984, 5985, 5986, 6379, 6443, 6666, 7001, 7002,
    7070, 7443, 8000, 8001, 8008, 8009, 8010, 8020, 8080, 8081,
    8082, 8083, 8088, 8090, 8161, 8181, 8443, 8444, 8500, 8834,
    8880, 8888, 8983, 9000, 9001, 9042, 9090, 9091, 9092, 9093,
    9200, 9300, 9418, 9443, 9990, 10000, 10443, 11211, 15672, 27017,
    27018, 50000,
)

# Timeout TCP par défaut (secondes)
TCP_TIMEOUT: Final[float] = 2.0

# Workers par défaut pour le scan concurrent
DEFAULT_WORKERS: Final[int] = 50

# Chemin vers nmap.json
NMAP_JSON_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "nmap.json")

# Mapping port → service connu (fallback si nmap non dispo)
KNOWN_SERVICES: Final[dict[int, str]] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    42: "wins", 53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmp-trap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 554: "rtsp", 587: "submission",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 3000: "node/grafana",
    3128: "squid", 3306: "mysql", 3389: "rdp", 4443: "https-alt",
    5000: "flask/docker", 5432: "postgresql", 5601: "kibana", 5672: "amqp",
    5800: "vnc-web", 5900: "vnc", 6379: "redis", 6443: "k8s-api",
    7001: "weblogic", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8834: "nessus", 8888: "http-alt", 8983: "solr", 9000: "portainer",
    9090: "prometheus", 9092: "kafka", 9200: "elasticsearch", 9418: "git",
    10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 50000: "jenkins",
}


#Modèle de résultat

@dataclass(slots=True, frozen=True)
class PortResult:
    """Résultat immuable d'un scan de port.

    Attributes:
        port:     Numéro de port TCP.
        state:    État du port ("open", "closed", "filtered").
        service:  Nom du service identifié (ex: "http", "ssh").
        version:  Version du service si détectée (ex: "Apache/2.4.52").
        banner:   Banner brut si récupéré.
    """
    port: int
    state: str = "open"
    service: str = "unknown"
    version: str = ""
    banner: str = ""


# Scan TCP connect (fallback sans nmap)

def _tcp_connect(
    target: str,
    port: int,
    timeout: float = TCP_TIMEOUT,
) -> PortResult | None:
    """Teste un port TCP via connect() + tentative de banner grab.

    Args:
        target:  Hôte cible (IP ou hostname).
        port:    Numéro de port.
        timeout: Timeout de connexion.

    Returns:
        PortResult si le port est ouvert, None sinon.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))

            if result == 0:
                # Port ouvert — tentative de banner grab
                banner = ""
                try:
                    sock.settimeout(1.5)
                    # Envoyer un probe HTTP basique pour les ports web
                    if port in (80, 8080, 8000, 8008, 8888, 3000, 5000, 8443, 443):
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                    banner = sock.recv(512).decode("utf-8", errors="ignore").strip()
                except (socket.timeout, OSError):
                    pass

                service = KNOWN_SERVICES.get(port, "unknown")
                version = ""
                if banner:
                    # Extraire la version depuis le banner
                    if "Server:" in banner:
                        for line in banner.split("\n"):
                            if line.strip().startswith("Server:"):
                                version = line.split("Server:", 1)[1].strip()
                                break
                    elif "/" in banner and len(banner) < 100:
                        version = banner.split("\n")[0]

                return PortResult(
                    port=port,
                    state="open",
                    service=service,
                    version=version,
                    banner=banner[:200] if banner else "",
                )
    except (socket.timeout, OSError):
        pass

    return None


#Scanner principal

class PortScanner:
    """Scanner de ports TCP concurrent.

    Deux modes :
      1. python-nmap si installé → détection de service + version précise
      2. Fallback socket TCP connect → scan basique + banner grab

    Usage :
        scanner = PortScanner("192.168.1.1")
        results = scanner.scan()

    Args:
        target:       Hôte cible (IP ou hostname).
        ports:        Tuple de ports à scanner (défaut: top 100).
        workers:      Threads parallèles (défaut: 50).
        timeout:      Timeout TCP par port (défaut: 2s).
        nmap_profile: Profil de scan issu de nmap.json (défaut: "default").
    """
    __slots__ = ("_target", "_ports", "_workers", "_timeout", "_nmap_profile")

    def __init__(
        self,
        target: str,
        ports: tuple[int, ...] | None = None,
        workers: int = DEFAULT_WORKERS,
        timeout: float = TCP_TIMEOUT,
        nmap_profile: str = "default",
    ) -> None:
        self._target = target.strip()
        self._ports = ports or TOP_PORTS
        self._workers = workers
        self._timeout = timeout
        self._nmap_profile = nmap_profile

    @property
    def target(self) -> str:
        """Hôte cible."""
        return self._target

    def scan(self) -> list[PortResult]:
        """Lance le scan de ports.

        Tente d'abord python-nmap, puis fallback sur le scan socket.

        Returns:
            Liste de PortResult pour les ports ouverts, triée par port.
        """
        try:
            return self._scan_nmap()
        except (ImportError, Exception) as exc:
            logger.info(
                "nmap non disponible (%s), fallback sur scan TCP connect.", exc
            )
            return self._scan_socket()

    def _get_nmap_args(self) -> list[str]:
        """Récupère une liste d'arguments nmap à exécuter."""
        if self._nmap_profile == "default":
            return ["-sV --version-intensity 5 -T4"]

        if self._nmap_profile == "deep":
            args_list = ["-sS -sV -O -A -T4 --min-rate 300"]
            if os.path.exists(NMAP_JSON_PATH):
                try:
                    with open(NMAP_JSON_PATH, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    for cat, profiles in data.get("categories", {}).items():
                        for prof in profiles:
                            cmd = prof.get("command", "")
                            cmd = cmd.replace("nmap", "").replace("{target}", "").replace("-p {ports}", "").replace("--top-ports {count}", "").strip()
                            if cmd:
                                logger.info("Profil nmap profond ajouté : %s", prof.get("name"))
                                args_list.append(cmd)
                except Exception as e:
                    logger.error("Erreur lecture nmap.json : %s", e)
            return args_list

        # Si un profil spécifique est demandé
        if os.path.exists(NMAP_JSON_PATH):
            try:
                with open(NMAP_JSON_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for cat, profiles in data.get("categories", {}).items():
                    for prof in profiles:
                        if self._nmap_profile.lower() in prof.get("name", "").lower():
                            cmd = prof.get("command", "")
                            cmd = cmd.replace("nmap", "").replace("{target}", "").replace("-p {ports}", "").replace("--top-ports {count}", "").strip()
                            return [cmd] if cmd else ["-sV --version-intensity 5 -T4"]
            except Exception as e:
                pass
        
        return ["-sV --version-intensity 5 -T4"]

    def _scan_nmap(self) -> list[PortResult]:
        """Scan via python-nmap avec itération sur de multiples profils si nécessaire."""
        import nmap

        nm = nmap.PortScanner()
        ports_str = ",".join(str(p) for p in self._ports)
        nmap_args_list = self._get_nmap_args()

        all_results = {}
        target_resolved = None

        for nmap_args in nmap_args_list:
            display_ports = ports_str if len(ports_str) < 30 else f"{len(self._ports)} ports"
            logger.info("Exécution Nmap : nmap -p %s %s %s", display_ports, nmap_args, self._target)
            try:
                nm.scan(
                    hosts=self._target,
                    ports=ports_str,
                    arguments=nmap_args,
                    timeout=max(60, len(self._ports) * 0.5),
                )
            except nmap.PortScannerError as e:
                logger.debug("Erreur Nmap avec %s : %s", nmap_args, e)
                continue

            host = self._target
            if host not in nm.all_hosts():
                # Tenter avec l'IP résolue
                if not target_resolved:
                    try:
                        target_resolved = socket.gethostbyname(self._target)
                    except socket.gaierror:
                        continue
                if target_resolved in nm.all_hosts():
                    host = target_resolved
                else:
                    logger.debug("Aucun résultat nmap sur cette passe pour %s", self._target)
                    continue

            # Fusionner les résultats
            if host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in sorted(nm[host][proto].keys()):
                        port_info = nm[host][proto][port]
                        if port_info["state"] == "open":
                            # Extraction de la bannière ou des scripts NSE
                            banner = port_info.get("extrainfo", "")
                            if "script" in port_info:
                                for script_id, output in port_info["script"].items():
                                    banner += f" | {script_id}: {output.strip()}"

                            if port not in all_results:
                                all_results[port] = PortResult(
                                    port=port,
                                    state="open",
                                    service=port_info.get("name", "unknown"),
                                    version=port_info.get("version", "") or port_info.get("product", ""),
                                    banner=banner.strip()
                                )
                            else:
                                # Enrichir le résultat existant si on trouve mieux
                                existing = all_results[port]
                                new_v = port_info.get("version", "") or port_info.get("product", "")
                                if new_v and not existing.version:
                                    existing.version = new_v
                                if banner and banner not in existing.banner:
                                    existing.banner += (" " + banner.strip())

        return sorted(list(all_results.values()), key=lambda r: r.port)

    def _scan_socket(self) -> list[PortResult]:
        """Scan TCP connect concurrent via ThreadPoolExecutor."""
        results: list[PortResult] = []

        logger.info(
            "Scan TCP connect sur %s (%d ports, %d workers)",
            self._target, len(self._ports), self._workers,
        )

        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            future_to_port = {
                pool.submit(_tcp_connect, self._target, port, self._timeout): port
                for port in self._ports
            }

            for future in as_completed(future_to_port):
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                        logger.info(
                            "%s:%d/tcp → %s %s",
                            self._target, result.port,
                            result.service, result.version,
                        )
                except Exception as exc:
                    port = future_to_port[future]
                    logger.debug("Erreur scan port %d : %s", port, exc)

        results.sort(key=lambda r: r.port)
        return results

    def scan_streaming(self) -> Generator[PortResult, None, None]:
        """Version streaming du scan (yield au fur et à mesure).

        Yields:
            PortResult pour chaque port ouvert découvert.
        """
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            future_to_port = {
                pool.submit(_tcp_connect, self._target, port, self._timeout): port
                for port in self._ports
            }

            for future in as_completed(future_to_port):
                try:
                    result = future.result()
                    if result is not None:
                        yield result
                except Exception:
                    pass


#Fonction de convenance

def scan_ports(
    target: str,
    ports: tuple[int, ...] | None = None,
    workers: int = DEFAULT_WORKERS,
    timeout: float = TCP_TIMEOUT,
    nmap_profile: str = "default",
) -> list[PortResult]:
    """Fonction de convenance pour le scan de ports.

    Args:
        target:       Hôte cible.
        ports:        Ports à scanner (défaut: top 100).
        workers:      Threads parallèles.
        timeout:      Timeout TCP.
        nmap_profile: Profil de scan.

    Returns:
        Liste de PortResult.
    """
    scanner = PortScanner(
        target=target,
        ports=ports,
        workers=workers,
        timeout=timeout,
        nmap_profile=nmap_profile,
    )
    return scanner.scan()
