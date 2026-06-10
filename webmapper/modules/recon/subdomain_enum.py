#!/usr/bin/env python3
# coding:utf-8
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# modules/recon/subdomain_enum.py — Découverte de sous-domaines par DNS.
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
from __future__ import annotations

import logging
import os
import socket
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Final, Generator

__all__ = [
    "SubdomainEnumerator",
    "SubdomainResult",
    "enumerate_subdomains",
]

logger = logging.getLogger("webmapper.recon.subdomain")


# Constantes

# Chemin par défaut de la wordlist embarquée
DEFAULT_WORDLIST: Final[str] = os.path.join(
    os.path.dirname(__file__), "wordlists", "subdomains.txt"
)

# Timeout par résolution DNS (secondes)
DNS_TIMEOUT: Final[float] = 3.0

# Workers par défaut pour la résolution concurrente
DEFAULT_WORKERS: Final[int] = 20


# Modèle de résultat

@dataclass(slots=True, frozen=True)
class SubdomainResult:
    """Résultat immuable d'une découverte de sous-domaine.

    Attributes:
        subdomain: FQDN du sous-domaine découvert (ex: "api.example.com").
        ip:        Adresse IP résolue.
        source:    Méthode de découverte ("dns_bruteforce").
    """
    subdomain: str
    ip: str
    source: str = "dns_bruteforce"


# Lecture de wordlist en streaming 

def _stream_wordlist(path: str) -> Generator[str, None, None]:
    """Lit une wordlist ligne par ligne (générateur).

    Avantage mémoire : ne charge jamais le fichier entier en RAM.
    Ignore les lignes vides et les commentaires (#).

    Args:
        path: Chemin absolu vers le fichier wordlist.

    Yields:
        Chaque mot de la wordlist (strippé).
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith("#"):
                    yield word
    except FileNotFoundError:
        logger.error("Wordlist introuvable : %s", path)
    except PermissionError:
        logger.error("Permission refusée pour la wordlist : %s", path)


# Résolution DNS

def _resolve_subdomain(fqdn: str, timeout: float = DNS_TIMEOUT) -> SubdomainResult | None:
    """Tente une résolution DNS A sur un FQDN.

    Utilise socket.getaddrinfo (standard library) pour éviter
    la dépendance à dnspython pour le cas basique.
    Fallback sur dns.resolver si dnspython est installé.

    Args:
        fqdn:    Nom de domaine complet à résoudre.
        timeout: Timeout en secondes.

    Returns:
        SubdomainResult si le sous-domaine répond, None sinon.
    """
    try:
        # Tentative via dnspython (plus précis, supporte les types de records)
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(fqdn, "A")
        if answers:
            ip = str(answers[0])
            return SubdomainResult(subdomain=fqdn, ip=ip)
    except ImportError:
        # Fallback sur socket (standard library)
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            try:
                result = socket.getaddrinfo(fqdn, None, socket.AF_INET)
                if result:
                    ip = result[0][4][0]
                    return SubdomainResult(subdomain=fqdn, ip=ip)
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (socket.gaierror, socket.timeout, OSError):
            return None
    except Exception:
        return None

    return None


# Énumérateur principal

class SubdomainEnumerator:
    """Énumérateur de sous-domaines par bruteforce DNS concurrent.

    Premier module exécuté dans le flux WebMapper.
    Utilise ThreadPoolExecutor car la résolution DNS est I/O-bound
    (le GIL est relâché pendant les appels réseau).

    Usage :
        enumerator = SubdomainEnumerator("example.com")
        results = enumerator.enumerate()
        for sub in results:
            print(f"{sub.subdomain} → {sub.ip}")

    Args:
        domain:     Domaine cible (ex: "example.com").
        wordlist:   Chemin vers la wordlist (défaut: wordlist embarquée).
        workers:    Nombre de threads parallèles (défaut: 20).
        timeout:    Timeout DNS par résolution (défaut: 3s).
    """
    __slots__ = ("_domain", "_wordlist", "_workers", "_timeout")

    def __init__(
        self,
        domain: str,
        wordlist: str | None = None,
        workers: int = DEFAULT_WORKERS,
        timeout: float = DNS_TIMEOUT,
    ) -> None:
        self._domain = domain.lower().strip().rstrip(".")
        self._wordlist = wordlist or DEFAULT_WORDLIST
        self._workers = workers
        self._timeout = timeout

    @property
    def domain(self) -> str:
        """Domaine cible."""
        return self._domain

    def _generate_fqdns(self) -> Generator[str, None, None]:
        """Génère les FQDNs à tester à partir de la wordlist.

        Yields:
            FQDNs uniques (ex: "api.example.com").
        """
        seen: set[str] = set()
        for word in _stream_wordlist(self._wordlist):
            fqdn = f"{word}.{self._domain}"
            if fqdn not in seen:
                seen.add(fqdn)
                yield fqdn

    def enumerate(self) -> list[SubdomainResult]:
        """Lance l'énumération DNS concurrente.

        Returns:
            Liste de SubdomainResult pour les sous-domaines actifs.
        """
        results: list[SubdomainResult] = []
        fqdns = list(self._generate_fqdns())

        if not fqdns:
            logger.warning(
                "Aucun sous-domaine à tester — wordlist vide ou introuvable : %s",
                self._wordlist,
            )
            return results

        logger.info(
            "Lancement de l'énumération DNS sur %s (%d sous-domaines, %d workers)",
            self._domain, len(fqdns), self._workers,
        )

        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            future_to_fqdn = {
                pool.submit(_resolve_subdomain, fqdn, self._timeout): fqdn
                for fqdn in fqdns
            }

            for future in as_completed(future_to_fqdn):
                fqdn = future_to_fqdn[future]
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                        logger.info(" %s → %s", result.subdomain, result.ip)
                except Exception as exc:
                    logger.debug("Erreur résolution %s : %s", fqdn, exc)

        # Tri par nom de sous-domaine pour un affichage cohérent
        results.sort(key=lambda r: r.subdomain)

        logger.info(
            "Énumération terminée : %d sous-domaine(s) actif(s) sur %d testés",
            len(results), len(fqdns),
        )

        return results

    def enumerate_streaming(self) -> Generator[SubdomainResult, None, None]:
        """Version streaming de l'énumération (yield au fur et à mesure).

        Utile pour les gros domaines où on veut traiter les résultats
        dès qu'ils arrivent sans attendre la fin de l'énumération.

        Yields:
            SubdomainResult pour chaque sous-domaine actif découvert.
        """
        fqdns = list(self._generate_fqdns())
        if not fqdns:
            return

        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            future_to_fqdn = {
                pool.submit(_resolve_subdomain, fqdn, self._timeout): fqdn
                for fqdn in fqdns
            }

            for future in as_completed(future_to_fqdn):
                try:
                    result = future.result()
                    if result is not None:
                        yield result
                except Exception:
                    pass


# Fonction de convenance

def enumerate_subdomains(
    domain: str,
    wordlist: str | None = None,
    workers: int = DEFAULT_WORKERS,
    timeout: float = DNS_TIMEOUT,
) -> list[SubdomainResult]:
    """Fonction de convenance pour l'énumération de sous-domaines.

    Args:
        domain:   Domaine cible.
        wordlist: Chemin vers la wordlist (optionnel).
        workers:  Nombre de threads (défaut: 20).
        timeout:  Timeout DNS (défaut: 3s).

    Returns:
        Liste de SubdomainResult.
    """
    enumerator = SubdomainEnumerator(
        domain=domain,
        wordlist=wordlist,
        workers=workers,
        timeout=timeout,
    )
    return enumerator.enumerate()
