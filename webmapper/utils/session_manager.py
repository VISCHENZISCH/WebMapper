#!/usr/bin/env python3
# coding:utf-8
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# utils/session_manager.py — Gestionnaire de sessions HTTP isolées.
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
from __future__ import annotations

import random
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Final, Generator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__all__ = [
    "SessionManager",
    "SessionConfig",
    "ManagedSession",
]


# User-Agents réalistes pour la rotation 

USER_AGENTS: Final[tuple[str, ...]] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) "
    "Gecko/20100101 Firefox/119.0",

    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 "
    "Mobile/15E148 Safari/604.1",
)

# En-têtes réalistes par défaut
DEFAULT_HEADERS: Final[dict[str, str]] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


# Configuration 

@dataclass(slots=True, frozen=True)
class SessionConfig:
    """Configuration immuable pour la création de sessions HTTP.

    Attributes:
        timeout:          Timeout global par requête (secondes).
        max_retries:      Nombre de retries automatiques sur erreur réseau.
        backoff_factor:   Facteur de backoff exponentiel entre les retries.
        pool_connections: Nombre de connexions poolées par hôte.
        pool_maxsize:     Taille max du pool de connexions.
        rotate_ua:        Rotation aléatoire de User-Agent par session.
        proxy:            Dictionnaire de proxy {"http": ..., "https": ...}.
        user_agent:       User-Agent fixe (utilisé si rotate_ua=False).
    """
    timeout: int = 10
    max_retries: int = 3
    backoff_factor: float = 0.3
    pool_connections: int = 10
    pool_maxsize: int = 20
    rotate_ua: bool = True
    proxy: dict[str, str] | None = None
    user_agent: str = USER_AGENTS[0]


# Session managée (context manager) 

class ManagedSession:
    """Wrapper autour de requests.Session avec context manager.

    Garantit la fermeture propre de la session et de ses connexions
    pool quand on sort du bloc `with`.

    Usage :
        with ManagedSession(config) as session:
            response = session.get(url)
    """
    __slots__ = ("_session", "_config", "_closed")

    def __init__(self, config: SessionConfig) -> None:
        self._config = config
        self._closed = False
        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        """Construit une session requests configurée et isolée."""
        session = requests.Session()
        
        # Désactiver la validation SSL (indispensable pour un scanner)
        session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # User-Agent : rotation ou fixe
        ua = (
            random.choice(USER_AGENTS)
            if self._config.rotate_ua
            else self._config.user_agent
        )
        headers = {**DEFAULT_HEADERS, "User-Agent": ua}
        session.headers.update(headers)

        # Proxy
        if self._config.proxy:
            session.proxies.update(self._config.proxy)

        # Retry + pooling via HTTPAdapter
        retry_strategy = Retry(
            total=self._config.max_retries,
            connect=0,  # Ne pas retry sur timeout de connexion (évite de bloquer le scanner)
            read=self._config.max_retries,
            backoff_factor=self._config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self._config.pool_connections,
            pool_maxsize=self._config.pool_maxsize,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    # Context manager protocol 

    def __enter__(self) -> requests.Session:
        """Retourne la session requests sous-jacente."""
        return self._session

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Ferme proprement la session et libère les connexions."""
        self.close()
        return False  # Ne pas supprimer les exceptions

    def close(self) -> None:
        """Ferme la session si elle n'est pas déjà fermée."""
        if not self._closed:
            self._session.close()
            self._closed = True

    @property
    def session(self) -> requests.Session:
        """Accès direct à la session (sans context manager)."""
        return self._session


#  Gestionnaire central 

class SessionManager:
    """Gestionnaire central de sessions HTTP isolées.

    Fournit une session indépendante à chaque module/thread.
    Résout les bugs #2 et #3 : plus de session globale partagée.

    Usage basique :
        manager = SessionManager(proxy={"http": "...", "https": "..."})
        session = manager.create_session()

    Usage context manager :
        with manager.managed_session() as session:
            response = session.get(url)

    Usage thread-safe (une session par thread) :
        session = manager.get_thread_session()

    Args:
        timeout:     Timeout par requête (secondes).
        max_retries: Nombre de retries automatiques.
        rotate_ua:   Rotation aléatoire de User-Agent.
        proxy:       Dictionnaire de proxy.
        user_agent:  User-Agent fixe (si rotate_ua=False).
    """

    def __init__(
        self,
        *,
        timeout: int = 10,
        max_retries: int = 3,
        rotate_ua: bool = True,
        proxy: dict[str, str] | None = None,
        user_agent: str = USER_AGENTS[0],
    ) -> None:
        self._config = SessionConfig(
            timeout=timeout,
            max_retries=max_retries,
            rotate_ua=rotate_ua,
            proxy=proxy,
            user_agent=user_agent,
        )
        # Thread-local storage pour les sessions par thread
        self._thread_local = threading.local()
        # Registre de toutes les sessions créées (pour cleanup global)
        self._sessions: list[ManagedSession] = []
        self._lock = threading.Lock()

    @property
    def config(self) -> SessionConfig:
        """Configuration actuelle (lecture seule)."""
        return self._config

    def create_session(self) -> requests.Session:
        """Crée et retourne une nouvelle session HTTP isolée.

        Chaque appel produit une session complètement indépendante
        avec son propre pool de connexions, ses propres cookies et headers.

        Returns:
            requests.Session configurée et prête à l'emploi.
        """
        managed = ManagedSession(self._config)
        with self._lock:
            self._sessions.append(managed)
        return managed.session

    @contextmanager
    def managed_session(self) -> Generator[requests.Session, None, None]:
        """Context manager qui crée une session et la ferme automatiquement.

        Usage :
            with manager.managed_session() as session:
                response = session.get(url, timeout=manager.config.timeout)
        """
        managed = ManagedSession(self._config)
        with self._lock:
            self._sessions.append(managed)
        try:
            yield managed.session
        finally:
            managed.close()
            with self._lock:
                self._sessions = [s for s in self._sessions if s is not managed]

    def get_thread_session(self) -> requests.Session:
        """Retourne la session du thread courant (lazy init).

        Si le thread n'a pas encore de session, en crée une.
        Les appels suivants depuis le même thread retournent la même session.

        Returns:
            requests.Session isolée pour le thread courant.
        """
        if not hasattr(self._thread_local, "session"):
            self._thread_local.session = self.create_session()
        return self._thread_local.session

    def close_all(self) -> None:
        """Ferme toutes les sessions créées par ce manager."""
        with self._lock:
            for managed in self._sessions:
                managed.close()
            self._sessions.clear()

    # ── Context manager sur le manager lui-même ──────────────────────

    def __enter__(self) -> SessionManager:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close_all()
        return False
