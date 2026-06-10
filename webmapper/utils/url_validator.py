#!/usr/bin/env python3
# coding:utf-8
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# utils/url_validator.py — Validation stricte d'URL pour WebMapper.
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
from __future__ import annotations

import re
import socket
import urllib.parse
from dataclasses import dataclass
from functools import lru_cache
from typing import Final

__all__ = ["URLValidator", "validate_url", "ValidationResult"]


# Constantes 

ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})

# RFC 1123 hostname : lettres, chiffres, tirets, points
_HOSTNAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

# IPv4 simple
_IPV4_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Longueur max d'une URL raisonnable
MAX_URL_LENGTH: Final[int] = 2048


# Modèle de résultat 

@dataclass(slots=True, frozen=True)
class ValidationResult:
    """Résultat immuable et léger d'une validation d'URL.

    Attributes:
        is_valid:       True si l'URL est valide et exploitable par le scanner.
        normalized_url: URL normalisée (trailing slash retiré, schéma en minuscule).
        error:          Message d'erreur explicite si invalide, None sinon.
        scheme:         Schéma extrait (http ou https).
        hostname:       Nom d'hôte ou IP extraite.
        port:           Port explicite ou None (implicite = 80/443).
    """
    is_valid: bool
    normalized_url: str
    error: str | None = None
    scheme: str = ""
    hostname: str = ""
    port: int | None = None


#Validateur principal

class URLValidator:
    """Validateur d'URL callable et réutilisable.

    Vérifie :
      1. Longueur raisonnable (≤ 2048 caractères)
      2. Schéma valide (http / https uniquement)
      3. Domaine non vide et conforme RFC 1123 (ou IPv4)
      4. Port dans la plage valide (1–65535) si explicite
      5. Pas de caractères dangereux dans le chemin

    Usage :
        validator = URLValidator()
        result = validator("http://example.com")
        # ou directement :
        result = validate_url("http://example.com")

    Le résultat est un ValidationResult immuable (frozen dataclass + __slots__).
    """

    # Caractères dangereux interdits dans le chemin URL brut
    _DANGEROUS_PATH_CHARS: Final[frozenset[str]] = frozenset({
        "\x00", "\n", "\r", "\t",
    })

    def __call__(self, url: str) -> ValidationResult:
        """Valide une URL et retourne un ValidationResult."""
        return self._validate(url)

    def _validate(self, url: str) -> ValidationResult:
        """Logique de validation interne."""
        # Nettoyage basique
        url = url.strip()

        # 1. Vérification de longueur
        if not url:
            return ValidationResult(
                is_valid=False,
                normalized_url="",
                error="URL vide — veuillez fournir une URL cible.",
            )

        if len(url) > MAX_URL_LENGTH:
            return ValidationResult(
                is_valid=False,
                normalized_url=url,
                error=f"URL trop longue ({len(url)} caractères, max {MAX_URL_LENGTH}).",
            )

        # 2. Parsing de l'URL
        parsed = urllib.parse.urlparse(url)

        # 3. Vérification du schéma
        scheme = parsed.scheme.lower()
        if not scheme:
            return ValidationResult(
                is_valid=False,
                normalized_url=url,
                error="Schéma manquant — l'URL doit commencer par http:// ou https://",
            )

        if scheme not in ALLOWED_SCHEMES:
            return ValidationResult(
                is_valid=False,
                normalized_url=url,
                error=f"Schéma '{scheme}' non supporté — utilisez http:// ou https://",
            )

        # 4. Vérification du domaine
        hostname = parsed.hostname
        if not hostname:
            return ValidationResult(
                is_valid=False,
                normalized_url=url,
                error="Domaine absent — l'URL doit contenir un nom d'hôte valide.",
            )

        # Valider le format du hostname (RFC 1123) ou IPv4
        if not (_HOSTNAME_RE.match(hostname) or _IPV4_RE.match(hostname)):
            # Vérifier si c'est une IPv6 entre crochets
            if not (hostname.startswith("[") or parsed.netloc.startswith("[")):
                return ValidationResult(
                    is_valid=False,
                    normalized_url=url,
                    error=f"Nom d'hôte invalide : '{hostname}'",
                )

        # Bloquer localhost et plages privées en production (optionnel, désactivable)
        # Note : on autorise localhost pour les tests — la vérification peut être
        # activée via une variable d'environnement WEBMAPPER_BLOCK_PRIVATE=1

        # 5. Vérification du port
        try:
            port = parsed.port
        except ValueError:
            return ValidationResult(
                is_valid=False,
                normalized_url=url,
                error="Port invalide (doit être entre 1 et 65535).",
            )
        if port is not None:
            if not (1 <= port <= 65535):
                return ValidationResult(
                    is_valid=False,
                    normalized_url=url,
                    error=f"Port invalide : {port} (doit être entre 1 et 65535).",
                )

        # 6. Vérification de caractères dangereux dans le chemin
        path = parsed.path or ""
        for char in self._DANGEROUS_PATH_CHARS:
            if char in path:
                return ValidationResult(
                    is_valid=False,
                    normalized_url=url,
                    error=f"Caractère dangereux détecté dans le chemin URL (0x{ord(char):02x}).",
                )

        # 7. Normalisation
        normalized = urllib.parse.urlunparse((
            scheme,
            parsed.netloc.lower(),
            parsed.path.rstrip("/") if parsed.path != "/" else "/",
            parsed.params,
            parsed.query,
            "",  # On retire le fragment (#) — inutile pour le scanner
        ))

        return ValidationResult(
            is_valid=True,
            normalized_url=normalized,
            error=None,
            scheme=scheme,
            hostname=hostname.lower(),
            port=port,
        )


# Singleton pré-instancié 

_validator = URLValidator()


@lru_cache(maxsize=256)
def validate_url(url: str) -> ValidationResult:
    """Valide et normalise une URL (résultat mis en cache LRU).

    Fonction de convenance qui utilise le singleton URLValidator.
    Le cache LRU évite de revalider la même URL quand plusieurs
    modules la traitent en séquence.

    Args:
        url: URL à valider (ex: "http://example.com/path")

    Returns:
        ValidationResult avec is_valid, normalized_url, error, etc.

    Example:
        >>> result = validate_url("http://example.com")
        >>> result.is_valid
        True
        >>> result.normalized_url
        'http://example.com'
    """
    return _validator(url)
