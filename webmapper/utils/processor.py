#!/usr/bin/env python3
# coding:utf-8
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# utils/processor.py — Processing unifié des résultats de scan.
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Final, Generator

__all__ = [
    "Finding",
    "ScanResult",
    "ResultAggregator",
    "BaseScanner",
    "Severity",
]

logger = logging.getLogger("webmapper.processor")


# Sévérités et priorités 

class Severity:
    """Constantes de sévérité avec priorité de tri."""
    CRITICAL: Final[str] = "critical"
    HIGH: Final[str] = "high"
    MEDIUM: Final[str] = "medium"
    LOW: Final[str] = "low"
    INFO: Final[str] = "info"

    # Priorité de tri : plus le score est élevé, plus c'est grave
    PRIORITY: Final[dict[str, int]] = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }

    @staticmethod
    def priority(severity: str) -> int:
        """Retourne le score de priorité d'une sévérité."""
        return Severity.PRIORITY.get(severity.lower(), 0)


# Finding standardisé 

@dataclass(slots=True)
class Finding:
    """Finding de vulnérabilité au format standardisé WebMapper.

    Tous les modules produisent des findings dans ce format.
    La déduplication se fait via le fingerprint (hash des champs clés).

    Attributes:
        type:       Type de vulnérabilité (ex: "XSS_REFLECTED", "SQL_INJECTION").
        severity:   Sévérité normalisée (critical/high/medium/low/info).
        url:        URL affectée.
        detail:     Description détaillée du finding.
        evidence:   Preuve technique (payload, signature, etc.).
        source:     Module qui a produit ce finding.
        timestamp:  Horodatage de la découverte.
        fingerprint: Hash unique pour la déduplication.
    """
    type: str
    severity: str
    url: str
    detail: str
    evidence: str = ""
    source: str = ""
    timestamp: str = ""
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """Normalise la sévérité et génère le fingerprint."""
        self.severity = self.severity.lower()
        if self.severity not in Severity.PRIORITY:
            self.severity = "info"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        """Calcule un hash unique basé sur les champs discriminants."""
        raw = f"{self.type}|{self.url}|{self.evidence[:80]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        """Convertit le finding en dict (compatible format existant)."""
        return {
            "type": self.type,
            "severity": self.severity,
            "url": self.url,
            "detail": self.detail,
            "evidence": self.evidence,
            "source": self.source,
            "timestamp": self.timestamp,
        }

    @staticmethod
    def from_dict(data: dict, source: str = "") -> Finding:
        """Crée un Finding depuis un dict brut (format legacy)."""
        return Finding(
            type=data.get("type", "UNKNOWN"),
            severity=data.get("severity", "info"),
            url=data.get("url", ""),
            detail=data.get("detail", ""),
            evidence=data.get("evidence", ""),
            source=source or data.get("source", ""),
        )


#  Résultat de scan agrégé 

@dataclass(slots=True)
class ScanResult:
    """Résultat agrégé d'un scan complet.

    Objet unifié transmis au générateur de rapport.

    Attributes:
        findings:        Liste de tous les findings dédupliqués.
        stats:           Statistiques de comptage par sévérité.
        by_type:         Findings groupés par type de vulnérabilité.
        by_url:          Findings groupés par URL.
        sources:         Liste des modules ayant contribué.
        total_urls:      Nombre total d'URLs scannées.
        scan_duration:   Durée du scan en secondes.
        started_at:      Horodatage de début.
        finished_at:     Horodatage de fin.
    """
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, list[Finding]] = field(default_factory=dict)
    by_url: dict[str, list[Finding]] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    total_urls: int = 0
    scan_duration: float = 0.0
    started_at: str = ""
    finished_at: str = ""

    @property
    def total_findings(self) -> int:
        """Nombre total de findings."""
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        """Nombre de findings critiques."""
        return self.stats.get("critical", 0)

    @property
    def high_count(self) -> int:
        """Nombre de findings high."""
        return self.stats.get("high", 0)

    @property
    def has_critical(self) -> bool:
        """True si au moins un finding critique ou high."""
        return self.critical_count > 0 or self.high_count > 0

    def to_dict_list(self) -> list[dict]:
        """Convertit tous les findings en liste de dicts (format legacy).

        Compatible avec Reporter.generate_all() existant.
        """
        return [f.to_dict() for f in self.findings]

    def iter_by_severity(self) -> Generator[Finding, None, None]:
        """Itère sur les findings triés par sévérité décroissante.

        Yields:
            Finding, du plus critique au moins critique.
        """
        sorted_findings = sorted(
            self.findings,
            key=lambda f: Severity.priority(f.severity),
            reverse=True,
        )
        yield from sorted_findings


# Agrégateur central 

class ResultAggregator:
    """Agrégateur central fusionnant les résultats de tous les modules.

    Gère la déduplication, le groupement et les statistiques.

    Usage :
        aggregator = ResultAggregator()
        
        # Depuis chaque module :
        aggregator.add_findings(xss_findings, source="xss")
        aggregator.add_findings(sqli_findings, source="sqli")
        aggregator.add_findings(nuclei_findings, source="nuclei")
        
        # Résultat final :
        result = aggregator.finalize()
        report_data = result.to_dict_list()
    """
    __slots__ = ("_findings", "_fingerprints", "_sources", "_started_at")

    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._fingerprints: set[str] = set()  # Déduplication O(1)
        self._sources: set[str] = set()
        self._started_at: str = datetime.now(timezone.utc).isoformat()

    def add_finding(self, finding: Finding) -> bool:
        """Ajoute un finding s'il n'est pas dupliqué.

        Args:
            finding: Finding standardisé.

        Returns:
            True si ajouté, False si doublon.
        """
        if finding.fingerprint in self._fingerprints:
            logger.debug("Finding dupliqué ignoré : %s", finding.fingerprint)
            return False

        self._fingerprints.add(finding.fingerprint)
        self._findings.append(finding)
        if finding.source:
            self._sources.add(finding.source)
        return True

    def add_findings(
        self,
        findings: list[dict] | list[Finding],
        source: str = "",
    ) -> int:
        """Ajoute une liste de findings (format dict ou Finding).

        Args:
            findings: Liste de findings bruts ou standardisés.
            source:   Nom du module source.

        Returns:
            Nombre de findings effectivement ajoutés (après dédup).
        """
        added = 0
        for item in findings:
            if isinstance(item, dict):
                finding = Finding.from_dict(item, source=source)
            else:
                finding = item
                if source and not finding.source:
                    finding.source = source

            if self.add_finding(finding):
                added += 1

        return added

    def finalize(self, total_urls: int = 0) -> ScanResult:
        """Produit le résultat final agrégé.

        Args:
            total_urls: Nombre total d'URLs scannées.

        Returns:
            ScanResult complet avec statistiques et groupements.
        """
        finished_at = datetime.now(timezone.utc).isoformat()

        # Statistiques par sévérité
        stats = Counter(f.severity for f in self._findings)

        # Groupement par type
        by_type: dict[str, list[Finding]] = defaultdict(list)
        for f in self._findings:
            by_type[f.type].append(f)

        # Groupement par URL
        by_url: dict[str, list[Finding]] = defaultdict(list)
        for f in self._findings:
            by_url[f.url].append(f)

        # Tri par sévérité décroissante
        sorted_findings = sorted(
            self._findings,
            key=lambda f: Severity.priority(f.severity),
            reverse=True,
        )

        return ScanResult(
            findings=sorted_findings,
            stats=dict(stats),
            by_type=dict(by_type),
            by_url=dict(by_url),
            sources=sorted(self._sources),
            total_urls=total_urls,
            started_at=self._started_at,
            finished_at=finished_at,
        )

    @property
    def count(self) -> int:
        """Nombre actuel de findings."""
        return len(self._findings)


# Interface commune des scanners 

class BaseScanner(ABC):
    """Classe abstraite définissant l'interface d'un module de scan.

    Tous les modules de scan devront à terme implémenter cette interface.
    Pour l'instant, les modules existants utilisent encore la convention
    scan(url, session) → list[dict], qui reste supportée.

    Usage futur :
        class XSSScanner(BaseScanner):
            def scan(self, url, session):
                ...
            def report(self, findings):
                ...
    """

    @abstractmethod
    def scan(self, url: str, session) -> list[dict]:
        """Lance le scan sur une URL.

        Args:
            url:     URL à scanner.
            session: Session requests isolée.

        Returns:
            Liste de findings au format dict.
        """
        ...

    @abstractmethod
    def report(self, findings: list[dict]) -> str:
        """Génère un rapport textuel des findings.

        Args:
            findings: Liste de findings produits par scan().

        Returns:
            Rapport formaté.
        """
        ...

    @property
    def name(self) -> str:
        """Nom du scanner (par défaut: nom de la classe)."""
        return self.__class__.__name__
