#!/usr/bin/env python3
# coding:utf-8
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# modules/recon/nuclei_runner.py — Intégration de Nuclei post-crawl.
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Final, Generator

__all__ = [
    "NucleiRunner",
    "NucleiResult",
    "run_nuclei",
]

logger = logging.getLogger("webmapper.recon.nuclei")


# Constantes

# Timeout global pour l'exécution de Nuclei (secondes)
DEFAULT_TIMEOUT: Final[int] = 600  # 10 minutes

# Sévérités Nuclei → mapping vers le format WebMapper
SEVERITY_MAP: Final[dict[str, str]] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

# Templates à exclure (trop bruyants ou faux positifs courants)
EXCLUDED_TAGS: Final[tuple[str, ...]] = (
    "dos",        # Denial of Service — dangereux en audit
    "fuzz",       # Fuzzing — trop lent pour un scan standard
    "intrusive",  # Tests intrusifs
)


# Modèle de résultat

@dataclass(slots=True, frozen=True)
class NucleiResult:
    """Résultat immuable d'un finding Nuclei.

    Attributes:
        template_id:  Identifiant du template (ex: "CVE-2021-44228").
        name:         Nom humain de la vulnérabilité.
        severity:     Sévérité (critical, high, medium, low, info).
        url:          URL affectée.
        matched_at:   URL exacte du match.
        description:  Description détaillée.
        reference:    Références (CVE, CWE, liens).
        tags:         Tags Nuclei (ex: "cve,apache,log4j").
        matcher_name: Nom du matcher qui a triggeré.
        extracted:    Données extraites par Nuclei.
    """
    template_id: str
    name: str
    severity: str
    url: str
    matched_at: str = ""
    description: str = ""
    reference: str = ""
    tags: str = ""
    matcher_name: str = ""
    extracted: str = ""


# Conversion vers le format de finding WebMapper

def _nuclei_to_finding(result: NucleiResult) -> dict:
    """Convertit un NucleiResult en finding au format WebMapper.

    Returns:
        Dict au format unifié {type, severity, url, detail, evidence}.
    """
    return {
        "type": f"NUCLEI_{result.template_id.upper().replace('-', '_')}",
        "severity": SEVERITY_MAP.get(result.severity.lower(), "info"),
        "url": result.url,
        "detail": f"[Nuclei] {result.name} — {result.description[:200]}"
        if result.description
        else f"[Nuclei] {result.name}",
        "evidence": (
            f"Template: {result.template_id} | "
            f"Tags: {result.tags} | "
            f"Matched: {result.matched_at}"
        ),
    }


# Runner principal

class NucleiRunner:
    """Runner Nuclei pour scanner des URLs post-crawl.

    Écrit les URLs dans un fichier temporaire, lance Nuclei en
    subprocess avec sortie JSONL, puis parse les résultats.

    Usage :
        runner = NucleiRunner(urls=["http://example.com/", ...])
        findings = runner.run()

    Args:
        urls:              Liste d'URLs à scanner.
        timeout:           Timeout global en secondes.
        severity_filter:   Sévérités à inclure (défaut: toutes).
        extra_args:        Arguments Nuclei supplémentaires.
        nuclei_binary:     Chemin vers le binaire nuclei.
    """
    __slots__ = (
        "_urls", "_timeout", "_severity_filter",
        "_extra_args", "_nuclei_binary",
    )

    def __init__(
        self,
        urls: list[str],
        timeout: int = DEFAULT_TIMEOUT,
        severity_filter: tuple[str, ...] | None = None,
        extra_args: list[str] | None = None,
        nuclei_binary: str | None = None,
    ) -> None:
        self._urls = urls
        self._timeout = timeout
        self._severity_filter = severity_filter
        self._extra_args = extra_args or []
        self._nuclei_binary = nuclei_binary or self._find_nuclei()

    @staticmethod
    def _find_nuclei() -> str:
        """Cherche le binaire nuclei dans le PATH."""
        path = shutil.which("nuclei")
        if path:
            return path
        # Emplacements courants
        for candidate in ("/usr/local/bin/nuclei", os.path.expanduser("~/go/bin/nuclei")):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return "nuclei"  # Laisser subprocess tenter le PATH

    @staticmethod
    def is_available() -> bool:
        """Vérifie si Nuclei est installé et accessible."""
        try:
            result = subprocess.run(
                ["nuclei", "--version"],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _build_command(self, urls_file: str, output_file: str) -> list[str]:
        """Construit la commande Nuclei."""
        cmd = [
            self._nuclei_binary,
            "-list", urls_file,
            "-jsonl",                      # Sortie JSONL (une ligne JSON par finding)
            "-output", output_file,
            "-silent",                     # Pas de sortie verbose
            "-no-color",                   # Pas de codes ANSI
            "-timeout", "10",              # Timeout par requête HTTP
            "-retries", "1",               # 1 seul retry par requête
            "-rate-limit", "50",           # Max 50 req/s pour éviter le rate-limiting
            "-bulk-size", "25",            # Taille du batch
            "-concurrency", "10",          # Templates en parallèle
        ]

        # Exclure les tags dangereux
        if EXCLUDED_TAGS:
            cmd.extend(["-exclude-tags", ",".join(EXCLUDED_TAGS)])

        # Filtre de sévérité
        if self._severity_filter:
            cmd.extend(["-severity", ",".join(self._severity_filter)])

        # Arguments supplémentaires
        cmd.extend(self._extra_args)

        return cmd

    def _parse_jsonl(self, output_file: str) -> Generator[NucleiResult, None, None]:
        """Parse le fichier de sortie JSONL de Nuclei.

        Yields:
            NucleiResult pour chaque finding valide.
        """
        if not os.path.isfile(output_file):
            return

        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    # Extraction des champs Nuclei
                    info = data.get("info", {})
                    references = info.get("reference", [])
                    if isinstance(references, list):
                        references = ", ".join(references)

                    yield NucleiResult(
                        template_id=data.get("template-id", data.get("templateID", "unknown")),
                        name=info.get("name", "Unknown"),
                        severity=info.get("severity", "info"),
                        url=data.get("host", data.get("url", "")),
                        matched_at=data.get("matched-at", data.get("matchedAt", "")),
                        description=info.get("description", ""),
                        reference=references if isinstance(references, str) else "",
                        tags=", ".join(info.get("tags", [])) if isinstance(info.get("tags"), list) else str(info.get("tags", "")),
                        matcher_name=data.get("matcher-name", data.get("matcherName", "")),
                        extracted=str(data.get("extracted-results", data.get("extractedResults", ""))),
                    )
                except json.JSONDecodeError:
                    logger.debug("Ligne JSONL invalide (#%d) : %s", line_num, line[:100])
                except Exception as exc:
                    logger.debug("Erreur parsing finding Nuclei (#%d) : %s", line_num, exc)

    def run(self) -> list[dict]:
        """Lance Nuclei et retourne les findings au format WebMapper.

        Returns:
            Liste de dicts au format unifié WebMapper.
            Liste vide si Nuclei n'est pas disponible ou si le scan échoue.
        """
        if not self._urls:
            logger.info("Aucune URL à scanner avec Nuclei.")
            return []

        # Vérification de la disponibilité de Nuclei
        if not self.is_available():
            logger.warning(
                "Nuclei n'est pas installé ou inaccessible. "
                "Installez-le : https://github.com/projectdiscovery/nuclei"
            )
            return []

        findings: list[dict] = []

        # Fichiers temporaires pour les URLs et la sortie
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="webmapper_urls_"
            ) as urls_f:
                urls_file = urls_f.name
                for url in self._urls:
                    urls_f.write(f"{url}\n")

            output_file = urls_file.replace(".txt", "_results.jsonl")

            # Construction et exécution de la commande
            cmd = self._build_command(urls_file, output_file)
            logger.info(
                "Lancement de Nuclei sur %d URL(s) (timeout: %ds)",
                len(self._urls), self._timeout,
            )
            logger.debug("Commande : %s", " ".join(cmd))

            try:
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=self._timeout,
                    text=True,
                )

                if process.returncode not in (0, 1):
                    # returncode 1 = findings trouvés (normal pour Nuclei)
                    logger.warning(
                        "Nuclei terminé avec code %d : %s",
                        process.returncode,
                        process.stderr[:500] if process.stderr else "(pas de stderr)",
                    )

            except subprocess.TimeoutExpired:
                logger.warning(
                    "Nuclei timeout après %ds — résultats partiels récupérés.",
                    self._timeout,
                )
            except FileNotFoundError:
                logger.error("Binaire Nuclei introuvable : %s", self._nuclei_binary)
                return []

            # Parsing des résultats
            for nuclei_result in self._parse_jsonl(output_file):
                findings.append(_nuclei_to_finding(nuclei_result))

            logger.info("Nuclei : %d finding(s) détecté(s).", len(findings))

        finally:
            # Nettoyage des fichiers temporaires
            for f in (urls_file, output_file):
                try:
                    if os.path.isfile(f):
                        os.unlink(f)
                except OSError:
                    pass

        return findings


# Fonction de convenance

def run_nuclei(
    urls: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    severity_filter: tuple[str, ...] | None = None,
) -> list[dict]:
    """Fonction de convenance pour lancer un scan Nuclei.

    Args:
        urls:            Liste d'URLs à scanner.
        timeout:         Timeout global en secondes.
        severity_filter: Sévérités à inclure.

    Returns:
        Liste de findings au format WebMapper.
    """
    runner = NucleiRunner(
        urls=urls,
        timeout=timeout,
        severity_filter=severity_filter,
    )
    return runner.run()
