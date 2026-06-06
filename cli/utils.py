#!/usr/bin/env python3
# coding:utf-8
"""
Utilitaires partagés entre tous les modules de WebMapper.

  - Rotation de User-Agent
  - Calcul de similarité (analyse différentielle)
  - Obfuscation de payloads (évasion WAF)
  - Extraction unifiée des champs de formulaires HTML
"""
import urllib.parse
import difflib
import logging

logger = logging.getLogger("webmapper")

# Liste de User-Agents réalistes pour la rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]


def calculate_similarity(text1: str, text2: str) -> float:
    """
    Calcule le ratio de similarité structurelle entre deux pages HTML.
    Utilise quick_ratio() en pré-filtre O(n) avant ratio() O(n²)
    pour éviter les calculs coûteux sur les grandes pages.
    """
    sm = difflib.SequenceMatcher(None, text1 or "", text2 or "")
    # Filtre rapide : si quick_ratio < 0.5 → inutile de calculer le ratio exact
    if sm.quick_ratio() < 0.5:
        return sm.quick_ratio()
    return sm.ratio()


def obfuscate_payload(payload: str, method: str = "url") -> str:
    """Obfusque un payload pour contourner les filtres basiques de WAF."""
    if method == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif method == "hex":
        return "".join(f"\\x{ord(c):02x}" for c in payload)
    elif method == "sql_spaces":
        return payload.replace(" ", "/**/")
    elif method == "url":
        return urllib.parse.quote(payload)
    return payload


def extract_form_fields(form, *, include_hidden: bool = True) -> tuple[dict, list[str]]:
    """
    Extrait les champs d'un formulaire HTML de manière unifiée.

    :param form:            Objet BeautifulSoup <form>
    :param include_hidden:  Si True, inclut les champs hidden comme injectables
    :return:                (template_data, injectable_names)
                            - template_data  : dict {nom: valeur_par_défaut} pour tous les champs
                            - injectable_names : liste des noms de champs injectables
    """
    template = {}
    injectable = []
    injectable_types = {"text", "password", "email", "search", "url"}
    if include_hidden:
        injectable_types.add("hidden")

    for inp in form.find_all(["input", "textarea"]):
        name = inp.get("name")
        if not name:
            continue

        if inp.name == "textarea":
            template[name] = inp.string or ""
            injectable.append(name)
            continue

        itype = (inp.get("type") or "text").lower()
        if itype in injectable_types:
            template[name] = inp.get("value") or ""
            injectable.append(name)
        elif itype in ("submit", "button", "image", "reset", "file"):
            template[name] = inp.get("value", "submit")
        elif itype in ("checkbox", "radio"):
            if inp.get("checked") is not None:
                template[name] = inp.get("value", "on")
        else:
            template[name] = inp.get("value", "")

    # Support <select>
    for select in form.find_all("select"):
        name = select.get("name")
        if name:
            option = select.find("option", selected=True) or select.find("option")
            template[name] = option.get("value", "") if option else ""

    return template, injectable
