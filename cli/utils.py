#!/usr/bin/env python3
# coding:utf-8
"""
Utilitaires partagés entre tous les modules de WebMapper.

  - Rotation de User-Agent
  - Calcul de similarité (analyse différentielle)
  - Obfuscation de payloads (évasion WAF)
  - Extraction unifiée des champs de formulaires HTML
  - Layout terminal (body, margin, padding, font-size)
"""
import os
import textwrap
import urllib.parse
import difflib
import logging



#  LAYOUT TERMINAL  (équivalents CSS)


# « font-size » : nombre max de caractères par ligne avant wrap.
# Plus la valeur est petite, plus le texte est « grand » (lisible).
FONT_SIZE  = 72   # max chars par ligne (équivalent font-size conséquent)
MARGIN_X   = 4   # marges gauche/droite (espaces)
PADDING_X  = 2   # padding interne supplémentaire


class MarginStdin:
    """
    Wrapper pour sys.stdin qui réinitialise le flag at_line_start du stdout
    après chaque lecture de ligne (car l'appui sur Entrée par l'utilisateur
    génère un retour à la ligne géré par le terminal).
    """
    def __init__(self, original_stdin, stdout_wrapper):
        self.original_stdin = original_stdin
        self.stdout_wrapper = stdout_wrapper

    def readline(self, *args, **kwargs):
        res = self.original_stdin.readline(*args, **kwargs)
        self.stdout_wrapper.at_line_start = True
        return res

    def read(self, *args, **kwargs):
        res = self.original_stdin.read(*args, **kwargs)
        self.stdout_wrapper.at_line_start = True
        return res

    def __getattr__(self, name):
        return getattr(self.original_stdin, name)


class MarginStdout:
    """
    Wrapper pour sys.stdout qui applique automatiquement une marge (margin/padding)
    à chaque début de ligne, sans modifier la logique d'affichage originale.
    """
    def __init__(self, original_stdout, margin=6):
        import sys
        self.original_stdout = original_stdout
        self.margin_str = " " * margin
        self.at_line_start = True
        
        # Envelopper sys.stdin pour réinitialiser at_line_start après une saisie
        if not isinstance(sys.stdin, MarginStdin):
            sys.stdin = MarginStdin(sys.stdin, self)

    def write(self, string):
        if not string:
            return
        
        parts = string.split('\n')
        for i, part in enumerate(parts):
            if i > 0:
                self.original_stdout.write('\n')
                self.at_line_start = True
            
            if part:
                if self.at_line_start:
                    self.original_stdout.write(self.margin_str)
                    self.at_line_start = False
                self.original_stdout.write(part)

    def flush(self):
        self.original_stdout.flush()


def get_term_width() -> int:
    """Retourne la largeur réelle du terminal (fallback: 100)."""
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 100


def body_width() -> int:
    """
    Calcule la largeur utile du 'body' terminal :
    min(FONT_SIZE, terminal_width - 2 × MARGIN_X).
    """
    return min(FONT_SIZE, get_term_width() - MARGIN_X * 2)


def padded(text: str, extra: int = 0) -> str:
    """
    Applique MARGIN_X + extra espaces à gauche.
    Simule padding-left / margin-left CSS.
    """
    return " " * (MARGIN_X + PADDING_X + extra) + text


def centered(text: str) -> str:
    """Centre le texte dans le terminal (margin: 0 auto)."""
    # On retire les codes ANSI pour calculer la vraie longueur visible
    import re
    clean = re.sub(r"\033\[[0-9;]*m", "", text)
    pad = max(0, (get_term_width() - len(clean)) // 2)
    return " " * pad + text


def wrap_lines(text: str, indent: int = 0) -> list[str]:
    """
    Découpe 'text' pour respecter body_width() puis indente chaque ligne.
    Retourne une liste de lignes prêtes à l'affichage.
    """
    prefix = " " * (MARGIN_X + PADDING_X + indent)
    width  = body_width() - indent
    wrapped = textwrap.wrap(text, width=max(20, width))
    return [prefix + line for line in wrapped] if wrapped else [prefix]


def print_wrapped(text: str, indent: int = 0) -> None:
    """Affiche un texte long avec wrap + margin automatiques."""
    for line in wrap_lines(text, indent):
        print(line)


def divider(char: str = "─", color: str = "", reset: str = "\033[0m") -> str:
    """
    Génère un séparateur horizontal de la largeur du body.
    Simule border-bottom / hr CSS.
    """
    line = char * body_width()
    margin = " " * MARGIN_X
    return f"{margin}{color}{line}{reset if color else ''}"


def print_section(title: str, color: str = "", reset: str = "\033[0m") -> None:
    """
    Affiche un titre de section centré entre deux dividers.
    Simule un <section> avec heading.
    """
    div = divider(color=color, reset=reset)
    print(f"\n{div}")
    print(centered(f"{color}{title}{reset}"))
    print(f"{div}\n")

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
