#!/usr/bin/env python3
# coding:utf-8
import re
from dataclasses import dataclass, field
from typing import List, Optional

# Patterns de cookies sensibles
SENSITIVE_PATTERNS = ["session", "token", "auth", "jwt", "sid", "csrf", "login", "key", "secret"]

SAMESITE_LEVELS = {"strict": 0, "lax": 1, "none": 2}  # 0 = plus sécurisé


# Dataclasses
@dataclass
class CookieInfo:
    name:       str
    value:      str          # valeur masquée à l'affichage
    domain:     str
    path:       str
    secure:     bool
    httponly:   bool
    samesite:   Optional[str]
    sensitive:  bool         # nom suspect ?

    def masked_value(self) -> str:
        """Affiche seulement les 10 premiers caractères"""
        return self.value[:10] + "..." if len(self.value) > 10 else self.value


@dataclass
class CookieResult:
    cookies: List[CookieInfo] = field(default_factory=list)
    issues:  List[str]        = field(default_factory=list)

    def add_cookie(self, info: CookieInfo):
        self.cookies.append(info)

    def add_issue(self, msg: str):
        self.issues.append(msg)

    def to_dict(self) -> dict:
        """Export JSON / logging"""
        return {
            "cookies": [
                {
                    "name":      c.name,
                    "value":     c.masked_value(),
                    "domain":    c.domain,
                    "path":      c.path,
                    "secure":    c.secure,
                    "httponly":  c.httponly,
                    "samesite":  c.samesite,
                    "sensitive": c.sensitive,
                }
                for c in self.cookies
            ],
            "issues": self.issues,
        }

    def summary(self) -> str:
        """Affichage terminal coloré"""
        W  = "\033[97m"   # blanc
        B  = "\033[94m"   # bleu
        C  = "\033[96m"   # cyan
        Y  = "\033[93m"   # jaune
        G  = "\033[92m"   # vert
        R  = "\033[91m"   # rouge
        RS = "\033[0m"    # reset

        if not self.cookies:
            return f"{W}[i] Aucun cookie détecté.{RS}\n"

        lines = [f"{B}[*] {len(self.cookies)} cookie(s) trouvé(s) :{RS}"]

        for c in self.cookies:
            # Indicateurs visuels des flags
            secure_flag   = f"{G}✔ Secure{RS}"   if c.secure   else f"{R}✘ Secure{RS}"
            httponly_flag = f"{G}✔ HttpOnly{RS}"  if c.httponly else f"{R}✘ HttpOnly{RS}"

            if c.samesite:
                level = SAMESITE_LEVELS.get(c.samesite.lower(), 2)
                color = [G, Y, R][level]
                samesite_flag = f"{color}SameSite={c.samesite}{RS}"
            else:
                samesite_flag = f"{R}✘ SameSite{RS}"

            sensitive_tag = f" {Y}[SENSIBLE]{RS}" if c.sensitive else ""

            lines.append(
                f"  {C}{c.name}{RS}{sensitive_tag}\n"
                f"    valeur  : {c.masked_value()}\n"
                f"    domaine : {c.domain} | chemin : {c.path}\n"
                f"    flags   : {secure_flag}  {httponly_flag}  {samesite_flag}"
            )

        if self.issues:
            lines.append(f"\n{Y}[!] Problèmes de sécurité détectés :{RS}")
            for issue in self.issues:
                lines.append(f"    {R}→{RS} {issue}")
        else:
            lines.append(f"\n{G}[✔] Aucun problème de sécurité détecté.{RS}")

        return "\n".join(lines) + "\n"


# Module principal 
class CookieModule:

    @staticmethod
    def _parse_flags_from_headers(response) -> dict:
        """
        Extrait les flags HttpOnly / SameSite directement depuis
        les headers HTTP bruts (Set-Cookie) — plus fiable que _rest.
        Retourne un dict : { cookie_name -> {httponly, samesite} }
        """
        flags_map = {}
        if not response:
            return flags_map
            
        # requests response.headers est un CaseInsensitiveDict, getlist n'y est pas forcément direct
        # Mais Set-Cookie peut apparaître plusieurs fois. 
        # On utilise response.raw.headers si possible (urllib3)
        raw_headers = []
        if hasattr(response, "raw") and hasattr(response.raw, "headers"):
            # Pour urllib3 < 2.0
            if hasattr(response.raw.headers, "getlist"):
                raw_headers = response.raw.headers.getlist("Set-Cookie")
            # Pour urllib3 >= 2.0
            elif hasattr(response.raw.headers, "get_all"):
                raw_headers = response.raw.headers.get_all("Set-Cookie")
        
        if not raw_headers:
            # Fallback manuel si besoin
            pass

        for header in raw_headers:
            parts = [p.strip() for p in header.split(";")]
            if not parts:
                continue

            # 1er élément = name=value
            name_value = parts[0].split("=", 1)
            if len(name_value) < 2:
                continue
            cookie_name = name_value[0].strip()

            header_lower = header.lower()
            httponly  = "httponly"  in header_lower
            samesite  = None

            match = re.search(r"samesite=(\w+)", header_lower)
            if match:
                samesite = match.group(1).capitalize()  # Strict / Lax / None

            flags_map[cookie_name] = {"httponly": httponly, "samesite": samesite}

        return flags_map

    @staticmethod
    def _is_sensitive(name: str) -> bool:
        name_lower = name.lower()
        return any(p in name_lower for p in SENSITIVE_PATTERNS)

    @staticmethod
    def _audit(info: CookieInfo, result: CookieResult):
        """Vérifie les flags de sécurité et remplit result.issues"""
        n = info.name

        if not info.secure:
            result.add_issue(f"'{n}' : flag 'Secure' manquant (cookie transmis en clair sur HTTP).")

        if not info.httponly:
            result.add_issue(f"'{n}' : flag 'HttpOnly' manquant (accessible via JavaScript).")

        if not info.samesite:
            result.add_issue(f"'{n}' : flag 'SameSite' absent (risque CSRF).")
        elif info.samesite.lower() == "none" and not info.secure:
            result.add_issue(f"'{n}' : SameSite=None sans Secure est invalide (RFC 6265bis).")

        if info.sensitive and not info.httponly:
            result.add_issue(f"'{n}' : cookie sensible sans HttpOnly — vol de session possible.")

    @staticmethod
    def analyze(session, response=None) -> CookieResult:
        """
        Analyse tous les cookies de la session.
        Passer `response` permet une détection plus fiable de HttpOnly / SameSite.
        """
        result   = CookieResult()
        flags_map = CookieModule._parse_flags_from_headers(response) if response else {}

        for cookie in session.cookies:
            # Flags depuis headers bruts si dispo, sinon fallback sur _rest
            header_flags = flags_map.get(cookie.name, {})

            httponly = header_flags.get("httponly", False)
            samesite = header_flags.get("samesite", None)

            # Fallback _rest si pas de réponse passée ou si header n'avait pas l'info
            if not httponly and hasattr(cookie, "_rest"):
                rest_lower = {k.lower(): v for k, v in cookie._rest.items()}
                httponly   = "httponly" in rest_lower
                if not samesite:
                    samesite = rest_lower.get("samesite", None)
                    if samesite:
                        samesite = samesite.capitalize()

            info = CookieInfo(
                name      = cookie.name,
                value     = cookie.value or "",
                domain    = cookie.domain or "",
                path      = cookie.path or "/",
                secure    = bool(cookie.secure),
                httponly  = httponly,
                samesite  = samesite,
                sensitive = CookieModule._is_sensitive(cookie.name),
            )

            result.add_cookie(info)
            CookieModule._audit(info, result)

        return result
