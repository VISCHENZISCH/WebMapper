# WebMapper v2.0

**WebMapper** est un outil d'audit de sécurité web modulaire, multi-threadé et extensible. Il permet de détecter automatiquement les vulnérabilités courantes sur des applications web et de générer des rapports détaillés aux formats HTML, JSON, CSV et SARIF.

© 2026 Félix TOVIGNAN

---

## Fonctionnalités

### Moteur de scan
- **Crawling récursif** : exploration automatique de tous les liens du domaine cible
- **Scan direct** : analyse d'une URL unique sans crawl (mode rapide)
- **Multi-threading** : exécution parallèle des modules (configurable)
- **Rotation de User-Agent** : évitement de détection par WAF
- **Support proxy** : compatible Burp Suite / OWASP ZAP


### Reporting
- **HTML** : rapport interactif avec tableau de findings, badges colorés par sévérité, mise en page responsive
- **JSON** : export structuré pour intégration CI/CD ou traitement automatisé
- **CSV** : tableur compatible Excel / LibreOffice
- **SARIF** : format standard pour intégration dans les pipelines DevSecOps (GitHub Code Scanning, etc.)

---

## Installation

### Cloner le dépôt
```bash
git clone https://github.com/VISCHENZISCH/WebMapper.git
cd WebMapper
```

### Linux (recommandé)
```bash
chmod +x install.sh
./install.sh
```

### Windows
```powershell
.\install.bat
```

---

## Utilisation

### Lancement interactif
```bash
# Linux
./webmapper.sh

# ou avec l'URL en argument direct
./webmapper.sh http://example.com
```

```powershell
# Windows
.\webmapper.bat http://example.com
```

### Options CLI
```
usage: main.py [-h] [-t THREADS] [--proxy PROXY] [--no-rotate-ua] [-v] [url]

positional arguments:
  url                   URL cible (ex: http://example.com)

options:
  -t, --threads N       Nombre de threads parallèles (défaut: 5)
  --proxy URL           Proxy HTTP (ex: http://127.0.0.1:8080)
  --no-rotate-ua        Désactiver la rotation de User-Agent
  -v, --verbose         Mode verbose (affiche les logs de debug)
```


## Clause de non-responsabilité

Cet outil a été créé **uniquement** pour des tests d'intrusion autorisés et des environnements de lab (ex : DVWA, Mutillidae, HackTheBox, TryHackMe).

**Toute utilisation sur des cibles sans autorisation préalable explicite est strictement illégale.** L'auteur décline toute responsabilité en cas de mauvaise utilisation de ce logiciel.