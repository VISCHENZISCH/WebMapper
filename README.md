<div align="center">
<pre style="font-family: monospace; text-align: left; display: inline-block; background-color: #0d1117; padding: 20px; border-radius: 8px; line-height: 1.2;">
<span style="color: #d700d7; font-weight: bold;">  __      __      ___. _____                                           </span>
<span style="color: #d700d7; font-weight: bold;">  \ \    /  \ ____\_ |__/     \ _____  ______ ______   ___________  </span>
<span style="color: #af5fff; font-weight: bold;">   \ \/\/   // __ \| __ \  \ /  \\__  \ \____ \\____ \_/ __ \_  __ \ </span>
<span style="color: #af5fff; font-weight: bold;">    \        /\  ___/| \_\ \   Y  / / __ \|  |_> >  |_> >\  ___/|  | \/  </span>
<span style="color: #00afff; font-weight: bold;">     \__/\  /  \___  >___  /__|_|  /(____  /   __/|   __/  \___  >__|    </span>
<span style="color: #00afff; font-weight: bold;">          \/       \/    \/      \/      \/|__|   |__|         \/       </span>
</pre>
</div>

# WebMapper v2.0

**WebMapper** est un outil d'audit de sécurité web modulaire, multi-threadé et extensible. Il permet de détecter automatiquement les vulnérabilités courantes sur des applications web et de générer des rapports détaillés aux formats HTML, JSON, CSV et SARIF.

© 2026 Félix TOVIGNAN

---

## Fonctionnalités

### Moteur de scan
- **Menu interactif** : Choisissez parmi 6 actions ciblées (Full Scan, Direct, Crawl, DNS, Nmap, Nuclei)
- **Énumération DNS avancée** : Découverte de sous-domaines via une wordlist embarquée de 2000 entrées.
- **Port Scanning intelligent** : Détection de ports via Nmap (Mode rapide & Mode Deep Scan avec `nmap.json`). Déduplication automatique des IP pour accélérer le processus.
- **Crawling récursif** : exploration automatique de tous les liens du domaine cible.
- **Intégration Nuclei** : Exécution automatique de templates de vulnérabilités.
- **Multi-threading** : exécution parallèle des modules avec gestion dynamique des *workers*.
- **Évasion** : Rotation de User-Agent et support de proxy HTTP/HTTPS.


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
chmod +x ./webmapper/scripts/install.sh
./webmapper/scripts/install.sh
```

### Windows
```powershell
.\webmapper\scripts\install.bat
```

### Mettre à jour WebMapper
Pour récupérer la dernière version :
```bash
./webmapper.sh --update
```
*Note : Le programme vous proposera également de vérifier les mises à jour lorsque vous quittez le menu interactif (Option 7).*

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
```bash
# Linux
usage: ./webmapper.sh [-h] [-t THREADS] [--proxy PROXY] [--no-rotate-ua] [--wordlist FILE] [--ports PORTS] [--nuclei-args ARGS] [--update] [-v] [url]

# Windows
usage: .\webmapper.bat [-h] [-t THREADS] [--proxy PROXY] [--no-rotate-ua] [--wordlist FILE] [--ports PORTS] [--nuclei-args ARGS] [--update] [-v] [url]
```

```text
positional arguments:
  url                   URL cible (ex: http://example.com)

options de scan:
  -t, --threads N       Nombre de threads parallèles (défaut: 5)
  --proxy URL           Proxy HTTP (ex: http://127.0.0.1:8080)
  --no-rotate-ua        Désactiver la rotation de User-Agent
  -v, --verbose         Mode verbose (affiche les logs de debug)

options de modules:
  --wordlist FILE       Chemin vers une wordlist custom pour l'énumération DNS
  --ports PORTS         Ports spécifiques à scanner (ex: '80,443' ou 'top100')
  --nuclei-args ARGS    Arguments supplémentaires à passer à Nuclei (ex: '-tags cve')

maintenance:
  --update              Met à jour WebMapper
```


## Clause de non-responsabilité

Cet outil a été créé **uniquement** pour des tests d'intrusion autorisés et des environnements de lab (ex : DVWA, Mutillidae, HackTheBox, TryHackMe).

**Toute utilisation sur des cibles sans autorisation préalable explicite est strictement illégale.** L'auteur décline toute responsabilité en cas de mauvaise utilisation de ce logiciel.