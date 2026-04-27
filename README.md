# WebMapper  v1.0

**WebMapper** est un outil de pointe pour l'audit de sécurité web. Conçu pour être à la fois modulaire, rapide et visuellement immersif, il permet de détecter les vulnérabilités courantes (XSS, SQLi, Cookies non sécurisés) et de générer des rapports détaillés.

© 2025 Félix TOVIGNAN

---

## Fonctionnalités Clés

- **Crawling** : Exploration récursive des liens pour cartographier l'intégralité du domaine cible.
- **Moteur de Détection Multi-Vecteurs** :
    - **XSS (Cross-Site Scripting)** : Audit des paramètres d'URL et des formulaires avec injection de payloads intelligents.
    - **Injection SQL** : Détection via analyse de signatures d'erreurs (MySQL, PostgreSQL, Oracle, etc.).
- **Audit de Sécurité des Cookies** 
- **Reporting Automatique** : Génération instantanée de rapports professionnels aux formats **HTML**, **JSON** et **CSV**.

---

## Installation

### Installation initiale
```bash
git clone https://github.com/VISCHENZISCH/WebMapper.git
cd WebMapper
```

### Sur Linux (Méthode recommandée)
Utilisez le script automatisé pour configurer l'environnement :
```bash
chmod +x install.sh
./install.sh
```

### Sur Windows
Double-cliquez sur `install.bat` ou utilisez PowerShell :
```powershell
.\install.bat
```

---

## Utilisation

Lancez l'outil via le lanceur dédié :

### Linux
```bash
./webmapper.sh
```

### Windows
```powershell
.\webmapper.bat
```

> **Note :** Vous pouvez également passer l'URL directement en argument : `./webmapper.sh http://example.com`

---

## Rapports d'Analyse

Tous les résultats sont sauvegardés dans le dossier `OUTPUT/reports/`.
Chaque scan génère des fichiers horodatés, ainsi qu'un lien direct vers le dernier rapport via :
- `latest_report.html`
- `latest_report.json`
- `latest_report.csv`

---



---

## Clause de non-responsabilité

Cet outil a été créé uniquement pour des tests d'intrusion autorisés. **Toute utilisation de cet outil sur des cibles sans autorisation préalable est strictement illégale.** L'auteur décline toute responsabilité en cas de mauvaise utilisation de ce logiciel.