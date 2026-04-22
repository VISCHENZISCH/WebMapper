# Web Scanner & Crawler

Un scanner Web simple écrit en Python utilisant `mechanize` et `BeautifulSoup4` pour explorer récursivement les liens d'un site web.

## Fonctionnalités

- Exploration récursive des liens (Crawler).
- Gestion des User-Agents.
- Support des Proxies.
- Extraction et gestion des cookies.
- Filtrage des liens internes pour rester sur le domaine cible.

## Installation

1. Clonez le dépôt 

2. Déplacez vous dans le dossier du projet
   ```bash
   cd web_scanner
   ```

3. Créez un environnement virtuel et installez les dépendances :
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Utilisation

Pour lancer le scan sur un site spécifique :

```bash
python3 cli/main.py <URL>
```

Exemple :
```bash
python3 cli/main.py http://example.com
```


```bash
python3 tests.py
```

