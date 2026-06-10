# Optimisation Python Moderne
### Gestion du CPU, de la RAM et des vitesses d'exécution

> Python 3.10+ | Approche pragmatique & moderne

---

## Table des matières

1. [Comprendre le modèle d'exécution Python](#1-comprendre-le-modèle-dexécution-python)
2. [Mesurer avant d'optimiser](#2-mesurer-avant-doptimiser)
3. [Gestion de la mémoire (RAM)](#3-gestion-de-la-mémoire-ram)
4. [Optimisation CPU & Calcul](#4-optimisation-cpu--calcul)
5. [Concurrence & Parallélisme](#5-concurrence--parallélisme)
6. [Compilation & Accélération native](#6-compilation--accélération-native)
7. [I/O & Réseau asynchrone](#7-io--réseau-asynchrone)
8. [Patterns d'optimisation avancés](#8-patterns-doptimisation-avancés)
9. [Checklist de production](#9-checklist-de-production)

---

## 1. Comprendre le modèle d'exécution Python

### Le GIL (Global Interpreter Lock)

Le GIL est le verrou central de CPython. **Un seul thread Python s'exécute à la fois**, même sur un CPU multi-cœurs.

```
Thread A  ██████░░░░██████░░░░
Thread B  ░░░░██████░░░░██████
              ↑ alternance GIL
```

**Conséquences directes :**

| Cas d'usage | Bénéficie du multi-thread ? |
|---|---|
| Calcul CPU intensif (boucles, numpy pure) | ❌ Non — GIL bloque |
| I/O réseau, fichiers, base de données | ✅ Oui — GIL relâché pendant l'attente |
| Extensions C/Fortran (NumPy, Pandas) | ✅ Oui — relâchent le GIL |
| `multiprocessing` (plusieurs processus) | ✅ Oui — GIL par processus |

> **Python 3.13+** : le GIL est optionnellement désactivable (`python3.13t`).
> C'est encore expérimental, mais c'est l'avenir du free-threaded Python.

---

## 2. Mesurer avant d'optimiser

> *"Premature optimization is the root of all evil."* — D. Knuth

### 2.1 Chronométrage rapide

```python
import timeit

# Comparer deux approches
t1 = timeit.timeit('"-".join(str(n) for n in range(100))', number=10_000)
t2 = timeit.timeit('"-".join(map(str, range(100)))',       number=10_000)

print(f"Comprehension : {t1:.4f}s")
print(f"map()         : {t2:.4f}s")
```

En ligne de commande :
```bash
python -m timeit -n 10000 '"-".join(map(str, range(100)))'
```

### 2.2 Profiling CPU — `cProfile`

```python
import cProfile
import pstats

with cProfile.Profile() as pr:
    ma_fonction()

stats = pstats.Stats(pr)
stats.sort_stats('cumulative')
stats.print_stats(15)          # top 15 fonctions les plus coûteuses
```

Visualisation avec **SnakeViz** :
```bash
pip install snakeviz
python -m cProfile -o output.prof mon_script.py
snakeviz output.prof            # ouvre un flamegraph interactif dans le navigateur
```

### 2.3 Profiling ligne par ligne — `line_profiler`

```python
# pip install line-profiler
@profile                        # décorateur injecté par kernprof
def fonction_lente():
    total = 0
    for i in range(1_000_000):  # ← ligne coûteuse identifiée
        total += i ** 2
    return total
```

```bash
kernprof -l -v mon_script.py
```

### 2.4 Profiling mémoire — `memory_profiler`

```python
# pip install memory-profiler
from memory_profiler import profile

@profile
def charge_donnees():
    data = [i for i in range(1_000_000)]  # +~8 MB
    return data
```

```bash
python -m memory_profiler mon_script.py
```

### 2.5 Profiling asynchrone — `pyinstrument`

```bash
pip install pyinstrument
python -m pyinstrument mon_script.py   # profil visuel en arbre, supporte async/await
```

---

## 3. Gestion de la mémoire (RAM)

### 3.1 Comment Python gère la mémoire

```
Votre code Python
      ↓
  Objets Python (sur le tas)
      ↓
  Allocateur d'objets Python (pymalloc)
      ↓
  malloc / système d'exploitation
```

- Python utilise un **compteur de références** + un **ramasse-miettes cyclique** (`gc`)
- Chaque objet coûte au minimum **28 à 56 bytes** d'overhead (header de l'objet)

### 3.2 Mesurer la taille des objets

```python
import sys

sys.getsizeof([])           # 56 bytes (liste vide)
sys.getsizeof([1, 2, 3])    # 88 bytes (3 éléments)
sys.getsizeof("hello")      # 54 bytes

# Taille récursive (objet + contenu)
import tracemalloc

tracemalloc.start()
data = [list(range(1000)) for _ in range(1000)]
snapshot = tracemalloc.take_snapshot()
for stat in snapshot.statistics('lineno')[:5]:
    print(stat)
```

### 3.3 `__slots__` — économiser la RAM sur les classes

Sans `__slots__`, chaque instance possède un `__dict__` (~230 bytes d'overhead).

```python
# ❌ Standard : ~360 bytes par instance
class PointLourd:
    def __init__(self, x, y, z):
        self.x = x
        self.y = y
        self.z = z

# ✅ Avec __slots__ : ~72 bytes par instance (5x moins)
class PointLeger:
    __slots__ = ('x', 'y', 'z')
    def __init__(self, x, y, z):
        self.x = x
        self.y = y
        self.z = z

# Sur 1 million d'instances :
# PointLourd  → ~360 MB
# PointLeger  → ~72 MB
```

### 3.4 Générateurs vs Listes — traitement en flux

```python
# ❌ Charge TOUT en RAM
def lire_tout(fichier):
    return [ligne.strip() for ligne in open(fichier)]   # 500 MB si gros fichier

# ✅ Traite ligne par ligne, RAM quasi-nulle
def lire_flux(fichier):
    with open(fichier) as f:
        for ligne in f:
            yield ligne.strip()

# Pipeline de générateurs (zéro copie intermédiaire)
lignes    = lire_flux("big_log.txt")
filtrees  = (l for l in lignes if "ERROR" in l)
parsees   = (l.split("|") for l in filtrees)

for record in parsees:
    traiter(record)
```

### 3.5 `array` et `numpy` — données compactes

```python
import array
import numpy as np

# list Python : chaque int = objet ~28 bytes
liste_python = list(range(1_000_000))   # ~28 MB

# array : entiers natifs 8 bytes
arr = array.array('q', range(1_000_000))  # ~8 MB

# numpy : entiers 4 bytes + opérations vectorisées
np_arr = np.arange(1_000_000, dtype=np.int32)  # ~4 MB
```

### 3.6 `weakref` — références sans retenir en vie

```python
import weakref

class Cache:
    def __init__(self):
        # weakref.WeakValueDictionary : les valeurs sont libérées
        # automatiquement quand plus aucune référence forte n'existe
        self._cache = weakref.WeakValueDictionary()

    def get(self, key):
        return self._cache.get(key)

    def set(self, key, obj):
        self._cache[key] = obj          # ne bloque pas le GC
```

### 3.7 `functools.lru_cache` — mémoise intelligemment

```python
from functools import lru_cache

@lru_cache(maxsize=256)         # garde les 256 derniers résultats
def fibonacci(n):
    if n < 2: return n
    return fibonacci(n-1) + fibonacci(n-2)

fibonacci.cache_info()          # CacheInfo(hits=..., misses=..., maxsize=256, currsize=...)
fibonacci.cache_clear()         # libère la mémoire si nécessaire
```

---

## 4. Optimisation CPU & Calcul

### 4.1 Vectorisation avec NumPy (éviter les boucles Python)

```python
import numpy as np

data = np.random.rand(1_000_000)

# ❌ Boucle Python : ~500ms
total = 0
for x in data:
    total += x ** 2

# ✅ Vectorisé NumPy : ~2ms (250x plus rapide)
total = np.sum(data ** 2)

# ✅ Encore plus rapide avec einsum / ufunc
total = np.dot(data, data)
```

### 4.2 `map()` et compréhensions — éviter l'overhead des appels

```python
noms = ["alice", "bob", "charlie"]

# Plus rapide que la boucle for explicite
majuscules = list(map(str.upper, noms))

# Équivalent mais plus lisible
majuscules = [n.upper() for n in noms]

# Pour les filtres : filter() ou compréhension avec if
adultes = list(filter(lambda x: x >= 18, ages))
adultes = [x for x in ages if x >= 18]     # souvent plus rapide
```

### 4.3 Structures de données adaptées

```python
from collections import deque

# ❌ list comme file d'attente : O(n) pour pop(0)
file = []
file.append(item)
item = file.pop(0)      # déplace TOUS les éléments → lent

# ✅ deque : O(1) aux deux extrémités
file = deque()
file.append(item)
item = file.popleft()   # O(1)

# ❌ list pour tester l'appartenance : O(n)
if valeur in ma_liste:  # parcourt toute la liste

# ✅ set pour tester l'appartenance : O(1)
mon_set = set(ma_liste)
if valeur in mon_set:   # hash lookup

# ❌ Concaténation de strings : O(n²)
s = ""
for mot in mots:
    s += mot + " "

# ✅ join : O(n)
s = " ".join(mots)
```

### 4.4 Variables locales vs globales

```python
import math

# ❌ Accès global à chaque itération
def calcul_lent(data):
    return [math.sqrt(x) for x in data]

# ✅ Copie locale : lookup LEGB plus court
def calcul_rapide(data):
    sqrt = math.sqrt          # référence locale → plus rapide en boucle
    return [sqrt(x) for x in data]
```

### 4.5 `bisect` — recherche dichotomique dans une liste triée

```python
import bisect

triee = [1, 3, 5, 7, 9, 11, 13]

# O(log n) au lieu de O(n)
pos = bisect.bisect_left(triee, 7)      # → 3
bisect.insort(triee, 6)                 # insère en gardant l'ordre
```

---

## 5. Concurrence & Parallélisme

### 5.1 Vue d'ensemble — choisir le bon outil

```
                     VOTRE TÂCHE
                         │
           ┌─────────────┴──────────────┐
        I/O bound                  CPU bound
      (réseau, disque)          (calcul intensif)
           │                          │
    asyncio / threading          multiprocessing
    (GIL relâché pendant          (contourne le GIL
      l'attente I/O)              via sous-processus)
```

### 5.2 `threading` — I/O concurrente

```python
import threading
import requests

urls = ["https://example.com"] * 20

resultats = {}
verrou = threading.Lock()

def telecharger(url, index):
    r = requests.get(url, timeout=5)
    with verrou:
        resultats[index] = len(r.content)

threads = [threading.Thread(target=telecharger, args=(url, i))
           for i, url in enumerate(urls)]

for t in threads: t.start()
for t in threads: t.join()
```

### 5.3 `concurrent.futures` — API haut niveau (recommandée)

```python
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

# ── I/O bound : ThreadPoolExecutor ──────────────────────
def fetch(url):
    return requests.get(url).status_code

with ThreadPoolExecutor(max_workers=10) as pool:
    futures = {pool.submit(fetch, url): url for url in urls}
    for future in as_completed(futures):
        url = futures[future]
        print(f"{url} → {future.result()}")

# ── CPU bound : ProcessPoolExecutor ──────────────────────
def factoriser(n):
    # calcul lourd...
    return [i for i in range(2, n) if n % i == 0]

with ProcessPoolExecutor(max_workers=8) as pool:
    resultats = list(pool.map(factoriser, grands_nombres))
```

### 5.4 `multiprocessing` — parallélisme CPU réel

```python
import multiprocessing as mp
import numpy as np

def traiter_chunk(chunk):
    return np.sum(chunk ** 2)

if __name__ == "__main__":
    data = np.random.rand(10_000_000)
    n_workers = mp.cpu_count()                  # nombre de cœurs disponibles

    # Découper les données en chunks
    chunks = np.array_split(data, n_workers)

    with mp.Pool(processes=n_workers) as pool:
        resultats = pool.map(traiter_chunk, chunks)

    total = sum(resultats)
```

#### Mémoire partagée entre processus (Python 3.8+)

```python
from multiprocessing import shared_memory
import numpy as np

# Processus parent : crée la mémoire partagée
shm = shared_memory.SharedMemory(create=True, size=1_000_000 * 8)
tableau = np.ndarray((1_000_000,), dtype=np.float64, buffer=shm.buf)
tableau[:] = np.random.rand(1_000_000)

# Passer shm.name aux processus enfants pour qu'ils y accèdent
# sans copier les données (zéro-copy inter-processus)
```

### 5.5 `asyncio` — I/O asynchrone (un seul thread, zéro GIL)

```python
import asyncio
import aiohttp                          # pip install aiohttp

async def fetch(session, url):
    async with session.get(url) as r:
        return await r.text()

async def main(urls):
    async with aiohttp.ClientSession() as session:
        taches = [fetch(session, url) for url in urls]
        resultats = await asyncio.gather(*taches)   # toutes en parallèle
    return resultats

# Lancement
asyncio.run(main(urls))
```

#### Gestion de la charge avec un semaphore

```python
async def main(urls, max_concurrent=20):
    sem = asyncio.Semaphore(max_concurrent)     # max 20 requêtes simultanées

    async def fetch_limite(session, url):
        async with sem:
            return await fetch(session, url)

    async with aiohttp.ClientSession() as session:
        taches = [fetch_limite(session, url) for url in urls]
        return await asyncio.gather(*taches)
```

---

## 6. Compilation & Accélération native

### 6.1 Numba — JIT compilation pour le calcul numérique

```python
# pip install numba
from numba import njit, prange
import numpy as np

# ❌ Python pur : ~5 secondes
def mandelbrot_python(c, max_iter):
    z = 0
    for i in range(max_iter):
        if abs(z) > 2: return i
        z = z*z + c
    return max_iter

# ✅ Numba JIT : ~20ms (250x plus rapide, compile en C la 1ère fois)
@njit(parallel=True)
def mandelbrot_numba(c, max_iter):
    z = 0
    for i in range(max_iter):
        if abs(z) > 2: return i
        z = z*z + c
    return max_iter

# Parallélisation automatique avec prange
@njit(parallel=True)
def somme_parallele(arr):
    total = 0.0
    for i in prange(len(arr)):          # prange = parallel range
        total += arr[i]
    return total
```

### 6.2 Cython — écrire du C depuis du Python

```python
# fichier: calcul.pyx
def somme_carre(int n):
    cdef int i
    cdef long total = 0
    for i in range(n):
        total += i * i
    return total
```

```python
# setup.py
from setuptools import setup
from Cython.Build import cythonize

setup(ext_modules=cythonize("calcul.pyx"))
```

```bash
python setup.py build_ext --inplace
# → calcul.cpython-311-linux.so  (~10-100x plus rapide)
```

### 6.3 PyPy — interpréteur alternatif avec JIT intégré

PyPy est un remplacement drop-in de CPython pour les workloads CPU purs :

```bash
pypy3 mon_script.py      # souvent 5-20x plus rapide sur les boucles
```

Limitations : support partiel de certaines extensions C (NumPy ok, certaines libs non).

### 6.4 `ctypes` / `cffi` — appeler des bibliothèques C directement

```python
import ctypes

libm = ctypes.CDLL("libm.so.6")        # bibliothèque math C standard
libm.sqrt.restype = ctypes.c_double
libm.sqrt.argtypes = [ctypes.c_double]

print(libm.sqrt(2.0))                  # appel C natif, sans overhead Python
```

---

## 7. I/O & Réseau asynchrone

### 7.1 Lecture/écriture fichiers optimisée

```python
# ❌ Lecture ligne par ligne avec decode Python
with open("big.csv") as f:
    data = f.readlines()

# ✅ Lecture en chunks (contrôle la RAM)
CHUNK = 64 * 1024  # 64 KB
with open("big.bin", "rb") as f:
    while chunk := f.read(CHUNK):
        traiter(chunk)

# ✅ mmap — fichier mappé en mémoire (accès direct sans copie)
import mmap

with open("big.bin", "r+b") as f:
    with mmap.mmap(f.fileno(), 0) as mm:
        data = mm[1000:2000]            # accès direct à une plage d'octets
```

### 7.2 Base de données — connexions poolées

```python
# SQLAlchemy avec pool de connexions
from sqlalchemy import create_engine

engine = create_engine(
    "postgresql://user:pass@host/db",
    pool_size=10,           # connexions permanentes
    max_overflow=20,        # connexions supplémentaires si besoin
    pool_pre_ping=True,     # vérifie la connexion avant usage
)

# psycopg3 asyncio (PostgreSQL)
import asyncpg

pool = await asyncpg.create_pool(dsn, min_size=5, max_size=20)
async with pool.acquire() as conn:
    rows = await conn.fetch("SELECT * FROM users WHERE active = $1", True)
```

### 7.3 Redis comme cache distribué

```python
import redis
import json
from functools import wraps

r = redis.Redis(host='localhost', decode_responses=True)

def cache_redis(ttl=300):
    def decorator(f):
        @wraps(f)
        def wrapper(*args):
            key = f"{f.__name__}:{args}"
            cached = r.get(key)
            if cached:
                return json.loads(cached)
            result = f(*args)
            r.setex(key, ttl, json.dumps(result))
            return result
        return wrapper
    return decorator

@cache_redis(ttl=60)
def requete_couteuse(user_id):
    return db.query(f"SELECT * FROM users WHERE id={user_id}")
```

---

## 8. Patterns d'optimisation avancés

### 8.1 Objets immuables et `dataclasses` avec `slots`

```python
from dataclasses import dataclass

# Python 3.10+ : slots=True sur dataclass
@dataclass(slots=True, frozen=True)     # frozen = immuable + hashable
class Point:
    x: float
    y: float
    z: float

# ~5x moins de RAM qu'une classe standard
# hashable → utilisable comme clé de dict / dans un set
```

### 8.2 `__slots__` hérité et `__weakref__`

```python
class Base:
    __slots__ = ('_x',)

class Enfant(Base):
    __slots__ = ('_y', '__weakref__')   # ajouter __weakref__ si besoin de weakref
    def __init__(self, x, y):
        self._x = x
        self._y = y
```

### 8.3 Lazy evaluation avec `__getattr__`

```python
class Config:
    """Charge les données de config uniquement quand on y accède."""
    def __getattr__(self, name):
        valeur = charger_depuis_env_ou_fichier(name)
        object.__setattr__(self, name, valeur)      # met en cache
        return valeur

config = Config()
# config.DATABASE_URL n'est chargé qu'au premier accès
```

### 8.4 Pool d'objets — réutiliser plutôt qu'allouer

```python
from queue import Queue

class ObjectPool:
    def __init__(self, factory, size=10):
        self._pool = Queue(maxsize=size)
        for _ in range(size):
            self._pool.put(factory())

    def acquire(self):
        return self._pool.get(timeout=5)

    def release(self, obj):
        self._pool.put(obj)

# Usage typique : connexions DB, sessions HTTP, buffers
pool = ObjectPool(lambda: requests.Session(), size=20)
session = pool.acquire()
try:
    result = session.get(url)
finally:
    pool.release(session)
```

### 8.5 `memoryview` — zéro copie sur les buffers binaires

```python
data = bytearray(b"Hello, World! " * 1_000_000)

# ❌ Slice classique : COPIE les données
partie = data[1000:2000]            # alloue un nouveau buffer

# ✅ memoryview : AUCUNE copie
vue = memoryview(data)
partie = vue[1000:2000]             # pointe sur les données originales

# Très utile pour parser des formats binaires (images, réseau, fichiers)
with open("image.raw", "rb") as f:
    raw = f.read()
    vue = memoryview(raw)
    header = vue[:16]               # lit l'en-tête sans copier
    pixels = vue[16:]               # lit les pixels sans copier
```

---

## 9. Checklist de production

### Diagnostic rapide

```bash
# CPU profil global
python -m cProfile -s cumulative script.py | head -30

# Mémoire globale
python -m memory_profiler script.py

# Profil visuel (recommandé)
pyinstrument script.py
```

### Récapitulatif des choix

| Problème | Solution recommandée |
|---|---|
| Boucles Python lentes sur nombres | `numpy` vectorisation ou `numba @njit` |
| Trop de RAM sur de gros objets | `__slots__`, générateurs, `array` |
| I/O réseau concurrent | `asyncio` + `aiohttp` |
| CPU multi-cœurs | `ProcessPoolExecutor` ou `multiprocessing` |
| I/O + threads | `ThreadPoolExecutor` |
| Fonctions répétées à résultat stable | `functools.lru_cache` |
| Parsing binaire sans copie | `memoryview` |
| Accès répété à des fichiers | `mmap` |
| Code Python pur trop lent | `PyPy`, `Cython`, ou `ctypes` |
| Cache distribué | Redis + décorateur de cache |
| Recherche dans liste triée | `bisect` (O(log n)) |

### Anti-patterns à éviter absolument

```python
# ❌ Concaténation de strings en boucle
s = ""
for ligne in lignes:
    s += ligne          # O(n²) — réalloue à chaque fois

# ✅
s = "".join(lignes)

# ❌ Vérifier l'appartenance dans une liste
if x in ma_liste:       # O(n)

# ✅
if x in mon_set:        # O(1)

# ❌ Import dans une boucle
for i in range(1000):
    import json         # re-lookup inutile à chaque itération

# ✅ Toujours importer au niveau module

# ❌ Copie inutile de données avec slice
def traiter(data):
    moitie = data[:len(data)//2]    # copie

# ✅
def traiter(data):
    vue = memoryview(data)
    moitie = vue[:len(data)//2]     # zéro copie
```

---

## Ressources complémentaires

- [`tracemalloc`](https://docs.python.org/3/library/tracemalloc.html) — profiling mémoire standard library
- [`concurrent.futures`](https://docs.python.org/3/library/concurrent.futures.html) — API unifiée threads/processus
- [`asyncio`](https://docs.python.org/3/library/asyncio.html) — I/O asynchrone
- [Numba](https://numba.readthedocs.io/) — JIT pour calcul numérique
- [PyPy](https://www.pypy.org/) — interpréteur avec JIT intégré
- [PEP 703](https://peps.python.org/pep-0703/) — suppression du GIL (Python 3.13+)