#!/usr/bin/env python3
# coding:utf-8
import unittest
import sys
import os

def run_all():
    print("\033[94m[*] Lancement de la suite de tests complète...\033[0m\n")
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(__file__)
    suite = loader.discover(start_dir, pattern='test_*.py')

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    if result.wasSuccessful():
        print("\n\033[92m[+] Tous les tests ont réussi !\033[0m")
    else:
        print("\n\033[91m[!] Certains tests ont échoué.\033[0m")
        sys.exit(1)

if __name__ == '__main__':
    run_all()
