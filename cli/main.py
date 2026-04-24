#!/usr/bin/env python3
# coding:utf-8

import sys
import web_scanner

def main():
    if len(sys.argv) < 2:
        print("[!]Utilisation: python3 main.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    print(f"[*] Début du scan sur : {url}")

    ws = web_scanner.WebScanner(url)
    ws.crawl()

if __name__ == "__main__":
    main()