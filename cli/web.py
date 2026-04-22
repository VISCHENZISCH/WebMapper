#!/usr/bin/env python3
# coding:utf-8
import sys
import urllib

import mechanize
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class WebCrawler:
    def __init__(self, url, proxy=None, user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"):
        if url.endswith("/"):
            self.url = url.rstrip("/")
        else:
            self.url = url
        self.proxy = proxy
        self.user_agent = user_agent
        self.browser = mechanize.Browser()
        self.stopped = False
        self.link_list = []

    def print_link_list(self):
        """
            Afficher la liste des liens dans le terminal
            :return:
        """
        for link in self.link_list:
            print(link)

    def get_page_source(self, page=None):
        """
        Avoir le code source de la page
        :param page: optionnel : lorsqu'une page demandée, si non définie, l'URL de l'instance par défaut est utilisée
        :return: HTML code source de la page
        """
        if page is None:
            page = self.url
        self.browser.set_handle_robots(False)
        user_agent = [("User-agent", self.user_agent)]
        self.browser.addheaders = user_agent
        if self.proxy:
            self.browser.set_proxies(self.proxy)
        page = page.strip()
        try:
            res = self.browser.open(page)
        except Exception as e:
            print("Erreur pour la page : " + page + str(e))
            return None
        return res

    def get_page_links(self, page=None):
        """
        Récupérer les liens disponibles sur la page
        :param page: page demandée, si non définie, l'URL de l'instance par défaut est utilisée
        :return: la liste contenant les liens disponibles sur la page ou une liste vide
        """
        link_list = []
        if page is None:
            page = self.url
        source = self.get_page_source(page)
        if source is not None:
            soup = BeautifulSoup(source, "html.parser")
            uparse = urlparse(page)
            for link in soup.find_all('a'):
                if not link.get("href") is None:
                    href = link.get("href")
                    if '#' in href:
                        href = href.split('#')[0]
                    new_link = urllib.parse.urljoin(page, href)
                    if uparse.hostname in new_link and new_link not in link_list:
                        link_list.append(new_link)

            return link_list
        else:
            return []


    def print_cookies(self):
        """
        Afficher les cookies depuis le navigateur
        :return: la liste de tous les cookies
        """
        cookies_list = []
        for cookie in self.browser.cookiejar:
            cookies_list.append(cookie)
        return cookies_list

    def get_cookies(self):
        """
        Renvoie tous les cookies depuis le navigateur
        :return: une liste de tous les cookies
        """
        cookies_list = []
        for cookie in self.browser.cookiejar:
            cookies_list.append(cookie)
        return cookies_list

    def crawl(self, page=None):
        """
        Explorer une page récursivement, ajouter les liens à la liste d'URLs
        :param page: page demandée, si non définie, l'URL de l'instance par défaut est utilisée
        :return:
        """

        try:
            page_links = self.get_page_links(page)
            for link in page_links:
                if self.stopped:
                    break
                if link not in self.link_list:
                    self.link_list.append(link)
                    print("[+] Lien ajouté à la liste : " + link)
                    self.crawl(link)
        except KeyboardInterrupt:
            print("\n[!] Programme interrompu par l'utilisateur.")
            sys.exit(1)
        except Exception as e:
            print("Erreur pour la page : " + page + str(e))
            sys.exit(1)