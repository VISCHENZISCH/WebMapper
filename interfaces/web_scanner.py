#!/usr/bin/env python3
# coding:utf-8
import random
import sys
import threading
import urllib
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup



class WebScanner:

    def __init__(self, url, proxy=None, user_agent="Mozilla/5.0 (X11; Linux i686; rv:68.0)\
     Gecko/20100101 Firefox/68.0"):
        if not url.endswith("/") and not url.endswith(".php") and not url.endswith(".html"):
            self.url = url + "/"
        else:
            self.url = url
        self.proxy = proxy
        self.user_agent = user_agent
        #self.browser = mechanize.Browser()
        self.session = requests.Session()
        self.link_list = []
        self.stopped = False

    def print_link_list(self):
        """
        Affiche la liste de liens ("crawlés") dans le Terminal
        :return:
        """
        for link in self.link_list:
            print(link)

    def get_page_source(self, page=None):
        """
        Obtient le code source d'une page web
        :param page: optionnel : la page recherchée, sinon utilise self.url
        :return: Le code source HTML de la page
        """
        if page is None:
            page = self.url
        page = page.strip()
        #self.browser.set_handle_robots(False)
        user_agent = {"User-agent": self.user_agent}
        #self.browser.addheaders = user_agent
        try:
            if self.proxy:
                #self.browser.set_proxies(self.proxy)
                res = self.session.get(page, headers=user_agent, proxies=self.proxy)
            else:
                res = self.session.get(page, headers=user_agent)

        except Exception as e:
            print("[-] Erreur pour la page : " + page + " " + str(e))
            return None
        return res.text

    def get_page_links(self, page=None):
        """
        Obtient les liens disponibles sur une page web (href), excluant les liens externes
        :param page: la page recherchée, sinon utilise self.url
        :return: une liste contenant les liens d'une page, ou une liste vide à défaut
        """
        link_list = []  # la liste de liens internes à "page"

        if page is None:
            page = self.url
        source = self.get_page_source(page)

        if source is not None:
            soup = BeautifulSoup(source, "html.parser")
            uparse = urlparse(page)
            for link in soup.find_all("a"):
                if not link.get("href") is None:
                    href = link.get("href")
                    if "#" in href:
                        href = href.split("#")[0]
                    new_link = urllib.parse.urljoin(page, href)
                    if uparse.hostname in new_link and new_link not in link_list:
                        link_list.append(new_link)
            return link_list
        else:
            return []

    def print_cookies(self):
        """
        Affiche les cookies de la session courante dans le Terminal
        :return:
        """
        for cookie in self.session.cookies:
            print(cookie)

    def get_cookies(self):
        """
        Retourne la liste des cookies de la session courante
        :return: La liste (dictionnaire) des cookies
        """
        return self.session.cookies

    def _do_crawl(self, queue, page=None):
        """
        Crawl (indexe) une page de manière récursive en arrière-plan
        :param page: la page recherchée, sinon utilise self.url
        :return:
        """
        try:
            page_links = self.get_page_links(page)
            for link in page_links:
                if self.stopped:
                    break
                if link not in self.link_list:
                    self.link_list.append(link)
                    # print("Lien ajouté à la liste : " + link)
                    queue.put(link)
                    self._do_crawl(queue, link)
        except KeyboardInterrupt:
            print("\nProgramme arrêté par l'utilisateur")
            sys.exit(1)
        except Exception as e:
            print("\nErreur : " + str(e))
            sys.exit(2)

    def _crawl_end_callback(self, crawl_thread, crawl_queue):

        """
        Tâche d'arrière-plan pour envoyer le message de fin de crawling
        :param crawl_thread: Le thread à observer
        :param crawl_queue: La queue à utiliser pour les communications
        :return:
        """

        crawl_thread.join()
        crawl_queue.put("END")

    def crawl(self, crawl_queue, page=None):
        """
        Le Crawl utilise des tâches en arrière-plan (pour l'interface graphique)
        :param crawl_queue: Du multiprocessing queue utilisé pour la communication
        :param page: -----------
        :return:
        """

        crawl_thread = threading.Thread(target=self._do_crawl, args=(crawl_queue, page))
        crawl_thread.start()
        thread2 = threading.Thread(target=self._crawl_end_callback, args=(crawl_thread, crawl_queue))
        thread2.start()

    #Recherche automatisée
    def check_sqli_form(self, page=None):
        """

        :param page:
        :return:
        """

        if page is None:
            page = self.url
        source = self.get_page_source(page)
        if source is not None:
            soup = BeautifulSoup(source, "html.parser")
            forms_list = soup.find_all("form")
            payload_ = "'" + random.choice("abcdefg")
            ret = ""

            for form in forms_list:
                form_action = form.get("action")
                form_method = form.get("method")
                target_url = urllib.parse.urljoin(page, form_action)


                input_lists = form.find_all("input")
                params_list = {}
                for input_ in input_lists:
                    input_name = input_.get("name")
                    input_type = input_.get("type")
                    input_value = input_.get("value")



                    if "?" + input_name not in target_url or "&" + input_type not in target_url:


                        if input_type == "text" or input_type == "password":
                            params_list[input_name] = payload_
                        elif input_value is not None:
                            params_list[input_name] = input_value
                        else:
                            params_list[input_name] = ""


                    if form_method.upper() == "GET":
                        res = self.session.get(target_url, params=params_list)


                    elif form_method.upper() == "POST":
                        res = self.session.post(target_url, data=params_list)

                    if "You have an error in your SQL syntax;" in res.text:

                        print("[!] INJECTION SQL DÉTECTÉE DANS FORM :"+ res.url + " (" + form_action + ")")
                        ret = ret + "[!] INJECTION SQL DÉTECTÉE DANS FORM :"+ res.url + " (" + form_action + ")\n"

            return ret
        else:
            return page

    #Injection SQL #Liens
    def check_sqli_link(self, page=None):
        """

        :param page: page demandée, on utilise l'URL si pas d'instance
        :return:
        """
        if page is None:
            page = self.url
        payload_ = "'" + random.choice("abcdefgehlk")
        page = page.replace("=", "=" + payload_)

        res = self.session.get(page)
        if "You have an error in your SQL syntax;" in res.text:

            print("[!] INJECTION SQL DÉTECTÉE DANS LIEN : " + res.url)
            return "[!] INJECTION SQL DÉTECTÉE DANS LIEN : " + res.url + "\n"
        else:
            return None


    def get_login_session(self, credentials, page=None):
        """

        :param credentials: un dictionnaire contenant toutes les valeurs POST
        :param page: page demandée, on utilise l'URL si pas d'instance
        :return: la réponse si connexion ou None
        """

        if page is None:
            page = self.url


        res = self.session.post(page, data=credentials)
        if res.status_code != 403: #"and You have logged in" in res.txt
            #print(res.text)
            return res
        else:
            return ""

    #XSS Formulaires
    def check_xss_form(self, page=None):
        """

        :param page:
        :return:
        """

        if page is None:
            page = self.url

        source = self.get_page_source(page)
        #print(source)
        soup = BeautifulSoup(source, "html.parser")
        forms_list = soup.find_all("form")
        payload_ = "<script>alert('Module test XSS');</script>"
        ret = ""

        for form in forms_list:
            form_action = form.get("action")
            form_method = form.get("method")
            print("form action : " + form_action)
            print("form method : " + form_method)
            target_url = urllib.parse.urljoin(page, form_action)
            params_list = {}
            input_lists = form.find_all("input")
            for input_ in input_lists:
                input_name = input_.get("name")
                input_type = input_.get("type")
                input_value = input_.get("value")
                print("input: " + input_name)
                print("type: " + input_type)

                #AD
                if "?" + input_name not in target_url or "&" + input_type not in target_url:

                    if input_type == "text" or input_type == "password":
                        params_list[input_name] = payload_
                    elif input_value is not None:
                        params_list[input_name] = input_value
                    else:
                        params_list[input_name] = ""



                if form_method.upper() == "GET":
                    res = self.session.get(target_url, params=params_list)


                elif form_method.upper() == "POST":
                    res = self.session.post(target_url, data=params_list)


                if payload_ in res.text:
                    print("[X] FAILLE XSS DÉTECTÉE DANS FORM : "+ res.url + " (" + form_action + ")")
                    ret = ret + "[X] FAILLE XSS DÉTECTÉE DANS FORM : "+ res.url + " (" + form_action + ")\n"
        return ret



    #XSS Liens
    def check_xss_link(self, page=None):
        """

        :param page: On utilise l'url si, pas d'instances
        :return:
        """
        if page is None:
            page = self.url
        payload_ = "<script>alert('Module test XSS');</script>"
        page = page.replace("=", "=" + payload_)

        res = self.session.get(page)

        if payload_ in res.text:
            print("[X] FAILLE XSS DÉTECTÉE ..." + res.url)
            return "XSS DÉTECTÉ DANS LIEN : " + res.url + "\n"
        else:
            return ""

# Recherche automatisée #
    def _do_check_vuln(self, queue, inks_list_):
        """
        _do_check_vuln (indexe) une page de manière récursive en arrière-plan
        :param page: la page recherchée, sinon utilise self.url
        :return:
        """
        try:
            for link in inks_list_:

                ck_xss_link = self.check_xss_link(link)
                if ck_xss_link != "":
                    queue.put(ck_xss_link)

                ck_xss_form = self.check_xss_form(link)
                if ck_xss_form != "":
                    queue.put(ck_xss_form)

                ck_sqli_link = self.check_sqli_link(link)
                if ck_sqli_link != "":
                    queue.put(ck_sqli_link)

                ck_sqli_form = self.check_sqli_form(link)
                if ck_sqli_form != "":
                    queue.put(ck_sqli_form)


        except KeyboardInterrupt:
            print("\nProgramme arrêté par l'utilisateur")
            sys.exit(1)
        except Exception as e:
            print("\nErreur : " + str(e))
            sys.exit(2)

    def _check_vuln_end_callback(self, check_thread, check_queue):

        """
        __check_vuln_end_callback
        Tâche d'arrière-plan pour envoyer le message de fin de crawling
        :param check_thread: Le thread à observer
        :param check_queue: La queue à utiliser pour les communications
        :return:
        """

        check_thread.join()
        check_queue.put("END")

    def check_vuln(self, check_queue, links_list_):
        """
        Le Check utilise des tâches en arrière-plan (pour l'interface graphique)
        :param check_queue: Du multiprocessing queue utilisé pour la communication
        :param page: -----------
        :return:
        """

        check_thread = threading.Thread(target=self._do_check_vuln, args=(check_queue, links_list_))
        check_thread.start()
        thread2 = threading.Thread(target=self._check_vuln_end_callback, args=(check_thread, check_queue))
        thread2.start()

