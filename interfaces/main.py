#!/usr/bin/env python3
# coding:utf-8


import web_scanner

#Métasploitable
ws = web_scanner.WebScanner("http://10.252.193.120")
ws.check_xss_link("http://10.252.193.120/mutillidae/index.php?page=dns-lookup.php")


#--- À mettre dans les tests ----
#Automatiser les la connexion
#session = ws.get_login_session({"username": "admin", "password": "password", "Login": "Login"}, "http://10.252.193.120/dvwa/login.php")

#if session is not None:

    #ws.check_sqli_form("http://10.252.193.120/mutillidae/index.php?page=login.php")
    #ws.print_cookies()



