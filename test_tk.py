#!/usr/bin/env python3
# coding:utf-8

import tkinter as tk
class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_wigets()
    def create_wigets(self):
        self.mon_boutton = tk.Button(self)
        self.mon_boutton["text"] = "Cliquez ici"
        self.mon_boutton["command"] = self.dire_bonjour
        self.mon_boutton.pack()

    def dire_bonjour(self):
        print("Bonjour")

root = tk.Tk()
root.title("Mon Titre")
# La géométrie de la fenêtre
root.geometry("1080x720")
root.minsize(480,360)

#Le background
root.config(background="#d4d4d4")


#Ajouter des Wigets

#label = tk.Label(root, text="Mon Label", font=("Arial", 35),bg='#000000', fg='#f1f1f1')
#Ajouter le label à la fenêtre
#label.pack(side=tk.TOP)

#Faire un input
#entry = tk.Entry(root, bd=2)
#entry.pack(side=tk.TOP)

#Un boutton
#boutton = tk.Button(root, bd=2, text="Click me!", command=lambda: print("Click me!"))
#boutton.pack(side=tk.TOP)

application =  Application(master=root)

application.mainloop()