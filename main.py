import tkinter as tk

from app import App

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Cryptography app")
    # root.configure(bg='#ebb494')
    app = App(master=root)
    app.mainloop()

