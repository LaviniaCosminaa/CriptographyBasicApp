import tkinter as tk
from tkinter import filedialog, ttk
from tkinter.ttk import Label

from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import binascii

input_filename = ''
output_filename = ''

# Generate a random initialization vector (IV) for CBC mode for AES encryption.
# iv = get_random_bytes(16)
iv = b'\xe8W\x8a\xe8\x11\x90\\Z\x9d\xed\xf1]i\xb2($'

# Generate RSA key pair
key_RSA = RSA.generate(2048)
# Get public and private keys
public_key_RSA = key_RSA.publickey()
private_key_RSA = key_RSA


def choose_input_file():
    global input_filename
    input_filename = filedialog.askopenfilename()
    print("Selected input file:", input_filename)


def choose_output_file():
    global output_filename
    output_filename = filedialog.askopenfilename()
    print("Selected output file:", output_filename)


def read_from_file():
    global input_filename
    with open(input_filename, "r+") as file:
        content = file.read()
        key, message = content.split("\n", 1)
        return key, message


def read_from_file_RSA():
    global input_filename
    with open(input_filename, "r+") as file:
        content = file.read()
        return content


def des_encrypt():
    key, message = read_from_file()

    # The secret key for DES encryption, which must be 8 bytes long.
    secret_key = key.encode('utf-8')
    if len(secret_key) != 8:
        with open(output_filename, "w") as f:
            f.write("Error: the key length is not valid for DES encryption.")

    # The message to be encrypted, which must be a multiple of 8 bytes long.
    message_to_encrypt = message.encode('utf-8')
    if len(message_to_encrypt) != 8:
        with open(output_filename, "w") as f:
            f.write("Error: the message length is not valid for DES encryption.")

    # Create a DES cipher object and encrypt the message
    cipher = DES.new(secret_key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(message_to_encrypt).hex()

    # Write to file
    with open(output_filename, "w") as f:
        f.write(ciphertext)


def des_decrypt():
    key, encrypted_message = read_from_file()

    # The secret key for DES decryption, which must be 8 bytes long.
    secret_key = key.encode('utf-8')
    if len(secret_key) != 8:
        with open(output_filename, "w") as f:
            f.write("Error: the key length is not valid for DES decryption.")

    message_to_decrypt = binascii.unhexlify(encrypted_message)

    # Create a DES cipher object and decrypt the message
    cipher = DES.new(secret_key, DES.MODE_ECB)
    decrypted = cipher.decrypt(message_to_decrypt).decode('utf-8')

    # Write to file
    with open(output_filename, "w") as f:
        f.write(decrypted)


def aes_encrypt():
    global iv
    key, message = read_from_file()

    # The secret key for AES encryption, which must be 16, 24, or 32 bytes long.
    secret_key = key.encode('utf-8')
    if len(secret_key) not in [16, 24, 32]:
        with open(output_filename, "w") as f:
            f.write("Error: the key length is not valid for AES encryption.")

    # The message to be encrypted, which must be a multiple of 16 bytes long.
    message_to_encrypt = message.encode('utf-8')
    # Pad the message to a multiple of 16 bytes using PKCS7 padding.
    padded_message = message_to_encrypt + (16 - len(message_to_encrypt) % 16) * chr(
        16 - len(message_to_encrypt) % 16).encode()
    if len(message_to_encrypt) % 16 != 0:
        with open(output_filename, "w") as f:
            f.write("Error: the message length is not valid for AES encryption.")

    # Create an AES cipher object in CBC mode with the specified secret key and IV.
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    # Encrypt the padded message using the AES cipher object and the specified IV.
    encrypted_message = cipher.encrypt(padded_message)
    # print("Initialization Vector: ", iv.hex())
    # print("Encrypted Message: ", encrypted_message.hex())

    # Write to file
    with open(output_filename, "w") as f:
        # f.write(iv.hex())
        # f.write("\n")
        f.write(encrypted_message.hex())


def aes_decrypt():
    global iv
    key, message = read_from_file()

    # The secret key for AES encryption, which must be 16, 24, or 32 bytes long.
    secret_key = key.encode('utf-8')
    if len(secret_key) not in [16, 24, 32]:
        with open(output_filename, "w") as f:
            f.write("Error: the key length is not valid for AES encryption.")

    # The message to be encrypted, which must be a multiple of 16 bytes long.
    message_to_decrypt = bytes.fromhex(message)
    if len(message_to_decrypt) % 16 != 0:
        with open(output_filename, "w") as f:
            f.write("Error: the message length is not valid for AES encryption.")

    # Create an AES cipher object in CBC mode with the specified secret key and IV.
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    # Decrypt the encrypted message using the AES cipher object and the specified IV.
    decrypted_message = cipher.decrypt(message_to_decrypt)
    # Remove the padding from the decrypted message using PKCS7 unpadding.
    unpadded_message = decrypted_message[:-decrypted_message[-1]]

    # Convert the decrypted message from bytes to string.
    decrypted = unpadded_message.decode('utf-8')

    # Write to file
    with open(output_filename, "w") as f:
        f.write(decrypted)


def rsa_encrypt():
    message = read_from_file_RSA()
    message_to_encrypt = message.encode('utf-8')

    # print(message_to_encrypt)

    cipher = PKCS1_OAEP.new(public_key_RSA)
    ciphertext = cipher.encrypt(message_to_encrypt)

    # Write to file
    with open(output_filename, "w") as f:
        f.write(ciphertext.hex())


def rsa_decrypt():
    message_to_decrypt = read_from_file_RSA()
    message_to_decrypt = bytes.fromhex(message_to_decrypt)
    print(message_to_decrypt)

    cipher = PKCS1_OAEP.new(private_key_RSA)
    plaintext = cipher.decrypt(message_to_decrypt)

    # Write to file
    with open(output_filename, "w") as f:
        f.write(plaintext.decode('utf-8'))


def execute_encrypt_function(selected_option):
    if selected_option == "DES":
        des_encrypt()
    elif selected_option == "AES":
        aes_encrypt()
    elif selected_option == "RSA":
        rsa_encrypt()


def execute_decrypt_function(selected_option):
    if selected_option == "DES":
        des_decrypt()
    elif selected_option == "AES":
        aes_decrypt()
    elif selected_option == "RSA":
        rsa_decrypt()


NORM_FONT = ("Helvetica", 10)
def popupmsg():
    popup = tk.Tk()
    popup.wm_title("Instructions")
    instr = "1. The files must have a specific format! \n" \
            "DES & AES files will have 2 lines: key, message. " \
            "\nRSA will have just one: message.\n\n" \
            "2. Be careful and choose the good algorithm, files and action."
    label = ttk.Label(popup, text= instr, font=NORM_FONT)
    label.pack(side="top", fill="x", pady=10)
    B1 = ttk.Button(popup, text="Okay", command=popup.destroy)
    B1.pack()
    popup.mainloop()


class App(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.label1 = None
        self.label2 = None
        self.label3 = None
        self.function1_button = None  # DES
        self.function2_button = None  # AES
        self.function3_button = None  # RSA
        self.dropdown = None
        self.option_var = None
        self.options = None
        self.file_button = None
        self.file_out_button = None
        self.encrypt_button = None
        self.decrypt_button = None
        self.instructions_button = None
        self.grid(pady=70, padx=60, sticky='nw')
        self.create_widgets()

    def create_widgets(self):
        # Instructions button
        self.instructions_button = tk.Button(self, text="Instructions", command=lambda: popupmsg())
        self.instructions_button.grid(row=10, column=4, sticky='e')

        # FILES
        self.label1 = tk.Label(self, text="Please choose the files:")
        self.label1.grid(row=0, column=0, sticky='w')
        # Input file chooser button
        self.file_button = tk.Button(self, text="Choose input file", command=choose_input_file)
        self.file_button.grid(row=1, column=0, sticky='w')
        # Output file chooser button
        self.file_out_button = tk.Button(self, text="Choose output file", command=choose_output_file)
        self.file_out_button.grid(row=1, column=3, sticky='w')

        # ALGORITHM
        self.label2 = tk.Label(self, text="Please choose the algorithm:")
        self.label2.grid(row=2, column=0, sticky='w')
        # Dropdown table
        self.options = ["DES", "AES", "RSA"]
        self.option_var = tk.StringVar(self)
        self.option_var.set(self.options[0])
        self.dropdown = tk.OptionMenu(self, self.option_var, *self.options)
        self.dropdown.grid(row=3, column=0, sticky='w')

        # ACTION
        self.label3 = tk.Label(self, text="Please choose the action:")
        self.label3.grid(row=4, column=0, sticky='w')
        # Encryption button
        self.encrypt_button = tk.Button(self, text="Encrypt", command=lambda: execute_encrypt_function(self.option_var.get()))
        self.encrypt_button.grid(row=5, column=0, sticky='w')
        # Decryption button
        self.decrypt_button = tk.Button(self, text="Decrypt", command=lambda: execute_decrypt_function(self.option_var.get()))
        self.decrypt_button.grid(row=5, column=3, sticky='w')

