from tkinter import *
from tkinter import ttk 
import tkinter as tk
root = Tk()
root.title('asd')

#---------------------------------------------------------------

#input text
inputM = Label(root,text="Enter the text:")
inputM.pack()
text = ttk.Entry(root, width=30)
text.pack()

#---------------------------------------------------------------

#input First kay
inputFirstKay = Label(root,text="Enter the first kay (an integer):")
inputFirstKay.pack()
kay1 = ttk.Entry(root, width=40)
kay1.pack()

#---------------------------------------------------------------

#input second kay
inputsecondKay = Label(root,text="Enter the second kay (an integer coprime with 26):")
inputsecondKay.pack()
kay2 = ttk.Entry(root, width=40)
kay2.pack()

#---------------------------------------------------------------

#select Encryption or Decryption
note = Label(root,text="* Note: You need a second key when choosing Affine Cipher", foreground="red")
note.pack()

#---------------------------------------------------------------

#select Encryption or Decryption
selectop = Label(root,text="What do you want?")
selectop.pack()
encryption = ttk.Radiobutton(root, text='Encryption')
encryption.pack()
decryption = ttk.Radiobutton(root, text='Decryption')
decryption.pack()

#---------------------------------------------------------------

#valu of Radiobutton Encryption and Decryption
rbvalu1 = StringVar()
encryption.config(variable =rbvalu1, value ='encryption')
decryption.config(variable =rbvalu1, value ='decryption')

#---------------------------------------------------------------

#select Encryption or Decryption
selectType = Label(root,text="What is the type of encryption?")
selectType.pack()
CaesarCipher = ttk.Radiobutton(root, text='Caesar Cipher')
CaesarCipher.pack()
AffineCipher = ttk.Radiobutton(root, text='Affine Cipher')
AffineCipher.pack()

#---------------------------------------------------------------

#valu of Radiobutton Caesar Cipher and Affine Cipher
rbvalu2 = StringVar()
CaesarCipher.config(variable =rbvalu2, value ='CaesarCipher')
AffineCipher.config(variable =rbvalu2, value ='AffineCipher')



def buClick():
    #check int num or not
    def check_int(input_str):
        try:
            num = int(input_str)
            return True, num
        except ValueError:
            if input_str.lstrip('-').lstrip('+').isdigit():
                return True, int(input_str)
            else:
                return False, None
            
    # caesar_cipher
    def caesar_cipher(text, key):
        resultCaesarCipher = ""

        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char_code = ord(char)
                shifted_code = (char_code - ord('A' if is_upper else 'a') + key) % 26
                encrypted_char = chr(shifted_code + ord('A' if is_upper else 'a'))
                resultCaesarCipher += encrypted_char
            else:
                resultCaesarCipher += char

        return resultCaesarCipher
    
    #---------------------------------------------------------------

    # decrypt_caesar_cipher
    def decrypt_caesar_cipher(encrypted_text, key):
        return caesar_cipher(encrypted_text, -key)
    
    #---------------------------------------------------------------
    
    #check mod_inverse
    def mod_inverse(a, m):
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None
    
    #---------------------------------------------------------------

    #encrypt affine_cipher
    def affine_cipher_encrypt(plaintext, a, b):
        result = ""
        m = 26

        for char in plaintext:
            if char.isalpha():
                is_upper = char.isupper()
                char_code = ord(char) - ord('A' if is_upper else 'a')
                encrypted_code = (a * char_code + b) % m
                encrypted_char = chr(encrypted_code + ord('A' if is_upper else 'a'))
                result += encrypted_char
            else:
                result += char

        return result
    
    #---------------------------------------------------------------
    
    # decrypt affine_cipher
    def affine_cipher_decrypt(ciphertext, a, b):
        result = ""
        m = 26

        a_inv = mod_inverse(a, m)

        if a_inv is not None:
            for char in ciphertext:
                if char.isalpha():
                    is_upper = char.isupper()
                    char_code = ord(char) - ord('A' if is_upper else 'a')
                    decrypted_code = (a_inv * (char_code - b)) % m
                    decrypted_char = chr(decrypted_code + ord('A' if is_upper else 'a'))
                    result += decrypted_char
                else:
                    result += char
        else:
            print("Error: Modular inverse does not exist for the given key.")
            result = None

        return result
    
    #---------------------------------------------------------------

    is_integer1, result = check_int(kay1.get())
    is_integer2, result = check_int(kay2.get())
    if is_integer1 and is_integer2:

        #encryption
        if(rbvalu1.get() == 'encryption'):

            #encrypt CaesarCipher
            if(rbvalu2.get() == 'CaesarCipher'):
                encryptedText = caesar_cipher(text.get(), int(kay1.get()))
                result = Label(root,text= encryptedText)
                result.pack()

            #encrypt AffineCipher
            else:
                encryptedText = affine_cipher_encrypt(text.get(), int(kay2.get()), int(kay1.get()))
                resolt = Label(root,text= encryptedText)
                resolt.pack()

        #decryption
        else:

            #decrypt CaesarCipher
            if(rbvalu2.get() == 'CaesarCipher'):
                plaintext = decrypt_caesar_cipher(text.get(), int(kay1.get()))
                result = Label(root,text= plaintext)
                result.pack()

            #decrypt AffineCipher
            else:
                encryptedText = affine_cipher_decrypt(text.get(), int(kay2.get()), int(kay1.get()))
                resolt = Label(root,text= encryptedText)
                resolt.pack()
    else:
        resolt = Label(root,text="Please Enter integer number",foreground="red")
        resolt.pack()

#start buttom            
but = ttk.Button(root, text="start", command=buClick)
but.pack()


root.mainloop()