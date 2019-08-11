#!/opt/rh/rh-python36/root/usr/bin/python

import tkinter
import tkinter.messagebox
import tkinter.filedialog
import tkinter.simpledialog
import tkinter.scrolledtext
import tkinter.ttk
from ARIA import *
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cast6ecb
import argparse
import sys
import os
import time
import getpass
import random
import string
import base64
import datetime

sProgramName = "AAZEHI"
sProgramVersion = "v1"

def createFileHeader(sProgramName, iAlgorithmID, iNonce, sOriginalFileExtension, iOriginalFileLength):
    sFileHeader = b""
    sErrorMessage = ""
    
    if len(sProgramName) != 8 or not set(sProgramName).issubset(set(string.printable)):
        raise ValueError("'{0}' is not a valid program name".format(sProgramName))

    if iAlgorithmID < 1 or iAlgorithmID > 3:
        raise NotImplementedError("'{0}' algorithm is not implemented".format(sAlgorithmName))
    
    if iNonce <= 0:
        raise ValueError("'{0}' is not a valid Nonce value".format(iNonce))
    
    if len(sOriginalFileExtension) > 8 or not set(sOriginalFileExtension).issubset(set(string.printable)):
            raise ValueError("'{0}' is not a valid file extension".format(sOriginalFileExtension))    
    
    if iOriginalFileLength <= 0 and iOriginalFileLength > (pow(2, 63) - 1 - 2):
        raise ValueError("'{0}' is not a valid file length".format(iOriginalFilLength))
    
    sFileHeader = sFileHeader + bytes(sProgramName, 'ascii')
    sFileHeader = sFileHeader + iAlgorithmID.to_bytes(8, "big")
    sFileHeader = sFileHeader + iNonce.to_bytes(8, "big")
    sFileHeader = sFileHeader + int(0).to_bytes(8 - len(sOriginalFileExtension), "big") + bytes(sOriginalFileExtension, 'ascii')
    sFileHeader = sFileHeader + iOriginalFileLength.to_bytes(8, "big")
    
    return sFileHeader


def decryptFile(sFileName, sDestinationFileName, sPassword, sPrivateKeyFileName, sPassphrase, bKeepOriginalFileExtension):
    bStatus = True
    
    try:
        fdNull = os.open("/dev/null", os.O_WRONLY)
        fdStOut = os.dup(1)    
        sTargetFileName = ""
        fdUnencryptedFile = None
        fdEncryptedFile = os.open(sFileName, os.O_RDONLY)
        
        #Read Header
        sEncryptionProgramID = str(os.read(fdEncryptedFile, 8), 'ascii')
        iAlgorithmID = int.from_bytes(os.read(fdEncryptedFile, 8), "big")
        iOriginalNonce = int.from_bytes(os.read(fdEncryptedFile, 8), "big")
        sOriginalFileExtension = str(os.read(fdEncryptedFile, 8), 'ascii').replace(chr(0), '')
        iOriginalFileLength = int.from_bytes(os.read(fdEncryptedFile, 8), "big")
        
        if sDestinationFileName == "":
            for i in range(0, 8):
                sTargetFileName = sTargetFileName + random.choice(string.digits + string.ascii_letters)
            sTargetFileName = sTargetFileName + "." + sOriginalFileExtension
            fdUnencryptedFile = os.open(sTargetFileName, os.O_APPEND|os.O_CREAT|os.O_RDWR, mode=0o0644)
        else:
            if bool(bKeepOriginalFileExtension):
                sTargetFileName = sDestinationFileName + "." + sOriginalFileExtension
            else:
                sTargetFileName = sDestinationFileName
                
            if os.path.exists(sTargetFileName):
                os.remove(sTargetFileName)
            
            fdUnencryptedFile = os.open(sTargetFileName, os.O_APPEND|os.O_CREAT|os.O_RDWR, mode=0o0644)
        
        if sProgramName + sProgramVersion != sEncryptionProgramID:
            raise ValueError("'{0}' seems not to be encrypted with {1}".format(sFileName, sProgramName))
            
        if iAlgorithmID == 1: #ARIA256CTR
            for pos in range(0, iOriginalFileLength // 16 + 1):
                os.dup2(fdNull, 1)
                
                sEncryptedChunk = os.read(fdEncryptedFile, 16)
                iEncryptedNonceAndCounter = ARIA_encryption( 
                    int.from_bytes(iOriginalNonce.to_bytes(8, "big") + pos.to_bytes(8, "big"), "big"), 
                    int.from_bytes(sPassword.encode(), "big"), 
                    256
                )
                sXoredEncryptedChunkAndEncryptedNonceAndCounter = xorStrings(
                    iEncryptedNonceAndCounter.to_bytes(16, "big"), 
                    sEncryptedChunk.ljust(16, int(0).to_bytes(1, "big"))
                )
                
                os.dup2(fdStOut, 1)
                
                if (pos + 1) * 16 < iOriginalFileLength:
                    os.write(fdUnencryptedFile, sXoredEncryptedChunkAndEncryptedNonceAndCounter)
                else:
                    os.write(fdUnencryptedFile, sXoredEncryptedChunkAndEncryptedNonceAndCounter[:iOriginalFileLength - pos * 16 ])
                
                print("Decyphering: {0}%".format(str((pos+1)*100//(iOriginalFileLength // 16 + 1)).rjust(3,' ')), end="\r")
                
        elif iAlgorithmID == 2: #CAST256CTR
            for pos in range(0, iOriginalFileLength // 16 + 1):
                sEncryptedChunk = os.read(fdEncryptedFile, 16)
                
                sEncryptedNonceAndCounter = cast6ecb.encrypt( 
                    iOriginalNonce.to_bytes(8, "big") + pos.to_bytes(8, "big"), 
                    sPassword.encode()
                )
                
                sXoredEncryptedChunkAndEncryptedNonceAndCounter = xorStrings(
                    sEncryptedNonceAndCounter, 
                    sEncryptedChunk.ljust(16, int(0).to_bytes(1, "big"))
                )
                
                if (pos + 1) * 16 < iOriginalFileLength:
                    os.write(fdUnencryptedFile, sXoredEncryptedChunkAndEncryptedNonceAndCounter)
                else:
                    os.write(fdUnencryptedFile, sXoredEncryptedChunkAndEncryptedNonceAndCounter[:iOriginalFileLength - pos * 16 ])      
                print("Decyphering: {0}%".format(str((pos+1)*100//(iOriginalFileLength // 16 + 1)).rjust(3,' ')), end="\r")
        
        elif iAlgorithmID == 3: #RSA and AES128CFB
            fdPrivateKey = None
            fdPrivateKey = os.open(sPrivateKeyFileName, os.O_RDONLY)
            sPrivKeyData = os.read(fdPrivateKey, os.path.getsize(sPrivateKeyFileName))
            iEncryptedSessionKeyLength = 0
        
            if iOriginalFileLength % 16 != 0:
                part = 1
            else:
                part = 0
            
            iEncryptedSessionKeyLength = 0
            iEncryptedSessionKeyLength = os.path.getsize(sFileName) - (16 * (iOriginalFileLength // 16 + part )) - 40 #los 40 salen del fileheader original
            
            rsaPrivateKey = serialization.load_pem_private_key(
                sPrivKeyData,
                sPassphrase.encode(),
                backend=default_backend()
            )
            
            sEncryptedSessionKey = os.read(fdEncryptedFile, iEncryptedSessionKeyLength)
            
            sSessionKey = rsaPrivateKey.decrypt(
                sEncryptedSessionKey,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            for pos in range(0, iOriginalFileLength // 16 + 1):
                aesCipher = AES.new(sSessionKey, mode=AES.MODE_CTR, nonce=iOriginalNonce.to_bytes(8, "big"))
                
                sEncryptedChunk = os.read(fdEncryptedFile, 16)
                sDecryptedChunk = aesCipher.decrypt(sEncryptedChunk)
                
                if (pos + 1) * 16 < iOriginalFileLength:
                    os.write(fdUnencryptedFile, sDecryptedChunk)
                else:
                    os.write(fdUnencryptedFile, sDecryptedChunk[:iOriginalFileLength - pos * 16 ])      
                print("Decyphering: {0}%".format(str((pos+1)*100//(iOriginalFileLength // 16 + 1)).rjust(3,' ')), end="\r")
        
                aesCipher = None
            
        print("")
        if len(sTargetFileName) > 0:
            print("Unencrypted data was saved in '{0}'".format(sTargetFileName))                 
    except Exception as e:
        bStatus = False
        print(e.with_traceback)
    
    return bStatus

def encrypt(iAlgorithm, sSourceFile, sTargetFile, sPassword, sPublicKey):
    bStatus = True
    
    try:
        iNonce = generateNonce(8)
    
        iSourceFileSize = os.path.getsize(sSourceFile)
    
        sSourceFileName, sSourceFileExtension = os.path.splitext(sSourceFile)
            
        sFileHeader = createFileHeader(
            sProgramName + sProgramVersion, 
            iAlgorithm, 
            iNonce, 
            sSourceFileExtension.replace(".",""), 
            iSourceFileSize
        )
        
        fdSourceFile = os.open(sSourceFile, os.O_RDONLY)
        fdNull = os.open("/dev/null", os.O_WRONLY)
        fdStOut = os.dup(1)
        
        if os.path.exists(sTargetFile):
            os.remove(sTargetFile)
        fdTargetFile = os.open(sTargetFile, os.O_APPEND|os.O_CREAT|os.O_RDWR, 0o664)
        
        os.write(fdTargetFile, sFileHeader)
        
        if iAlgorithm == 1:
            for pos in range(0, iSourceFileSize // 16 + 1):
                os.dup2(fdNull, 1)
                
                chunk = os.read(fdSourceFile, 16)
                iEncryptedNonceAndCounter = ARIA_encryption(
                    int.from_bytes(iNonce.to_bytes(8, "big") + pos.to_bytes(8, "big"), "big"), 
                    int.from_bytes(sPassword.encode(), "big"), 
                    256
                )
                
                sXoredChunkAndEncryptedNonceAndCounter = xorStrings(
                    chunk.ljust(16, int(0).to_bytes(1, "big")), 
                    iEncryptedNonceAndCounter.to_bytes(16, "big")
                )
                
                os.write(fdTargetFile, sXoredChunkAndEncryptedNonceAndCounter)
        
                os.dup2(fdStOut, 1)
                print("Encrypting: {0}%".format(str((pos+1)*100//(iSourceFileSize // 16 + 1)).rjust(3,' ')), end="\r")
                
        elif iAlgorithm == 2:
            for pos in range(0, iSourceFileSize // 16 + 1):
                chunk = os.read(fdSourceFile, 16)
                
                iEncryptedNonceAndCounter = cast6ecb.encrypt(
                    iNonce.to_bytes(8, "big") + pos.to_bytes(8, "big"), 
                    sPassword.encode()
                )
                
                sXoredChunkAndEncryptedNonceAndCounter = xorStrings(
                    chunk.ljust(16, int(0).to_bytes(1, "big")), 
                    iEncryptedNonceAndCounter
                )
                
                os.write(fdTargetFile, sXoredChunkAndEncryptedNonceAndCounter)
        
                print("Encrypting: {0}%".format(str((pos+1)*100//(iSourceFileSize // 16 + 1)).rjust(3,' '), end="\r")) 
                
        elif iAlgorithm == 3:
            rsaPublicKey = None
            cert = None
            sPublicKeyFileExtension = os.path.splitext(sPublicKey)[1]
            sEncryptedSessionKey = ""
            fdPublickKey = None
            
            fdPublicKey = os.open(sPublicKey, os.O_RDONLY)
            sPublicKeyData = os.read(fdPublicKey, os.path.getsize(sPublicKey))
            
            if sPublicKeyFileExtension == ".pem":
                rsaPublicKey = serialization.load_pem_public_key(
                    sPublicKeyData, 
                    backend=default_backend()
                )
                
            else:
                cert = x509.load_pem_x509_certificate(
                    sPublicKeyData,
                    backend=default_backend()
                )
                
            sSessionKey = random.getrandbits(128).to_bytes(16, "big")
            
            if sPublicKeyFileExtension == ".pem":
                sEncryptedSessionKey = rsaPublicKey.encrypt(
                    sSessionKey,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )                                           
                )
            else:
                sEncryptedSessionKey = cert.public_key().encrypt(
                    sSessionKey,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )                                           
                )                
            
            os.write(fdTargetFile, sEncryptedSessionKey)
            for pos in range(0, iSourceFileSize // 16 + 1):
                aesCipher = AES.new(sSessionKey, mode=AES.MODE_CTR, nonce=iNonce.to_bytes(8, "big"))
        
                chunk = os.read(fdSourceFile, 16)
                sEncryptedChunk = ""
                sEncryptedChunk = aesCipher.encrypt(chunk.ljust(16, int(0).to_bytes(1, "big")))
                os.write(fdTargetFile, sEncryptedChunk)
        
                aesCipher = None
        
                print("Encrypting: {0}%".format(str((pos+1)*100//(iSourceFileSize // 16 + 1)).rjust(3,' ')), end="\r") 
        print("")
        
    except Exception as e:
        bStatus = False
    
    return bStatus

def generateNonce(iLength):
    return random.getrandbits(iLength)

def xorStrings(str1, str2):
    xoredString = b""
    
    if len(str1) != len(str2):
        raise ValueError("Supplied strings are not suitable for being xored")
    
    for i in range(0, len(str1)):
        xoredString = xoredString + int(str1[i] ^ str2[i]).to_bytes(1, "big")
    
    return xoredString

def generateKeys(sPrivateKeyFileName, sPublicKeyFileName, iKeySize, sPassphrase, bCreateCertificate=False, sCommonName=""):
    bStatus = True
    
    try:
        key = rsa.generate_private_key(65537, iKeySize, backend=default_backend())
        
        sPrivateKeyData = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(sPassphrase.encode())
        )
        
        sPublicKeyData = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        if bCreateCertificate: 
            subject = issuer = x509.Name([
                #x509.NameAttribute(NameOID.COUNTRY_NAME, u"SV"),
                #x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"San Salvador"),
                #x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Salvador"),
                #x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"None"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"" + sCommonName),
            ])
            print(5)
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365) #1 años
            ).sign(key, hashes.SHA256(), default_backend())
            
            sCertificateFileName = os.path.splitext(sPublicKeyFileName)[0] + ".crt"
            if(os.path.exists(sCertificateFileName)):
                os.remove(sCertificateFileName)
            fdCertificate = os.open(sCertificateFileName, os.O_APPEND|os.O_CREAT|os.O_RDWR, 0o0644)
            
            os.write(fdCertificate, cert.public_bytes(encoding=serialization.Encoding.PEM))
            
            os.close(fdCertificate)
            
        if os.path.exists(sPrivateKeyFileName):
            os.remove(sPrivateKeyFileName)
            
        if os.path.exists(sPublicKeyFileName):
            os.remove(sPublicKeyFileName)
            
        fdPrivateKey = os.open(sPrivateKeyFileName, os.O_APPEND|os.O_CREAT|os.O_RDWR, 0o0644)
        fdPublicKey = os.open(sPublicKeyFileName, os.O_APPEND|os.O_CREAT|os.O_RDWR, 0o0644)
                
        os.write(fdPrivateKey, sPrivateKeyData)
        os.write(fdPublicKey, sPublicKeyData)
                
        os.close(fdPrivateKey)
        os.close(fdPublicKey)        
    except Exception as e:
        print(e)
        bStatus = False
        
    return bStatus

def checkIfPassphraseIsRequired(sPrivateKeyFileName):
    bPassphraseIsRequired = False
    try:
        fdPrivateKey = os.open(sPrivateKeyFileName, os.O_RDONLY)
        sPrivateKeyData = os.read(fdPrivateKey, os.path.getsize(sPrivateKeyFileName))
        os.close(fdPrivateKey)
        RSA.importKey(sPrivateKeyData)
        
    except Exception as e:
        bPassphraseIsRequired = True
        
    return bPassphraseIsRequired

def signFile(sFileName, sPrivateKeyFileName, sSignatureFileName, sPassphrase):
    bStatus = True
    
    try:
        fdFileToSign = None
        fdPrivateKey = None
        fdSignature = None
        rsaPrivateKey = None
        
        fdFileToSign = os.open(sFileName, os.O_RDONLY)
        fdPrivateKey = os.open(sPrivateKeyFileName, os.O_RDONLY)
        
        if os.path.exists(sSignatureFileName):
            os.remove(sSignatureFileName)
        
        fdSignature = os.open(sSignatureFileName, os.O_APPEND|os.O_CREAT|os.O_RDWR, 0o0644)
        
        sFileToSignContent = os.read(fdFileToSign, os.path.getsize(sFileName))
        os.close(fdFileToSign)
        sPrivateKeyData = os.read(fdPrivateKey, os.path.getsize(sPrivateKeyFileName))
        
        if checkIfPassphraseIsRequired(sPrivateKeyFileName):
            #rsaPrivateKey = RSA.importKey(sPrivateKeyData, sPassphrase)
            rsaPrivateKey = serialization.load_pem_private_key(
                sPrivateKeyData,
                password=sPassphrase.encode(),
                backend=default_backend()
            )
        else:
            #rsaPrivateKey = RSA.importKey(sPrivateKeyData)
            rsaPrivateKey = serialization.load_pem_private_key(
                sPrivateKeyData,
                password=None,
                backend=default_backend()
            )
            
        os.close(fdPrivateKey)
            
        #oHash = SHA256.new(sFileToSignContent)
        #oSignature = pkcs1_15.new(rsaPrivateKey).sign(oHash)
        oSignature = rsaPrivateKey.sign(
            sFileToSignContent,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(oSignature)
        os.write(fdSignature, b"-----BEGIN SIGNATURE-----\n")
        os.write(fdSignature, base64.urlsafe_b64encode(oSignature))
        os.write(fdSignature, b"\n-----END SIGNATURE-----")
        os.close(fdSignature)
        
        print("The signature was saved in {0}".format(sSignatureFileName))
    except Exception as e:
        bStatus = False
        
    return bStatus

def verifySignature(sFileName, sPublicKeyFileName, sSignatureFileName):
    bStatus = True
    
    try:
        fdPublicKey = None
        fdSignature = None
        fdSignedFile = None
        oHash = None
        sPublicKeyData = None
        sSignatureData = None
        sSignedFileData = None
        rsaPublicKey = None     
        
        fdPublicKey = os.open(sPublicKeyFileName, os.O_RDONLY)
        sPublicKeyData = os.read(fdPublicKey, os.path.getsize(sPublicKeyFileName))
        os.close(fdPublicKey)
        
        fdSignedFile = os.open(sFileName, os.O_RDONLY)
        sSignedFileData = os.read(fdSignedFile, os.path.getsize(sFileName))
        os.close(fdSignedFile)
        
        fdSignature = os.open(sSignatureFileName, os.O_RDONLY)
        sSignatureData = os.read(fdSignature, os.path.getsize(sSignatureFileName))
        os.close(fdSignature)
        
        sPublicKeyFileExtension = os.path.splitext(sPublicKeyFileName)[1]
        
        if  sPublicKeyFileExtension == ".pem":
            rsaPublicKey = serialization.load_pem_public_key(
                sPublicKeyData,
                backend=default_backend()
            )
        else:
            cert = x509.load_pem_x509_certificate(
                sPublicKeyData,
                backend=default_backend()
            )
        
        if sPublicKeyFileExtension == ".pem":
            rsaPublicKey.verify(
                base64.urlsafe_b64decode(sSignatureData[26:len(sSignatureData) - 24]),
                sSignedFileData,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()            
            )
        else:
            cert.public_key().verify(
                base64.urlsafe_b64decode(sSignatureData[26:len(sSignatureData) - 24]),
                sSignedFileData,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()            
            )                
        print("The signature is valid. Have a happy day ☺")
    except Exception as e:
        bStatus = False
        print("This signature is not valid.")
    
    return bStatus

def isAValidPublicKey(sPublicKeyFileName):
    bValidPublicKey = True
    
    try:
        fdPublicKey = os.open(sPublicKeyFileName, os.O_RDONLY)
        sPublicKeyData = os.read(fdPublicKey, os.path.getsize(sPublicKeyFileName))
        os.close(fdPublicKey)
        
        if str(sPublicKeyData, 'ascii').find("PUBLIC") == -1 and str(sPublicKeyData, 'ascii').find("END") == -1:
            raise Exception("It is not a valid public key.")
        
        rsaPublicKey = RSA.importKey(sPublicKeyData)
        
    except Exception as e:
        bValidPublicKey = False
    
    return bValidPublicKey

class MainWindow(tkinter.Frame):

    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        
        self.iAlgorithm = tkinter.IntVar(value=1)
        self.sFileToEncrypt = tkinter.StringVar()
        self.sFileToSaveEncryptedContent = tkinter.StringVar()
        self.sFileToDecrypt = tkinter.StringVar()
        self.sFileToSaveDecryptedContent = tkinter.StringVar()
        self.iKeySize = tkinter.IntVar(value=2048)
        self.sTargetPublicKeyFile = tkinter.StringVar()
        self.sTargetPrivateKeyFile = tkinter.StringVar()
        self.sPrivateKeyForSigning = tkinter.StringVar()
        self.sFileToSaveSignature = tkinter.StringVar()
        self.sFileToSign = tkinter.StringVar()
        self.sSignedFile = tkinter.StringVar()
        self.sPublicKeyToVerifySignature = tkinter.StringVar()
        self.sSignatureToVerify = tkinter.StringVar()
        self.iUseOriginalFileExtension = tkinter.IntVar(value=1)
        self.iAlsoCreateSelfSignedCertificate = tkinter.IntVar(value=1)
        self.logger = None
        
        self.pack()
        
        self.create_widgets()
        
    def create_widgets(self):
        self.master.geometry("640x400+200+200")
        
        menubar = tkinter.Menu(self.master)
        filemenu = tkinter.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        helpmenu = tkinter.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.createChildWindow)
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.master.config(menu=menubar)
        
        tabs = tkinter.ttk.Notebook(self.master, height=200)
        tabs.pack( fill="x", side="top")
        
        self.logger = tkinter.scrolledtext.ScrolledText(self.master, state="disabled", wrap=tkinter.WORD)
        self.logger.pack(expand=1, fill="both")      
        
        encryptTab = tkinter.ttk.Frame(tabs)
        decryptTab = tkinter.ttk.Frame(tabs)
        keysTab = tkinter.ttk.Frame(tabs)
        signTab = tkinter.ttk.Frame(tabs)
        verifyTab = tkinter.ttk.Frame(tabs)
        
        tabs.add(encryptTab, text="Encrypt")
        tabs.add(decryptTab, text="Decrypt")
        tabs.add(keysTab, text="Keys")
        tabs.add(signTab, text="Sign")
        tabs.add(verifyTab, text="Verify")
        
        tabs.select(encryptTab)
        tabs.enable_traversal()
        
        #TAB: Encrypt
        tkinter.Label(encryptTab, text="Algorithm: ").place(x=20, y=20, height=30)
        tkinter.Radiobutton(encryptTab, text="ARIA256CTR", variable=self.iAlgorithm, value=1).place(x=120, y=24)
        tkinter.Radiobutton(encryptTab, text="CAST256CTR", variable=self.iAlgorithm, value=2).place(x=240, y=24)
        tkinter.Radiobutton(encryptTab, text="RSA & AES128CTR", variable=self.iAlgorithm, value=3).place(x=360, y=24)
        self.iAlgorithm.set(1)
        
        tkinter.Label(encryptTab, text="Plain file: ").place(x=20, y=60, height=30)
        tkinter.Entry(encryptTab, state="readonly", textvariable=self.sFileToEncrypt).place(x=120, y=60, height=30, width=410)
        tkinter.Button(encryptTab, text="Choose... ", command=self.launchFileToEncryptDialog).place(x=530, y=60, width=85)
        
        tkinter.Label(encryptTab, text="Encrypted file: ").place(x=20, y=100, height=30)
        tkinter.Entry(encryptTab, state="readonly", textvariable=self.sFileToSaveEncryptedContent).place(x=120, y=100, height=30, width=410)
        tkinter.Button(encryptTab, text="Save as...", command=self.launchDestinationFileNameDialog).place(x=530, y=100, width=85)
        
        tkinter.Button(encryptTab, text="Encrypt", command=self.encryptFile).place(x=516, y=150, width=100)
        
        #TAB Decrypt
        tkinter.Label(decryptTab, text="Encrypted file: ").place(x=20, y=20, height=30)
        tkinter.Entry(decryptTab, state="readonly", textvariable=self.sFileToDecrypt).place(x=120, y=20, height=30, width=410)
        tkinter.Button(decryptTab, text="Choose... ", command=self.launchFiletoDecryptFileDialog).place(x=530, y=20, width=85)
        
        tkinter.Label(decryptTab, text="Plain file: ").place(x=20, y=60, height=30)
        tkinter.Entry(decryptTab, state="readonly", textvariable=self.sFileToSaveDecryptedContent).place(x=120, y=60, height=30, width=410)
        tkinter.Button(decryptTab, text="Save as...", command=self.launchFileToSaveDecryptedContentFileDialog).place(x=530, y=60, width=85)
        
        tkinter.Checkbutton(decryptTab, text="Use original file extension", variable=self.iUseOriginalFileExtension).place(x=20, y=100)
        
        tkinter.Button(decryptTab, text="Decrypt", command=self.decryptFile).place(x=516, y=150, width=100)
        
        #TAB Keys
        tkinter.Label(keysTab, text="Key size: ").place(x=20, y=20, height=30)
        tkinter.Radiobutton(keysTab, text="2048", variable=self.iKeySize, value=2048).place(x=120, y=24)
        tkinter.Radiobutton(keysTab, text="3072", variable=self.iKeySize, value=3072).place(x=240, y=24)
        tkinter.Radiobutton(keysTab, text="4096", variable=self.iKeySize, value=4096).place(x=360, y=24)
        self.iKeySize.set(2048)        
        
        tkinter.Label(keysTab, text="Private key file: ").place(x=20, y=60, height=30)
        tkinter.Entry(keysTab, state="readonly", textvariable=self.sTargetPrivateKeyFile).place(x=120, y=60, height=30, width=350)
        tkinter.Button(keysTab, text="Save private key as...", command=self.launchTargetPrivateKeyFileDialog).place(x=470, y=60, width=145)
        
        tkinter.Label(keysTab, text="Public key file: ").place(x=20, y=100, height=30)
        tkinter.Entry(keysTab, state="readonly", textvariable=self.sTargetPublicKeyFile).place(x=120, y=100, height=30, width=350)
        tkinter.Button(keysTab, text="Save public key as...", command=self.launchTargetPublicKeyFileDialog).place(x=470, y=100, width=145)
        
        tkinter.Checkbutton(keysTab, text="Create a self-signed certificate", variable=self.iAlsoCreateSelfSignedCertificate).place(x=20, y=140)
        
        tkinter.Button(keysTab, text="Generate keys", command=self.generateKeys).place(x=516, y=150, width=100)
        
        #TAB Sign
        tkinter.Label(signTab, text="File to sign: ").place(x=20, y=20, height=30)
        tkinter.Entry(signTab, state="readonly", textvariable=self.sFileToSign).place(x=120, y=20, height=30, width=410)
        tkinter.Button(signTab, text="Choose... ", command=self.launchFileToSignFileDialog).place(x=530, y=20, width=85)
        
        tkinter.Label(signTab, text="Private key file: ").place(x=20, y=60, height=30)
        tkinter.Entry(signTab, state="readonly", textvariable=self.sPrivateKeyForSigning).place(x=120, y=60, height=30, width=410)
        tkinter.Button(signTab, text="Choose...", command=self.launchPrivateKeyForSigningFileDialog).place(x=530, y=60, width=85)
        
        tkinter.Label(signTab, text="Signature file: ").place(x=20, y=100, height=30)
        tkinter.Entry(signTab, state="readonly", textvariable=self.sFileToSaveSignature).place(x=120, y=100, height=30, width=410)
        tkinter.Button(signTab, text="Save as...", command=self.launchFileToSaveSignatureFileDialog).place(x=530, y=100, width=85)
                
        tkinter.Button(signTab, text="Sign", command=self.signFile).place(x=516, y=150, width=100)

        #TAB Verify
        tkinter.Label(verifyTab, text="Signed file: ").place(x=20, y=20, height=30)
        tkinter.Entry(verifyTab, state="readonly", textvariable=self.sSignedFile).place(x=120, y=20, height=30, width=410)
        tkinter.Button(verifyTab, text="Choose... ", command=self.launchFileUsedToCreateSignatureFileDialog).place(x=530, y=20, width=85)
        
        tkinter.Label(verifyTab, text="Signature file: ").place(x=20, y=60, height=30)
        tkinter.Entry(verifyTab, state="readonly", textvariable=self.sSignatureToVerify).place(x=120, y=60, height=30, width=410)
        tkinter.Button(verifyTab, text="Choose...", command=self.launchSignatureToVerifyFileDialog).place(x=530, y=60, width=85)
        
        tkinter.Label(verifyTab, text="Public key file: ").place(x=20, y=100, height=30)
        tkinter.Entry(verifyTab, state="readonly", textvariable=self.sPublicKeyToVerifySignature).place(x=120, y=100, height=30, width=410)
        tkinter.Button(verifyTab, text="Choose...", command=self.launchPublicKeyToCheckSignatureFileDialog).place(x=530, y=100, width=85)
        
        
        tkinter.Button(verifyTab, text="Verify", command=self.verifySignature).place(x=516, y=150, width=100)
    
    def addEntryToLogger(self, entry, end="\n"):
        self.logger.configure(state="normal")
        self.logger.insert('1.0',  "{0:%Y-%m-%d %H:%M:%S}: {1}{2}".format(datetime.datetime.now(), str(entry), end))
        self.logger.configure(state="disabled")
        
    def decryptFile(self):
        bStatus = True
        sDestinationFileName = ""
        sFileName = ""
        sOriginalFileExtension = ""
        sPartialFileHeader = ""
        sPassword = ""
        sPassphrase = ""
        sPrivateKeyFileName = ""
        
        try:
            if self.sFileToDecrypt.get() == None or len(self.sFileToDecrypt.get()) == 0:
                raise ValueError("Please, specify an encrypted file to decrypt.")
        
            if self.sFileToSaveDecryptedContent.get() == None or len(self.sFileToSaveDecryptedContent.get()) == 0:
                raise ValueError("Please, specify a filename to save the decrypted content.")
            
            sFileName = self.sFileToDecrypt.get()
            sDestinationFileName = self.sFileToSaveDecryptedContent.get()
            
            fdFileName = os.open(sFileName, os.O_RDONLY)
            sPartialFileHeader = os.read(fdFileName, 32)
            os.close(fdFileName)
            
            iAlgorithm = int.from_bytes(sPartialFileHeader[8:16], "big")
            sOriginalFileExtension = str(sPartialFileHeader[24:], 'ascii').replace(chr(0), '')
            
            if bool(self.iUseOriginalFileExtension.get()):
                sDestinationFileName = os.path.splitext(sDestinationFileName)[0]
            
            print(sDestinationFileName)
            print(self.iUseOriginalFileExtension.get())
            
            if iAlgorithm == 1 or iAlgorithm == 2:
                sPassword = self.askPassword2()
                
                if sPassword == None or len(sPassword) == 0:
                    raise RuntimeError("Unable to perform the decryption because a password has not been provided.")
                
            elif iAlgorithm == 3:
                sPrivateKeyFileName = self.launchPrivateKeyForDecryptingFileDialog()
                if sPrivateKeyFileName == None or len(sPrivateKeyFileName) == 0:
                    raise RuntimeError("Unable to perform the decryption because a valid private key has not been provided.")
                else:
                    if checkIfPassphraseIsRequired(sPrivateKeyFileName):
                        sPassphrase = self.askPassphrase2()    
                        if sPassphrase == None:
                            raise RuntimeError("Unable to perform the decryption because a valid passphrase has not been provided.")
            else:
                raise RuntimeError("Algorithm has not been implemented")
            
            bStatus = decryptFile(
                sFileName, 
                sDestinationFileName, 
                sPassword, 
                sPrivateKeyFileName, 
                sPassphrase, 
                self.iUseOriginalFileExtension.get()
            )
            
            if bStatus:
                if bool(self.iUseOriginalFileExtension.get()):
                    sDestinationFileName = sDestinationFileName + "." + sOriginalFileExtension
                    
                tkinter.messagebox.showinfo(title="Decryption successful", message="The file has successfully decrypted and saved as {1}.".format(sFileName.split('/')[-1], sDestinationFileName.split('/')[-1]))
                self.addEntryToLogger(
                    "The file {0} has successfully decrypted and saved as {1}.".format(
                        sFileName.split('/')[-1], 
                        sDestinationFileName.split('/')[-1]
                    )
                )
                
            else: #Falta validad algunos errores logicos
                self.addEntryToLogger(
                    "The file {0} cannot be decrypted.".format(
                        self.sFileToEncrypt.get().split('/')[-1]
                    )
                )
                
                raise RuntimeError("Something went wrong. Are the passphrase or the key correct?")
            
        except ValueError as e:
            tkinter.messagebox.showwarning(title="Something is missing!", message=e)
        except (RuntimeError, Exception) as e:
            tkinter.messagebox.showerror(title="An error has ocurred!", message=e)
            
    def launchPrivateKeyForDecryptingFileDialog(self):
        sPrivateKeyForDecryptingFileName = ""
        
        sPrivateKeyForDecryptingFileName = tkinter.filedialog.askopenfilename(
            title="Choose the private key for decrypting", 
            filetypes=[("Private Key files", "*.pem")])
        
        return sPrivateKeyForDecryptingFileName

        
    def launchFileToSaveDecryptedContentFileDialog(self):
        sFileName = ""

        sFileName = tkinter.filedialog.asksaveasfilename(
            title="Save plain file as...", 
            filetypes=[("All files", "*.*")]
        )
        
        if sFileName != None and len(sFileName) > 0:
            self.sFileToSaveDecryptedContent.set(sFileName)
            
    def launchFiletoDecryptFileDialog(self):
        sFileName = ""
        
        sFileName = tkinter.filedialog.askopenfilename(
            title="Choose the encrypted file", 
            filetypes=[("Encrypted files", "*.enc")]
        )
        
        if sFileName != None and len(sFileName) > 0:
            self.sFileToDecrypt.set(sFileName)
            
    def launchFileUsedToCreateSignatureFileDialog(self):
        sFileUsedToCreateSignatureFileName = ""
        
        sFileUsedToCreateSignatureFileName = tkinter.filedialog.askopenfilename(
            title="Choose the file to check the signature", 
            filetypes=[("All files", "*.*")])
        
        if sFileUsedToCreateSignatureFileName != None and len(sFileUsedToCreateSignatureFileName) > 0:
            self.sSignedFile.set(sFileUsedToCreateSignatureFileName)
        
    def launchSignatureToVerifyFileDialog(self):
        sSignatureToVerifyFileName = ""
        
        sSignatureToVerifyFileName = tkinter.filedialog.askopenfilename(
            title="Choose a signature to validate", 
            filetypes=[("Signature file", "*.signature")]
        )
        
        if sSignatureToVerifyFileName != None and len(sSignatureToVerifyFileName) > 0:
            self.sSignatureToVerify.set(sSignatureToVerifyFileName)
        
    def launchPublicKeyToCheckSignatureFileDialog(self):
        sPublicKeyToVerifySignatureFileName = ""
        
        sPublicKeyToVerifySignatureFileName = tkinter.filedialog.askopenfilename(
            title="Choose a public key to verify signature", 
            filetypes=[("Public Key file", "*.pem"), ("Certificate file", "*.crt")]
        )
        
        if sPublicKeyToVerifySignatureFileName != None and len(sPublicKeyToVerifySignatureFileName) > 0:
            self.sPublicKeyToVerifySignature.set(sPublicKeyToVerifySignatureFileName)
        
    def verifySignature(self):
        bStatus = True
        
        try:
            if self.sSignedFile.get() == None or len(self.sSignedFile.get()) == 0:
                raise ValueError("Please, specify the file used to create the signature.")
            
            if self.sSignatureToVerify.get() == None or len(self.sSignatureToVerify.get()) == 0:
                raise ValueError("Please, specify a signature to validate.")
                
            if self.sPublicKeyToVerifySignature.get() == None or len(self.sPublicKeyToVerifySignature.get()) == 0:
                raise ValueError("Please, specify a public key to validate the signature.")
                
            bStatus = verifySignature(
                self.sSignedFile.get(), 
                self.sPublicKeyToVerifySignature.get(), 
                self.sSignatureToVerify.get()
            )
            
            if bStatus:
                tkinter.messagebox.showinfo(
                    title="Signature is valid", 
                    message="The signature is valid. Have a happy day ☺"
                )
                
                issuer = ""
                if self.sPublicKeyToVerifySignature.get().find(".crt") != -1:
                    fdPublicKey = os.open(self.sPublicKeyToVerifySignature.get(), os.O_RDONLY)
                    sPublicKeyData = os.read(fdPublicKey, os.path.getsize(self.sPublicKeyToVerifySignature.get()))
                    os.close(fdPublicKey)
                    cert = x509.load_pem_x509_certificate(
                        sPublicKeyData,
                        backend=default_backend()
                    )
                    issuer = str(cert.issuer).replace("<Name(CN=", "").replace(")>", "")
                    print(cert.issuer)
                    validThrough = cert.not_valid_after
                    self.addEntryToLogger(
                        "{0} is a valid signature. The file {1} was signed with the private key associated to the certificate {2}. This certificate belongs to {3} and is valid through {4}".format(
                            self.sSignatureToVerify.get().split('/')[-1], 
                            self.sSignedFile.get().split('/')[-1], 
                            self.sPublicKeyToVerifySignature.get().split('/')[-1], 
                            issuer, 
                            validThrough
                        )
                    )
                    
                else:    
                    self.addEntryToLogger(
                        "{0} is a valid signature. The file {1} was signed with the private key associated to the public key {2}.".format(
                            self.sSignatureToVerify.get().split('/')[-1], 
                            self.sSignedFile.get().split('/')[-1], 
                            self.sPublicKeyToVerifySignature.get().split('/')[-1]
                        )
                    )
            else:
                tkinter.messagebox.showerror(
                    title="Validation Error", 
                    message="The signature is not valid."
                )
                
                self.addEntryToLogger(
                    "{0} is not a valid signature. The public key {1} could not match the private key used to sign the original file or the file {2} is different from the original file.".format(
                        self.sSignatureToVerify.get().split('/')[-1], 
                        self.sPublicKeyToVerifySignature.get().split('/')[-1], 
                        self.sSignedFile.get().split('/')[-1]
                    )
                )
    
        except ValueError as e:
            tkinter.messagebox.showwarning(
                title="Something is missing!", 
                message=e
            )
            
        except (RuntimeError, Exception) as e:
            tkinter.messagebox.showerror(
                title="An error has ocurred!", 
                message=e
            )
            
    def signFile(self):
        bPassphraseRequired = False
        bStatus = True
        sPassphrase = ""
        
        try:
            if self.sFileToSign.get() == None or len(self.sFileToSign.get()) == 0:
                raise ValueError("Please, specify a file to sign.")
            
            if self.sPrivateKeyForSigning.get() == None or len(self.sPrivateKeyForSigning.get()) == 0:
                raise ValueError("Please, provide a valid private key for signing.")
            
            if self.sFileToSaveSignature.get() == None or len(self.sFileToSaveSignature.get()) == 0:
                raise ValueError("Please, provide a filename to save the signature.")
            
            bPassphraseRequired = checkIfPassphraseIsRequired(self.sPrivateKeyForSigning.get())
            
            if bPassphraseRequired:
                sPassphrase = self.askPassphrase2()
                
            if sPassphrase == None:
                raise ValueError("A passphrase is required in order to read the private key.")
            
            bStatus = signFile(
                self.sFileToSign.get(), 
                self.sPrivateKeyForSigning.get(), 
                self.sFileToSaveSignature.get(), 
                sPassphrase
            )
            
            if bStatus:
                tkinter.messagebox.showinfo(
                    title="File has been signed!", 
                    message="The file has been signed successfully."
                )
                
                fdSignature = os.open(self.sFileToSaveSignature.get(), os.O_RDONLY)
                self.addEntryToLogger(
                    "File has been signed successfully.\nThe signature was saved in {0}.\nSignature file content:\n{1}".format(
                        self.sFileToSaveSignature.get().split('/')[-1], 
                        str(os.read(fdSignature, os.path.getsize(self.sFileToSaveSignature.get())), 'ascii')
                    )
                )
                
                os.close(fdSignature)
            else:
                self.addEntryToLogger(
                    "Unable to sign the file {0}. The passphrase is wrong.".format(
                        self.sFileToSign.get().split('/')[-1]
                    )
                )
                
                raise RuntimeError("Passphrase is wrong.")
        
        except ValueError as e:
            tkinter.messagebox.showwarning(title="Something is missing!", message=e)
        except (RuntimeError, Exception) as e:
            tkinter.messagebox.showerror(title="An error has ocurred!", message=e)        
            
    def launchFileToSignFileDialog(self):
        sFileToSignFileName = ""
        
        sFileToSignFileName = tkinter.filedialog.askopenfilename(
            title="Choose a file to sign", 
            filetypes=[("All files", "*.*")]
        )
        
        if sFileToSignFileName != None and len(sFileToSignFileName) > 0:
            self.sFileToSign.set(sFileToSignFileName)
            
    def launchFileToSaveSignatureFileDialog(self):
        sSignatureFileName = ""
        
        sSignatureFileName = tkinter.filedialog.asksaveasfilename(
            title="Save signature as...", 
            filetypes=[("Signature File", "*.signature")]
        )
        
        if sSignatureFileName != None and len(sSignatureFileName) > 0:
            self.sFileToSaveSignature.set(sSignatureFileName)
        
    def launchPrivateKeyForSigningFileDialog(self):
        sPrivateKeyForSigningFileName = ""
        
        sPrivateKeyForSigningFileName = tkinter.filedialog.askopenfilename(
            title="Choose a private key for signing", 
            filetypes=[("Private Key file", "*.pem")]
        )
        
        if sPrivateKeyForSigningFileName != None and len(sPrivateKeyForSigningFileName) > 0:
            self.sPrivateKeyForSigning.set(sPrivateKeyForSigningFileName)
            
    def launchTargetPrivateKeyFileDialog(self):
        sTargetPrivateKeyFileName = ""
        
        sTargetPrivateKeyFileName = tkinter.filedialog.asksaveasfilename(
            title="Save private key as...", 
            filetypes=[("Private Key file", "*.pem")]
        )
        
        if sTargetPrivateKeyFileName != None and len(sTargetPrivateKeyFileName) > 0:
            self.sTargetPrivateKeyFile.set(sTargetPrivateKeyFileName)
            
    def launchTargetPublicKeyFileDialog(self):
        sTargetPublicKeyFileName = ""
        
        sTargetPublicKeyFileName = tkinter.filedialog.asksaveasfilename(
            title="Save public key as...", 
            filetypes=[("Public Key file", "*.pem")]
        )
        
        if sTargetPublicKeyFileName != None and len(sTargetPublicKeyFileName) > 0:
            self.sTargetPublicKeyFile.set(sTargetPublicKeyFileName)
            
    def generateKeys(self):
        bStatus = True
        sPassphrase = ""
        sCommonName = ""
        
        try:
            if self.sTargetPrivateKeyFile.get() == None or self.sTargetPrivateKeyFile.get() == "": 
                raise ValueError("Specify a filename to save the private key.")
            
            if self.sTargetPublicKeyFile.get() == None or self.sTargetPublicKeyFile.get() == "":
                raise ValueError("Specify a filename to save the public key.")
            
            sPassphrase = self.askPassphrase()
            
            if sPassphrase != None:
                
                if bool(self.iAlsoCreateSelfSignedCertificate.get()):
                    sCommonName = self.askCommonName()
                
                    if sCommonName != None and len(sCommonName) != 0:
                        bStatus = generateKeys(
                            self.sTargetPrivateKeyFile.get(), 
                            self.sTargetPublicKeyFile.get(), 
                            self.iKeySize.get(), 
                            sPassphrase, 
                            bool(self.iAlsoCreateSelfSignedCertificate.get()), 
                            sCommonName
                        )
                        
                        if bStatus:
                            tkinter.messagebox.showinfo(
                                title="Generation successfully", 
                                message="Keys and certificate have been generated successfully.")
                            
                            self.addEntryToLogger("Keys and certificate have been generated successfully. The private key was saved in {0} and its corresponding public key was saved in {1}. The certificate was saved in {2}.".format(
                                self.sTargetPrivateKeyFile.get().split('/')[-1], 
                                self.sTargetPublicKeyFile.get().split('/')[-1], 
                                os.path.splitext(self.sTargetPublicKeyFile.get().split('/')[-1])[0] + ".crt"
                            ))
                            
                        else:
                            self.addEntryToLogger("An error has ocurred. The keys could not be generated.")
                            raise RuntimeError("Keys could not be generated due to a program error.")                        
                    else:
                        self.addEntryToLogger("The keys could not be generated because a self-signed certificate was requested but an owner name has not been specified.")
                        raise RuntimeError("Keys could not be generated because the certificate owner name was not specified.") 
                else:
                    bStatus = generateKeys(self.sTargetPrivateKeyFile.get(), self.sTargetPublicKeyFile.get(), self.iKeySize.get(), sPassphrase)
                    if bStatus:
                        tkinter.messagebox.showinfo(
                            title="Generation successfully", 
                            message="Keys have been generated successfully."
                        )
                        
                        self.addEntryToLogger("The keys have been generated successfully. The private key was saved in {0} and its corresponding public key was saved in {1}".format(
                            self.sTargetPrivateKeyFile.get().split('/')[-1], 
                            self.sTargetPublicKeyFile.get().split('/')[-1]
                        ))
                        
                    else:
                        self.addEntryToLogger("An error has ocurred. The keys could not be generated.")
                        raise RuntimeError("Keys could not be generated due to a program error.")
                    
            else:
                tkinter.messagebox.showerror(title="An error has ocurred...", message="Keys could not be generated because a passphrase has not been specified.")
                self.addEntryToLogger("The keys could not be generated because a passphrase has not been specified.")
                            
        except ValueError as e:
            tkinter.messagebox.showwarning(
                title="Something is missing!", 
                message=e
            )
            
        except (RuntimeError, Exception) as e:
            tkinter.messagebox.showerror(
                title="An error has ocurred!", 
                message=e
            )
    
    def askPassphrase(self):
        sPassphrase = ""
        sVerifiedPassphrase = ""
        bCancelled = False
        
        while len(sPassphrase) < 8:
            sPassphrase = tkinter.simpledialog.askstring(
                "Passphrase", "Enter a passphrase to protect the private key (minimum 8 characters): ", 
                show="*"
            )
            
            if sPassphrase == None:
                bCancelled = True
                break
            
            if len(sPassphrase) < 8:
                tkinter.messagebox.showerror(
                    title="Passphrase is not valid", 
                    message="Passphrase does not meet requirements. The passphrase should be a minimum of eight characters long."
                )
        
        while bCancelled == False and sPassphrase != sVerifiedPassphrase:
            sVerifiedPassphrase = tkinter.simpledialog.askstring(
                "Passphrase", "                       Confirm the passphrase:                       ", 
                show="*"
            )
            
            if sVerifiedPassphrase == None:
                bCancelled = True
                break
            if sPassphrase != sVerifiedPassphrase:
                tkinter.messagebox.showerror(
                    title="Passphrase Confirmation Error", 
                    message="Passphrases does not match."
                )
                
        if bCancelled:
            sPassphrase = None
        return sPassphrase    
    
    def askCommonName(self):
        sCommonName = ""
        
        sCommonName = tkinter.simpledialog.askstring(
            "Certificate Owner", 
            "Enter the certificate owner name: "
        )
        
        return sCommonName
        
        
    def askPassphrase2(self):
        sPassphrase = ""
        bCancelled = False
        
        sPassphrase = tkinter.simpledialog.askstring(
            "Passphrase", 
            "Enter the passphrase used to protect the private key: ", 
            show="*"
        )
        
        if sPassphrase == None:
            bCancelled = True
        
        if bCancelled:
            sPassphrase = None
        return sPassphrase 
    
    def askPassword2(self):
        sPassword = ""
        
        sPassword = tkinter.simpledialog.askstring(
            "Password is required", 
            "Enter the password used to encrypt the file: ", 
            show="*"
        )
        
        return sPassword 
    
    def launchFileToEncryptDialog(self):
        sFileName = ""
        
        sFileName = tkinter.filedialog.askopenfilename(title="Choose a file to encrypt")
        
        if sFileName == None or len(sFileName) != 0:
            self.sFileToEncrypt.set(sFileName)
    
    def launchDestinationFileNameDialog(self):
        sFileName = ""
        
        sFileName = tkinter.filedialog.asksaveasfilename(
            title="Save as", 
            filetypes=[("Encrypted file", "*.enc")]
        )
        
        if sFileName == None or len(sFileName) != 0:
            self.sFileToSaveEncryptedContent.set(sFileName)
    
    def encryptFile(self):
        bStatus = True
        sPassword = ""
        sPublicKeyFileName = ""
        
        try:
            if self.sFileToEncrypt.get() == None or len(self.sFileToEncrypt.get()) == 0:
                raise ValueError("Choose a file to encrypt")
                
            if self.sFileToSaveEncryptedContent.get() == None or len(self.sFileToSaveEncryptedContent.get()) == 0:
                raise ValueError("Choose a file to save the encrypted content.")
            
            if self.iAlgorithm.get() == 1 or self.iAlgorithm.get() == 2:
                sPassword = self.askPassword()
                
                if sPassword != None and len(sPassword) > 0:
                    bStatus = encrypt(
                        self.iAlgorithm.get(), 
                        self.sFileToEncrypt.get(), 
                        self.sFileToSaveEncryptedContent.get(), 
                        sPassword,
                        ""
                    )
                    
                    if bStatus == True:
                        tkinter.messagebox.showinfo(
                            title="Encryption completed", 
                            message="Encryption has been completed successfully!"
                        )
                        self.addEntryToLogger("The file {0} has successfully encrypted and saved as {1}.".format(
                            self.sFileToEncrypt.get().split('/')[-1], 
                            self.sFileToSaveEncryptedContent.get().split('/')[-1]
                        ))
                    else:
                        raise RuntimeError("Encryption could not be completed due to a program error.")                    
                else:
                    raise RuntimeError("Unable to perform the encryption because a valid password has not been provided.")
                
            elif self.iAlgorithm.get() == 3:
                
                sPublicKeyFileName = self.launchPublicKeyFileDialog()
                
                if sPublicKeyFileName != None and len(sPublicKeyFileName) > 0 and isAValidPublicKey(sPublicKeyFileName):
                    bStatus = encrypt(
                        self.iAlgorithm.get(), 
                        self.sFileToEncrypt.get(), 
                        self.sFileToSaveEncryptedContent.get(), 
                        "", 
                        sPublicKeyFileName
                    )
                    
                    if bStatus == True:
                        tkinter.messagebox.showinfo(
                            title="Encryption completed", 
                            message="Encryption has been completed successfully!"
                        )
                        self.addEntryToLogger("The file {0} has successfully encrypted and saved as {1}.".format(
                            self.sFileToEncrypt.get().split('/')[-1], 
                            self.sFileToSaveEncryptedContent.get().split('/')[-1])
                        )                        
                    else:
                        raise RuntimeError("Encryption could not be completed due to a program error.")
                else:
                    raise RuntimeError("Unable to perform the encryption because a valid public key File has not been specified")
                        
            else:
                raise RuntimeError("Algorithm has not been implemented")
                        
        except ValueError as e:
            tkinter.messagebox.showwarning(title="Something is missing!", message=e)
        except (RuntimeError, Exception) as e:
            tkinter.messagebox.showerror(title="An error has ocurred!", message=e)

    def askPassword(self):
        sPassword = ""
        sVerifiedPassword = ""
        bCancelled = False
        
        while len(sPassword) < 8:
            sPassword = tkinter.simpledialog.askstring("Password", "Enter a password (minimum 8 characters): ", show="*")
            if sPassword == None:
                bCancelled = True
                break
            if len(sPassword) < 8:
                tkinter.messagebox.showerror(
                    title="Password is not valid",
                    message="Password does not meet requirements. The password should be a minimum of eight characters."
                )
        
        while bCancelled == False and sPassword != sVerifiedPassword:
            sVerifiedPassword = tkinter.simpledialog.askstring("Password", "          Confirm your password:         ", show="*")
            if sVerifiedPassword == None:
                bCancelled = True
                break
            if sPassword != sVerifiedPassword:
                tkinter.messagebox.showerror(
                    title="Password Confirmation Error", 
                    message="Password does not match. Please, confirm your password"
                )
                
        if bCancelled:
            sPassword = None
        return sPassword    
    
    def launchPublicKeyFileDialog(self):
        bCancelled = False
        sPublicKeyFile = ""
        
        while bCancelled == False and len(sPublicKeyFile) == 0:
            sPublicKeyFile = tkinter.filedialog.askopenfilename(
                title="Specify a Valid Public Key", 
                filetypes=[("Public Key file", "*.pem"), ("Certificate file", "*.crt")]
            )
            if sPublicKeyFile == None or len(sPublicKeyFile) == 0:
                bCancelled = True
        
        if bCancelled == True:
            sPublicKeyFile = None
            
        return sPublicKeyFile
        
    def createChildWindow(self):
        sCredits = (
            "AAZEHI was written by Aaron Lopez, Hidelmar Huezo and Jorge Zelaya.\n\n" + 
            "This program contains the following third-party modules and packages: \n\n" +
            " * Python 3.6, the programming language, written by Guido van Rossum and\n" +
            "   many contributors.\n" +
            " * TkInter, the standard Python interface to the Tk GUI toolkit written by Steen\n" +
            "   Lumholt and Guido van Rossum.\n" +
            " * cryptography, a packages that provides recipes and primitives tto Python\n" + 
            "   by many authors that you can check in the URL\n" +
            "   https://github.com/pyca/cryptography/blob/master/AUTHORS.rst\n" +
            " * PyCryptodome 3.8.2, a self-contained Python package of low-level cryptographic\n" +
            "   primitives, developed by many authors that you can check in the URL\n" +
            "   https://github.com/Legrandin/pycryptodome/blob/master/AUTHORS.rst.\n" +
            " * PyAria 1.0.0, an ARIA cipher implementation with Python developed by Jihwan\n" + 
            "   Chun.\n" +
            " * cast6ecb 0.2.1.dev0, A mcrypt binding for CAST-256 written by Rémi Paulmier.\n\n" + 
            "This program is free software: you can redistribute it and/or modify it under the\n" +
            "terms of the GNU General Public License as published by the Free Software\n" +
            "Foundation, either version 3 of the License, or (at your option) any later version.\n\n" +
            "This program is distributed in the hope that it will be useful, but WITHOUT ANY\n" +
            "WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS\n" + 
            "FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.\n\n" +
            "You should have received a copy of the GNU General Public License along with this\n" +
            "program.  If not, see <https://www.gnu.org/licenses/>."                    
        ) 
                    
        self.aboutWindow = tkinter.Toplevel(self.master)
        self.aboutWindow.title("About AAZEHI")
        self.aboutWindow.resizable(width=520, height=540)
        self.aboutWindow.maxsize(width=520, height=540)
        self.aboutWindow.minsize(width=520, height=540)
        self.aboutWindow.transient(self.master)
        self.aboutWindow.attributes('-topmost', 'true')
        self.aboutWindow.programName = tkinter.Label(self.aboutWindow, text=sProgramName + sProgramVersion, justify="left", font=("Helvetica, 14"), padx=5).place(x=0, y=5)
        self.aboutWindow.message = tkinter.Label(self.aboutWindow, text=sCredits, justify="left", padx=5).place(x=0, y=45)
        self.aboutWindow.okButton = tkinter.Button(self.aboutWindow, text="Ok", command=self.aboutWindow.destroy).place(x=399, y=490, width=100)
        self.aboutWindow.grab_set()
        
    def doNothing():
        pass
    
def main():    
    root = tkinter.Tk()
    root.title(sProgramName)    
    app = MainWindow(master=root)
    app.mainloop()

    
if __name__ == "__main__":
    main()
