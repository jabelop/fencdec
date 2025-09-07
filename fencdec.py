#! /usr/bin/env python
from pyDesCust import triple_des as des
from os import walk, system
import hashlib as h
import signal
import sys

sha256 = h.sha256

class KillException(Exception):
    def __init__(self):
      Exception.__init__(self)

def sig_handler(code, frame)->None:
    raise KillException()

signal.signal(signal.SIGINT, sig_handler)

GREEN = '\033[92m'
HEADER = '\033[95m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
RED = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

PASS_FILE_NAME = '.pass.fed'

debug_mode = False

def verifyPass(user_pass):
    try:
        f = open(PASS_FILE_NAME, 'r')
        for line in f:
            if sha256(user_pass.encode('utf-8')).hexdigest() == line:
                f.close()
                return True
        msg = RED + "\n\t\t[-] Passphrase incorect!!!\r\n" + ENDC
        log.append(msg)
        print (msg)
        foo = input(YELLOW+"\t\tPress any key to show the menu\n"+ENDC)
        f.close()
        return False
    except Exception as ex:
        system('clear')
        if debug_mode:
          print(ex)
        log.append(ex.__str__())
        while True:
            confirm = input(YELLOW+'\n\t\tThere is no way to verify the pass to decrypt.\n\t\tDo you want continue anyway?'+ENDC+BLUE+' [y/n]:'+ENDC)
            if (confirm == 'y'):
                return True
            elif (confirm == 'n'):
                return False
def existPass():
    try:
        f = open(PASS_FILE_NAME)
        f.close()
        return True

    except Exception as ex:
        if debug_mode:
            print(ex)
        return False


def printLog(log):
    system('clear')
    if len(log) < 1:
        print (GREEN+"\t\tThere is not activity yet\n"+ENDC)
        foo = input(YELLOW+"\t\tPress any key to show the menu\n"+ENDC)
        return
    for line in log:
        print (line)
    foo = input(YELLOW+"\t\tPress any key to show the menu\n"+ENDC)

def encryptFile(fichero, user_pass):
    '''
    @funcionamiento: Encripta un fichero en el mismo directorio.
    @argumentos: la clave de encriptacion, el nombre del fichero
    @return: devuelve True
    '''
    try:
      # abro el fichero lo copio en memoria y lo cierro
      f = open(fichero, 'rb+')
      d = f.read()
      f.close()

      # convierto la clave string en objeto clave
      k = des(user_pass, logger= lambda msg: log.append(msg))

      # encripto el fichero-objeto en memoria con el
      # objeto clave y lo grabo con el mismo nombre
      msg = YELLOW + "\t\t[/] encrypting "+fichero+ " ....\r\n" + ENDC
      log.append(msg)
      print (msg)
      d = k.encrypt(d, pad='$', file_name=fichero)
      f = open(fichero + ".enc", 'wb+')
      f.write(d)
      f.close()
      return True
    except Exception as ex:
      if debug_mode:
        print(ex)
      return False

def encryptFiles(dir, user_pass):
  if existPass():
    system('clear')
    msg = RED + "\n\t\t[-] This folder has been encrypted previously\r\n" + ENDC
    log.append(msg)
    print (msg)
    foo = input(YELLOW+"\t\tPress any key to show the menu\n"+ENDC)
    return
  try:
      f = open(PASS_FILE_NAME, 'w')
      hashed = sha256(user_pass.encode('utf-8')).hexdigest()

      f.write(hashed)
      f.close()
      msg = GREEN + "\n\t\t[+] Pass verifier succesfully created\r\n" + ENDC
      log.append(msg)
      print (msg)
  except Exception as ex:
    while True:
      system('clear')
      print (ex)
      confirm =input(YELLOW + "\n\t\tThe pass verifier can't be created\r\n\t\tDo you want to continue anyway? "+ENDC+BLUE+"[y/n]: " + ENDC)
      if confirm == 'y':
          break
      elif confirm == 'n':
          return
    pass
  for (dirpath, dirnames, filenames) in walk(dir):
    for filename in filenames:
        if filename == "fencdec.py" or filename == PASS_FILE_NAME:
            continue
        if dirpath != './':
            filename = dirpath + "/" + filename
        if (encryptFile(filename, user_pass)):
          msg = GREEN + "\t\t[+] "+filename+ " succesfully encrypted\r\n" + ENDC
          log.append(msg)
          print (msg)
        else:
          msg = RED + "\t\t[-]error encrypting "+ filename + "\r\n" + ENDC
          log.append(msg)
          print (msg)
  foo = input(YELLOW+"\t\tPress any key to show the menu\n"+ENDC)

def decryptFile(fichero, user_pass):
    '''
    @funcionamiento: Desencripta un fichero en el mismo directorio.
    @argumentos: la clave de encriptacion, el nombre del fichero
    @return: devuelve True
    '''
    try:
      # abro el fichero lo copio en memoria y lo cierro
      f = open(fichero, 'rb+')
      d = f.read()
      f.close()
  
      # convierto la clave string en objeto clave
      k = des(user_pass, logger= lambda msg: log.append(msg))
  
      # desencripto el fichero-objeto en memoria con el objeto
      # clave y lo grabo con el mismo nombre
      msg = YELLOW + "\t\t[/] Decrypting "+fichero+ " ....\r\n" + ENDC
      log.append(msg)
      print (msg)
      d = k.decrypt(d, pad='$', file_name=fichero)
      f = open(fichero[:-3]+'dec', 'wb+')
      f.write(d)
      f.close()
      return True
    except Exception as ex:
        if debug_mode:
            print(ex)
        return False

def decryptFiles(dir, user_pass):
  success = True
  if not verifyPass(user_pass):
    return
  for (dirpath, dirnames, filenames) in walk(dir):
    for filename in filenames:
        if filename == "fencdec.py" or filename == PASS_FILE_NAME:
            continue
        if filename[-4:] != '.enc':
            confirm = input(YELLOW+'\n\t\tThe file: '+ filename +' does not seem to be encripted.\n\t\tDo you want decrypt it anyway?'+ENDC+BLUE+' [y/n]:'+ENDC)
            if (confirm == 'n'):
                continue
        if dirpath != './':
            filename = dirpath + "/" + filename
        if (decryptFile(filename, user_pass)):
          msg = GREEN + "\t\t[+] "+ filename + " succesfully decrypted\r\n" + ENDC
          log.append(msg)
          print (msg)
        else:
            success = False
            msg = RED+"\t\t[-] error decrypting " + filename + "\r\n" + ENDC
            log.append(msg)
            print (msg)
  if success:
      system('rm '+ PASS_FILE_NAME)
  foo = input(YELLOW+"\t\tPress any key to show the menu\n"+ENDC)

def build_key(user_pass):
    if len(user_pass) > 23:
      return user_pass[0:24]
    hash_fun = h.new('sha256')
    hash_fun.update(bytes(user_pass, encoding='utf8'))
    hash_pass = hash_fun.hexdigest()
    final_pass = user_pass[:]
    for index in range(24):
        if index == len(hash_pass):
            hash_fun.update(bytes(final_pass, encoding='utf8'))
            hash_pass += hash_fun.hexdigest()
        if len(final_pass) == 24:
            return final_pass
        final_pass = final_pass + hash_pass[index]
    return final_pass

log = []
while True:
  system('clear')
  print (GREEN + ("\t"*2)+("#"*80) + ENDC)
  print (GREEN+("\t"*2)+("#"*2)+ ENDC+BLUE+"      _____   _____    ____    __    _____    _____    _____     _____"+ENDC+ "      "+GREEN+("#"*2)+ENDC)
  print (GREEN+("\t"*2)+("#"*2)+ ENDC+BLUE+"     |   __| |   __|  |    \\  |  |  |   __|  |     \\  |   __|   |   __|"+ENDC+ "     "+GREEN+("#"*2)+ENDC)
  print (GREEN+("\t"*2)+("#"*2)+ ENDC+BLUE+"     |  |__  |  |__   |     \\ |  |  |  |     |  |\\  \\ |  |__    |  |"+ENDC+ "        "+GREEN+("#"*2)+ENDC)
  print (GREEN+("\t"*2)+("#"*2)+ ENDC+BLUE+"     |   __| |   __|  |  |\\  \\|  |  |  |     |  |/  / |   __|   |  |  "+ENDC+ "      "+GREEN+("#"*2)+ENDC)
  print (GREEN+("\t"*2)+("#"*2)+ ENDC+BLUE+"     |  |    |  |__   |  | \\     |  |  |__   |     /  |  |__    |  |__"+ENDC+ "      "+GREEN+("#"*2)+ENDC)
  print (GREEN+("\t"*2)+("#"*2)+ ENDC+BLUE+"     |__|    |_____|  |__|  \\____|  |_____|  |____/   |_____|   |_____|"+ENDC+ "     "+GREEN+("#"*2)+ENDC)
  print (GREEN+("\t"*2)+("#"*2) + (" "*76) + ("#"*2)+ENDC)
  print (GREEN+("\t"*2)+("#"*2) +ENDC+YELLOW+ "\t\t    File encryptor decryptor 2018"+ENDC+BLUE+" Code Xa"+ENDC+(" "*21) + GREEN+("#"*2)+ENDC)
  print (GREEN+("\t"*2)+("#"*2) + (" "*76) + ("#"*2)+ENDC)
  print (GREEN+("\t"*2)+("#"*80)+ENDC)

  print ("\n\n\t\t"+RED+" 1.-"+ENDC+YELLOW+" Encrypt files from directory"+ENDC)
  print ("\n\t\t"+RED+" 2.-"+ENDC+YELLOW+" Decrypt files from directory"+ENDC)
  print ("\n\t\t"+RED+" 3.-"+ENDC+YELLOW+" View log"+ENDC)
  print (RED+"\n\t\t 4.- "+ ENDC+YELLOW+("Deactivate " if debug_mode else "Activate ")  +"debug mode"+ENDC)
  print (RED+"\n\t\t 5.- Exit\n\n"+ENDC)
  try:
    opc = int(input("Choice an option "+BLUE+"[1-5]"+ENDC+": "))
  except Exception as e:
    if debug_mode:
        print(e)
    system('clear')
    print (RED+"you must input a number betwen 1 and 5.\r\n"+ENDC)
    foo = input(YELLOW+"\t\tPress any key to show the menu\n"+ENDC)
    continue
  if isinstance(opc, int):
      try:
        if opc > 0 and opc < 6:
            if opc == 5:
                system("clear")
                exit(0)
            if opc == 3:
                printLog(log)
                continue
            if opc == 4:
                system("clear")
                if debug_mode:
                    msg = GREEN+"Debug mode deactivated"+ENDC
                    log.append(msg)
                    print("\t\t"+msg+"\n")
                    debug_mode = False
                else:
                    msg = GREEN+"Debug mode activated"+ENDC
                    log.append(msg)
                    print("\t\t"+msg+"\n")
                    debug_mode = True
                foo = input(YELLOW+"\t\tPress any key to show the menu\n"+ENDC)
                continue
            system('clear')
            dir = input(BLUE+"\n\tInput the directory with the files to " + ("decrypt " if opc == 2 else "encrypt ") + "\n\tpulse intro for the current directory: "+ENDC)
  
            if dir == "":
                dir = "./"
            system("stty -echo")
            user_pass = input(BLUE+"\n\tInput a passphrase: "+ENDC)
            system("stty echo")
            print ("\n")
            if opc == 1:
                encryptFiles(dir, build_key(user_pass))
            else:
                decryptFiles(dir, build_key(user_pass))
        else:
          system('clear')
          print (RED+"\t\tyou must input a number betwen 1 and 3.\r\n"+ENDC)
          foo = input(YELLOW+"\t\tPress any key to show the menu\n"+ENDC)
          continue
      except KillException as ex:
        sys.stdout.flush()
  else:
    system('clear')
    print (RED+"\t\tyou must input a number betwen 1 and 3.\r\n"+ENDC)
    foo = input(YELLOW+"\t\tPress any key to show the menu\n"+ENDC)
    continue

