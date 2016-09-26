import random

def shuffleString(s):
    strList = list(s)
    random.shuffle(strList)
    return ''.join(strList)

def getAlphabet():
    alphabet = ''
    
    for code in range(ord('a'), ord('z') + 1):
        alphabet += chr(code)

    for code in range(ord('A'), ord('Z') + 1):
        alphabet += chr(code)

    for code in range(ord('0'), ord('9') + 1):
        alphabet += chr(code)
        
    alphabet += ' -'
    
    return alphabet

def letter2Index(ch):
    alphabet = getAlphabet()
    index = alphabet.find(ch)
    if index < 0:
        index = len(alphabet) - 1
        
    return index

def index2Letter(index):
    alphabet = getAlphabet()
    if index >= len(alphabet) or index < 0:
        # invalid. Index is too big or too small
        letter = '-'
    
    else:
        letter = alphabet[index]
        
    return letter

def removeDups(s):
    newString = ''
    for ch in s:
        if ch not in newString:
            newString += ch
            
    return newString

def removeMatches(myString, removeString):
    newString = ''
    for ch in myString:
        if ch not in removeString:
            newString += ch
    
    return newString
    

def genKeyFromPassword(password):
    alphabet = getAlphabet()
    password = removeDups(password)
    lastChar = password[-1]
    lastCharIndex = letter2Index(lastChar)
    
    beforeString = alphabet[:lastCharIndex]
    afterString = alphabet[lastCharIndex + 1:]
    
    beforeString = removeMatches(beforeString, password)
    afterString = removeMatches(afterString, password)
    
    key = password + afterString + beforeString
    
    return key
    

def subEncrypt(plainText, key):
    alphabet = getAlphabet()
    cipherText = ''
    
    for ch in plainText:
        i = letter2Index(ch)
        cipherText += key[i]
        
    return cipherText

def subDecrypt(cipherText, key):
    alphabet = getAlphabet()
    plainText = ''
    
    for ch in cipherText:
        i = key.index(ch)
        plainText += alphabet[i]
    
    return plainText

def main():
    message = input('Enter Message: ')
    print(message)
    
    password = input('Enter a password: ')
    
    key = genKeyFromPassword(password)
    
    enc = subEncrypt(message, key)
    print(enc)
    
    password = input('Enter password to decrypt: ')
    key = genKeyFromPassword(password)
    
    dec = subDecrypt(enc, key)
    print(dec)

main()
