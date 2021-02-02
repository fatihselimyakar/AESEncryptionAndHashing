# Author: Fatih Selim YAKAR
# ID    : 161044054
# Crpytography and Computer Security Project

#implements hash technique, integrity control technique and encription using written AES
import AES
import time

class hashAndControl(object):
    # Controls if n is a power of 2
    def isPowerOf2(self,n):
        return (n & (n - 1) == 0) and n != 0

    # Expands state string to power of 2
    def expand16xbit(self,state):
        counter=0
        if(type(state)== str):
            while((self.isPowerOf2(len(state))==False) or len(state)<16):
                state+=chr(counter)
                counter+=1
                counter%=256
        else:
            while((self.isPowerOf2(len(state))==False) or len(state)<16):
                state.append(counter)
                counter+=1
                counter%=256

        return state
        

    # It expands the string that comes as a parameter, divides it into half and converts it to 16 digits by xor.
    def hashFunction(self,state):
        state = self.expand16xbit(state)
        #print state
        if(len(state)==16):
            return state

        size=len(state)/2
        newState=[-1]*size

        counter=0
        while(size>=16):
            if(counter==0):
                for i in range(size):
                    if(type(state)==str):
                        newState[i]=ord(state[i])^ord(state[i+size])
                    else:
                        newState[i]=state[i]^state[i+size]
            else:
                for i in range(size):
                    newState[i]=newState[i]^newState[i+size]
            counter+=1
            size/=2
        return newState[0:16]
        
    # It hashes,encrypts then writes the end of the file
    def hashAndEncrypt(self,fileName,key):
        f=open(fileName,"rb")
        willHash = f.read()
        hashedList = self.hashFunction(willHash)
        print "Ozetlenmis metin:",hashedList
        f.close()

        with open(fileName,"a") as fh:
            fh.seek(0,2)
            hashed = ' '.join([str(elem) for elem in hashedList])
            cipher=AES.runAesEncrypt(hashed,key,"ECB")
            cipherReadable=[ord(x) for x in cipher]
            toWrite=' '.join([str(elem) for elem in cipherReadable])
            print "Sifrelenmis metin:",toWrite
            fh.write(toWrite)
            
        fh.close()   
        
        return hashedList,len(toWrite)

    # Controls the integrity of the file, if changed then returns true, else returns false
    def controlChange(self,fileName,key,size):
        f=open(fileName,"rb")
        f.seek(-size,2)
        fileString = f.read()

        lst = list(fileString.split(" ")) 
        cipherText=""
        for i in range(0,len(lst)):
            lst[i]=int(lst[i])
            cipherText+=chr(lst[i])

        plaintext=AES.runAesDecrypt(cipherText,key,"ECB")
        
        f.seek(0,0)
        fileString=f.read()
        willHash=""
        for i in range(len(fileString)-(size-1)):
            willHash+=fileString[i]

        hashedList = self.hashFunction(willHash[0:len(willHash)-1])
        hashedString = ' '.join([str(elem) for elem in hashedList])

        f.close()

        print "Ana metinden olusturulmus ozet metin:",hashedString
        print "Desifre edilmis ozet metin:",plaintext

        for i in range(len(hashedString)):
            if hashedString[i]!=plaintext[i]:
                return True

        return False

    # It changes the file for the test
    def changeTheFile(self,fileName):
        f = open(fileName, "r")
        contents = f.readlines()
        f.close()

        contents.insert(0, "buraya ekleme yapildi")

        f = open(fileName, "w")
        contents = "".join(contents)
        f.write(contents)
        f.close()

# it tests the changed situation
def testChange(fileName):
    print "Dosya ismi:",fileName
    hash=hashAndControl()
    key=AES.generateRandomKey(32)
    print "Anahtar:",[ord(elem) for elem in key]
    print "**Ozetleme,sifreleme ve dosyaya yazma islemi**"
    fileHash,length = hash.hashAndEncrypt(fileName,key)
    hash.changeTheFile(fileName)
    print "**Dosya degistirildi**"
    print "**Kontrol islemi:"
    retVal=hash.controlChange(fileName,key,length)
    print "Dosya Butunlugu Degisti mi?:",retVal

# it tests the unchanged situation
def testNotChange(fileName):
    print "Dosya ismi:",fileName
    hash=hashAndControl()
    key=AES.generateRandomKey(32)
    print "Anahtar:",[ord(elem) for elem in key]
    print "**Ozetleme,sifreleme ve dosyaya yazma islemi**"
    fileHash,length = hash.hashAndEncrypt(fileName,key)
    print "**Dosya degistirilmedi**"
    print "**Kontrol islemi**:"
    retVal=hash.controlChange(fileName,key,length)
    print "Dosya Butunlugu Degisti mi?:",retVal

if __name__ == "__main__":

    fileName="sample.txt"
    testChange(fileName)
    print ""
    testNotChange(fileName)
    





