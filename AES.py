# Author: Fatih Selim YAKAR
# ID    : 161044054
# Crpytography and Computer Security Project

#implements AES(Advanced Encryption Standard) and its running modes
import os
import sys
import math


# Rijndael type AES funtions 
class AES(object):
    def __init__(self):
        # Rijndael S-box
        self.sbox =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
                    0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
                    0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
                    0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
                    0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
                    0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
                    0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
                    0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
                    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
                    0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
                    0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
                    0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
                    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
                    0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
                    0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
                    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
                    0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
                    0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
                    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
                    0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
                    0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
                    0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
                    0x54, 0xbb, 0x16]

        # Rijndael Inverted S-box
        self.invertedSBox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
                    0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
                    0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
                    0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
                    0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
                    0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
                    0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
                    0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
                    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
                    0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
                    0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
                    0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
                    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
                    0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
                    0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
                    0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
                    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
                    0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
                    0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
                    0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
                    0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
                    0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
                    0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
                    0x21, 0x0c, 0x7d]
        
        # Rijndael Rcon
        self.Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
                    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
                    0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
                    0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
                    0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
                    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
                    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
                    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
                    0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
                    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
                    0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
                    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
                    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
                    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
                    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
                    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
                    0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
                    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
                    0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
                    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
                    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
                    0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
                    0xe8, 0xcb ]

        self.keySize = dict(KEY_SIZE_128=16, KEY_SIZE_192=24, KEY_SIZE_256=32)

    #Rijndael key schedule rotate operation. Rotate a word eight bits to the left.
    def keyScheduleRotate(self, word):
        return word[1:] + word[:1]

    # Getter of Rcon table's value
    def getRconValue(self, num):
        return self.Rcon[num]

    # Getter of SBox table's value
    def getSBoxValue(self,num):
        return self.sbox[num]

    # Getter of InvertedSBox table's value
    def getInvertedSBoxValue(self,num):
        return self.invertedSBox[num]

    # Key schedule base algorithm.
    def keySchedule(self, word, iteration):
        # rotate
        word = self.keyScheduleRotate(word)
        # substitution
        for i in range(4):
            word[i] = self.getSBoxValue(word[i])
        # XOR the output
        word[0] = word[0] ^ self.getRconValue(iteration)
        return word

    # Expands an 128,192,256 key into an 176,208,240 bytes key. Applies Rijndael type key expansion.
    def expandKey(self, key, size, expandedKeySize):
        currentSize = 0
        rconIteration = 1
        expandedKey = [0] * expandedKeySize

        # set the bytes of the expanded key to the input key
        for j in range(size):
            expandedKey[j] = key[j]
        currentSize += size

        while currentSize < expandedKeySize:
            temp = expandedKey[currentSize-4:currentSize]
            # keySchedule schedule to temp
            if currentSize % size == 0:
                temp = self.keySchedule(temp, rconIteration)
                rconIteration += 1
            # If key is 256 bit then add extra sbox
            if size == self.keySize["KEY_SIZE_256"] and ((currentSize % size) == 16):
                for l in range(4): 
                    temp[l] = self.getSBoxValue(temp[l])
            # XOR temp with the block 16,24,32 bytes 
            for m in range(4):
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ \
                        temp[m]
                currentSize += 1

        return expandedKey

    # Applies XOR the round key to the table.
    def addRoundKey(self, table, roundKey):
        for i in range(16):
            table[i] ^= roundKey[i]
        return table

    # Generates a round key from the initialVector expanded key and the position within the expanded key.
    def generateRoundKey(self, expandedKey, roundKeyPointer):
        roundKey = [0] * 16
        for i in range(4):
            for j in range(4):
                roundKey[j*4+i] = expandedKey[roundKeyPointer + i*4 + j]
        return roundKey

    # Galois multiplication of characters a and b.
    def galoisMultiplication(self, a, b):
        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            bitSet = a & 0x80
            a <<= 1
            # hold it eight bit
            a &= 0xFF
            if bitSet:
                a ^= 0x1b
            b >>= 1
        return p


    # Substitutes all the values from the table with the value in the SBox table
    def substitudeBytes(self, table, isInv):
        if isInv: 
            for i in range(16): 
                table[i] = self.getInvertedSBoxValue(table[i])
        else: 
            for i in range(16): 
                table[i] = self.getSBoxValue(table[i])
        
        return table

    # Iterates over the 4 rows and  with indexed row
    def shiftRows(self, table, isInv):
        for i in range(4):
            table = self.shiftRow(table, i*4, i, isInv)
        return table

    # Each iteration shifts the row to the left
    def shiftRow(self, table, tablePointer, size, isInv):
        for i in range(size):
            if isInv:
                table[tablePointer:tablePointer+4] = \
                        table[tablePointer+3:tablePointer+4] + \
                        table[tablePointer:tablePointer+3]
            else:
                table[tablePointer:tablePointer+4] = \
                        table[tablePointer+1:tablePointer+4] + \
                        table[tablePointer:tablePointer+1]
        return table

    # Galois multiplication of the matrix
    def mixColumns(self, table, isInv):
        # For all columns
        for i in range(4):
            column = table[i:i+16:4]
            column = self.mixColumnProcess(column, isInv)
            table[i:i+16:4] = column

        return table

    # Galois multiplication of 1 column of the matrix
    def mixColumnProcess(self, column, isInv):
        columnList = list(column)
        if isInv: 
            mult = [14, 9, 13, 11]
        else: 
            mult = [2, 1, 1, 3]

        column[0] = self.galoisMultiplication(columnList[0], mult[0]) ^ self.galoisMultiplication(columnList[3], mult[1]) ^ \
                    self.galoisMultiplication(columnList[2], mult[2]) ^ self.galoisMultiplication(columnList[1], mult[3])
        column[1] = self.galoisMultiplication(columnList[1], mult[0]) ^ self.galoisMultiplication(columnList[0], mult[1]) ^ \
                    self.galoisMultiplication(columnList[3], mult[2]) ^ self.galoisMultiplication(columnList[2], mult[3])
        column[2] = self.galoisMultiplication(columnList[2], mult[0]) ^ self.galoisMultiplication(columnList[1], mult[1]) ^ \
                    self.galoisMultiplication(columnList[0], mult[2]) ^ self.galoisMultiplication(columnList[3], mult[3])
        column[3] = self.galoisMultiplication(columnList[3], mult[0]) ^ self.galoisMultiplication(columnList[2], mult[1]) ^ \
                    self.galoisMultiplication(columnList[1], mult[2]) ^ self.galoisMultiplication(columnList[0], mult[3])
        return column

    # Applies the 4 operations of the round in sequence
    def aesRound(self, table, roundKey):
        table = self.substitudeBytes(table, False)
        table = self.shiftRows(table, False)
        table = self.mixColumns(table, False)
        table = self.addRoundKey(table, roundKey)
        return table

    # Applies the 4 operations of the inverse round in sequence
    def aesInverseRound(self, table, roundKey):
        table = self.shiftRows(table, True)
        table = self.substitudeBytes(table, True)
        table = self.addRoundKey(table, roundKey)
        table = self.mixColumns(table, True)
        return table

    # Applies the initial operations, the standard round, and the other operations
    def aesMain(self, table, expandedKey, roundNumbers):
        table = self.addRoundKey(table, self.generateRoundKey(expandedKey, 0))
        i = 1
        while i < roundNumbers:
            table = self.aesRound(table,self.generateRoundKey(expandedKey, 16*i))
            i += 1
        table = self.substitudeBytes(table, False)
        table = self.shiftRows(table, False)
        table = self.addRoundKey(table,self.generateRoundKey(expandedKey, 16*roundNumbers))
        return table

    # Applies the initial operations, the standard round, and the other operations for inverse 
    def aesInverseMain(self, table, expandedKey, roundNumbers):
        table = self.addRoundKey(table,self.generateRoundKey(expandedKey, 16*roundNumbers))
        i = roundNumbers - 1
        while i > 0:
            table = self.aesInverseRound(table,self.generateRoundKey(expandedKey, 16*i))
            i -= 1
        table = self.shiftRows(table, True)
        table = self.substitudeBytes(table, True)
        table = self.addRoundKey(table, self.generateRoundKey(expandedKey, 0))
        return table

    # Encrypts a 128 bit input block by using initialVector and Key
    def encrypt(self, inputText, key, size):
        output = [0] * 16
        roundNumbers = 0
        block = [0] * 16

        if size == self.keySize["KEY_SIZE_128"]: 
            roundNumbers = 10
        elif size == self.keySize["KEY_SIZE_192"]: 
            roundNumbers = 12
        elif size == self.keySize["KEY_SIZE_256"]: 
            roundNumbers = 14
        else: 
            return None
        # the expanded keySize
        expandedKeySize = 16*(roundNumbers+1)
        # for 4x4 
        for i in range(4):
            for j in range(4):
                block[(i+(j*4))] = inputText[(i*4)+j]
        # expand the key into an 176, 208, 240 bytes key
        expandedKey = self.expandKey(key, size, expandedKeySize)
        # encrypt the block using the expandedKey
        block = self.aesMain(block, expandedKey, roundNumbers)
        # unmap the block again into the output
        for k in range(4):
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]
        return output

    # Decrypts a 128 bit input block by using initialVector and Key
    def decrypt(self, inputText, key, size):
        output = [0] * 16
        roundNumbers = 0
        block = [0] * 16

        if size == self.keySize["KEY_SIZE_128"]: 
            roundNumbers = 10
        elif size == self.keySize["KEY_SIZE_192"]: 
            roundNumbers = 12
        elif size == self.keySize["KEY_SIZE_256"]: 
            roundNumbers = 14
        else: 
            return None
        # the expanded keySize
        expandedKeySize = 16*(roundNumbers+1)
        # for 4x4
        for i in range(4):
            for j in range(4):
                block[(i+(j*4))] = inputText[(i*4)+j]
        # expand the key into an 176, 208, 240 bytes key
        expandedKey = self.expandKey(key, size, expandedKeySize)
        # decrypt the block using the expandedKey
        block = self.aesInverseMain(block, expandedKey, roundNumbers)
        # unmap the block again into the output
        for k in range(4):
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]
        return output

# Implements aes with modes OFB, CFB, CBC, ECB
class ModesOfAES(object):

    aes = AES()
    modeOfOperation = dict(ECB=0, OFB=1, CBC=2, CFB=3)

    # converts a 16 character string into array
    def convertString(self, string, start, end, mode):
        if end - start > 16: 
            end = start + 16
        if mode == self.modeOfOperation["CBC"]: 
            ar = [0] * 16
        else: 
            ar = []
        i = start
        j = 0
        while len(ar) < end - start:
            ar.append(0)
        while i < end:
            ar[j] = ord(string[i])
            j += 1
            i += 1
        return ar

    # Encrypts the plaintext using mode,hexadecimal key, size, hexadecimal initialVector parameters
    def encrypt(self, stringIn, mode, key, size, initialVector):
        # base controls
        if len(key) % size:
            return None
        if len(initialVector) % 16:
            return None
        # the AES variables
        plaintext = []
        inputText = [0] * 16
        output = []
        ciphertext = [0] * 16
        cipherOut = []
        firstRound = True

        if stringIn != None:
            for j in range(int(math.ceil(float(len(stringIn))/16))):
                start = j*16
                end = j*16+16
                if  end > len(stringIn):
                    end = len(stringIn)
                plaintext = self.convertString(stringIn, start, end, mode)
                # mode CFB
                if mode == self.modeOfOperation["CFB"]:
                    if firstRound:
                        output = self.aes.encrypt(initialVector, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(inputText, key, size)
                    for i in range(16):
                        if len(plaintext)-1 < i:
                            ciphertext[i] = 0 ^ output[i]
                        elif len(output)-1 < i:
                            ciphertext[i] = plaintext[i] ^ 0
                        elif len(plaintext)-1 < i and len(output) < i:
                            ciphertext[i] = 0 ^ 0
                        else:
                            ciphertext[i] = plaintext[i] ^ output[i]
                    for k in range(end-start):
                        cipherOut.append(ciphertext[k])
                    inputText = ciphertext
                # mode OFB
                elif mode == self.modeOfOperation["OFB"]:
                    if firstRound:
                        output = self.aes.encrypt(initialVector, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(inputText, key, size)
                    for i in range(16):
                        if len(plaintext)-1 < i:
                            ciphertext[i] = 0 ^ output[i]
                        elif len(output)-1 < i:
                            ciphertext[i] = plaintext[i] ^ 0
                        elif len(plaintext)-1 < i and len(output) < i:
                            ciphertext[i] = 0 ^ 0
                        else:
                            ciphertext[i] = plaintext[i] ^ output[i]
                    for k in range(end-start):
                        cipherOut.append(ciphertext[k])
                    inputText = output
                # mode CBC
                elif mode == self.modeOfOperation["CBC"]:
                    for i in range(16):
                        if firstRound:
                            inputText[i] =  plaintext[i] ^ initialVector[i]
                        else:
                            inputText[i] =  plaintext[i] ^ ciphertext[i]
                    firstRound = False
                    ciphertext = self.aes.encrypt(inputText, key, size)
                    # padding for CBC
                    for k in range(16):
                        cipherOut.append(ciphertext[k])
                # mode ECB(default mode)
                elif mode == self.modeOfOperation["ECB"]:
                    for i in range(16):
                        if(i>=len(plaintext)):
                            inputText[i]=0
                        else:
                            inputText[i] =  plaintext[i]
                    firstRound = False
                    ciphertext = self.aes.encrypt(inputText, key, size)
                    for k in range(16):
                        cipherOut.append(ciphertext[k])
        return mode, len(stringIn), cipherOut

    # Decrypts the cipher using mode,originalsize,hexadecimal key, size, hexadecimal initialVector parameters
    def decrypt(self, cipherIn, originalsize, mode, key, size, initialVector):
        if len(key) % size:
            return None
        if len(initialVector) % 16:
            return None
        ciphertext = []
        inputText = []
        output = []
        plaintext = [0] * 16
        charOutput = []
        firstRound = True

        if cipherIn != None:
            for j in range(int(math.ceil(float(len(cipherIn))/16))):
                start = j*16
                end = j*16+16
                if j*16+16 > len(cipherIn):
                    end = len(cipherIn)
                ciphertext = cipherIn[start:end]
                # Mode CFB
                if mode == self.modeOfOperation["CFB"]:
                    if firstRound:
                        output = self.aes.encrypt(initialVector, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(inputText, key, size)
                    for i in range(16):
                        if len(output)-1 < i:
                            plaintext[i] = 0 ^ ciphertext[i]
                        elif len(ciphertext)-1 < i:
                            plaintext[i] = output[i] ^ 0
                        elif len(output)-1 < i and len(ciphertext) < i:
                            plaintext[i] = 0 ^ 0
                        else:
                            plaintext[i] = output[i] ^ ciphertext[i]
                    for k in range(end-start):
                        charOutput.append(chr(plaintext[k]))
                    inputText = ciphertext
                # Mode OFB
                elif mode == self.modeOfOperation["OFB"]:
                    if firstRound:
                        output = self.aes.encrypt(initialVector, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(inputText, key, size)
                    for i in range(16):
                        if len(output)-1 < i:
                            plaintext[i] = 0 ^ ciphertext[i]
                        elif len(ciphertext)-1 < i:
                            plaintext[i] = output[i] ^ 0
                        elif len(output)-1 < i and len(ciphertext) < i:
                            plaintext[i] = 0 ^ 0
                        else:
                            plaintext[i] = output[i] ^ ciphertext[i]
                    for k in range(end-start):
                        charOutput.append(chr(plaintext[k]))
                    inputText = output
                # Mode CBC
                elif mode == self.modeOfOperation["CBC"]:
                    output = self.aes.decrypt(ciphertext, key, size)
                    for i in range(16):
                        if firstRound:
                            plaintext[i] = initialVector[i] ^ output[i]
                        else:
                            plaintext[i] = inputText[i] ^ output[i]
                    firstRound = False
                    if originalsize is not None and originalsize < end:
                        for k in range(originalsize-start):
                            charOutput.append(chr(plaintext[k]))
                    else:
                        for k in range(end-start):
                            charOutput.append(chr(plaintext[k]))
                    inputText = ciphertext
                # Mode ECB
                elif mode == self.modeOfOperation["ECB"]:
                    cipheredText=[]
                    for i in range(16):
                        if i>=len(ciphertext):
                            cipheredText.append(0)
                        else:
                            cipheredText.append(ciphertext[i])
                    plaintext = self.aes.decrypt(cipheredText, key, size)  
                    firstRound = False
                    for k in range(16):
                        charOutput.append(chr(plaintext[k]))
                    inputText = cipheredText
        return "".join(charOutput)


# Global functions and test functions that runs the AES algoritm


# Returns stripped string with PKCS#7 padding
def stripPadding(s):
    if len(s)%16 or not s:
        raise ValueError("String length must be multiple of 16 ")
    numpads = ord(s[-1])
    if numpads > 16:
        raise ValueError("String ending is invalid: %r for padding" % s[-1])
    return s[:-numpads]

# Returns string padded with PKCS#7 padding
def appendPadding(string):
    numpads = 16 - (len(string)%16)
    return string + numpads*chr(numpads)

# Encrypts data parameter using the key parameter. Also key must be string of bytes. Then returns encrypted cipher string 
def encryptData(key, data, mode=ModesOfAES.modeOfOperation["ECB"]):
    key = map(ord, key)
    if mode == ModesOfAES.modeOfOperation["CBC"]:
        data = appendPadding(data)
    keysize = len(key)
    aes=AES()
    assert keysize in aes.keySize.values(), 'invalid key size: %s' % keysize
    # create a random initialVector 
    initialVector = [ord(i) for i in os.urandom(16)]
    moo = ModesOfAES()
    (mode, length, ciph) = moo.encrypt(data, mode, key, keysize, initialVector)
    # Stores the original message length. Prepend the initialVector.
    return ''.join(map(chr, initialVector)) + ''.join(map(chr, ciph))

# Decrypts data parameter using the key parameter. Also key must be string of bytes. Then returns encrypted plaintext string 
def decryptData(key, data, mode=ModesOfAES.modeOfOperation["ECB"]):
    key = map(ord, key)
    keysize = len(key)
    aes=AES()
    assert keysize in aes.keySize.values(), 'invalid key size: %s' % keysize
    # initialVector is first 16 bytes
    initialVector = map(ord, data[:16])
    data = map(ord, data[16:])
    moo = ModesOfAES()
    decr = moo.decrypt(data, None, mode, key, keysize, initialVector)
    if mode == ModesOfAES.modeOfOperation["CBC"]:
        decr = stripPadding(decr)
    return decr

# generates a key from random data of length keySize. The returned key is a string of bytes.  
def generateRandomKey(keySize):
    if keySize not in (16, 24, 32):
        emsg = 'Invalid key size, %s. It can be 16, 24, 32.'
        raise ValueError, emsg % keySize
    return os.urandom(keySize)

# run Aes Algorithm for demostration
def runAESDemo(plaintext, keysize=16, modeName = "ECB"):
    print 'Mod:', modeName
    print 'Anahtar boyutu:', keysize
    print 'Sifrelenmemis metin:', plaintext
    key =  generateRandomKey(keysize)
    print 'Rastgele Anahtar:', [ord(x) for x in key]
    mode = ModesOfAES.modeOfOperation[modeName]
    cipher = encryptData(key, plaintext, mode)
    print 'Sifrelenmis Metin:', [ord(x) for x in cipher]
    decr = decryptData(key, cipher, mode)
    print 'Desifrelenmis Metin:', decr
    print ''

def runForAllCombination(plaintext):
    runAESDemo(plaintext,16,"ECB")
    runAESDemo(plaintext,16,"CBC")
    runAESDemo(plaintext,16,"OFB")
    runAESDemo(plaintext,16,"CFB")
    runAESDemo(plaintext,24,"ECB")
    runAESDemo(plaintext,24,"CBC")
    runAESDemo(plaintext,24,"OFB")
    runAESDemo(plaintext,24,"CFB")
    runAESDemo(plaintext,32,"ECB")
    runAESDemo(plaintext,32,"CBC")
    runAESDemo(plaintext,32,"OFB")
    runAESDemo(plaintext,32,"CFB")

# run aes algorithm for encrypt
def runAesEncrypt(plaintext,key,modeName = "ECB"):
    mode = ModesOfAES.modeOfOperation[modeName]
    cipher = encryptData(key, plaintext, mode)

    return cipher

# run aes algorithm for decrypt
def runAesDecrypt(ciphertext,key,modeName = "ECB"):
    mode = ModesOfAES.modeOfOperation[modeName]
    plaintext = decryptData(key, ciphertext, mode)

    return plaintext
    

if __name__ == "__main__":
    runForAllCombination("Merhaba, bu sifrelencek metin")



    



