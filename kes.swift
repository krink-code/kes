
import Foundation

func xorEncrypt(plainText: String, keyStr: String) -> String {
    let plaintextBytes = Array(plainText.utf8)
    let keyBytes = Array(keyStr.utf8)
    var encryptedData = [UInt8](repeating: 0, count: plaintextBytes.count)

    for i in 0..<plaintextBytes.count {
        let keyByte = keyBytes[i % keyBytes.count]
        encryptedData[i] = plaintextBytes[i] ^ keyByte
    }

    let data = Data(encryptedData)
    return data.base64EncodedString()
}

func xorDecrypt(base64Cipher: String, keyStr: String) -> String {
    guard let cipherData = Data(base64Encoded: base64Cipher) else {
        return ""
    }

    let cipherBytes = Array(cipherData)
    let keyBytes = Array(keyStr.utf8)
    var decryptedData = [UInt8](repeating: 0, count: cipherBytes.count)

    for i in 0..<cipherBytes.count {
        let keyByte = keyBytes[i % keyBytes.count]
        decryptedData[i] = cipherBytes[i] ^ keyByte
    }

    return String(bytes: decryptedData, encoding: .utf8) ?? ""
}

func vigenereEncrypt(plainText: String, keyStr: String) -> String {
    let plaintextBytes = Array(plainText.utf8)
    let keyBytes = Array(keyStr.utf8)
    var encryptedData = [UInt8](repeating: 0, count: plaintextBytes.count)

    for i in 0..<plaintextBytes.count {
        let keyByte = keyBytes[i % keyBytes.count]
        encryptedData[i] = plaintextBytes[i] &+ keyByte
    }

    let hexString = encryptedData.map { String(format: "%02x", $0) }.joined()
    return hexString
}

func vigenereDecrypt(hexCipher: String, keyStr: String) -> String {
    let hexCipherBytes = stride(from: 0, to: hexCipher.count, by: 2).compactMap {
        UInt8(hexCipher[hexCipher.index(hexCipher.startIndex, offsetBy: $0)..<hexCipher.index(hexCipher.startIndex, offsetBy: $0 + 2)], radix: 16)
    }

    let keyBytes = Array(keyStr.utf8)
    var decryptedData = [UInt8](repeating: 0, count: hexCipherBytes.count)

    for i in 0..<hexCipherBytes.count {
        let keyByte = keyBytes[i % keyBytes.count]
        decryptedData[i] = UInt8((Int(hexCipherBytes[i]) - Int(keyByte) + 256) % 256)
    }

    return String(bytes: decryptedData, encoding: .utf8) ?? ""
}



func encryptRailFence(plainText: String, numRails: Int) -> String {
    var rails = Array(repeating: [Character](), count: numRails)
    var railIndex = 0
    var direction = 1

    for char in plainText {
        rails[railIndex].append(char)

        if railIndex == 0 {
            direction = 1
        } else if railIndex == numRails - 1 {
            direction = -1
        }

        railIndex += direction
    }

    let cipherText = rails.joined().map(String.init).joined()
    return Data(cipherText.utf8).base64EncodedString()
}

func decryptRailFence(base64Cipher: String, numRails: Int) -> String {
    guard let cipherData = Data(base64Encoded: base64Cipher),
          let cipherText = String(data: cipherData, encoding: .utf8) else {
        return ""
    }

    var rails = Array(repeating: Array(repeating: Character(" "), count: cipherText.count), count: numRails)
    var railIndex = 0
    var direction = 1
    var currentIndex = 0

    for i in 0..<cipherText.count {
        rails[railIndex][i] = "*"

        if railIndex == 0 {
            direction = 1
        } else if railIndex == numRails - 1 {
            direction = -1
        }

        railIndex += direction
    }

    for i in 0..<numRails {
        for j in 0..<cipherText.count {
            if rails[i][j] == "*" && currentIndex < cipherText.count {
                let charIndex = cipherText.index(cipherText.startIndex, offsetBy: currentIndex)
                rails[i][j] = Character(extendedGraphemeClusterLiteral: cipherText[charIndex])
                currentIndex += 1
            }
        }
    }

    railIndex = 0
    direction = 1
    var plainText = ""

    for i in 0..<cipherText.count {
        plainText.append(rails[railIndex][i])

        if railIndex == 0 {
            direction = 1
        } else if railIndex == numRails - 1 {
            direction = -1
        }

        railIndex += direction
    }

    return plainText
}




func encryptKES(plainText: String, keyStr: String) -> String {
    var order = 0

    for char in keyStr.utf8 {
        order += Int(char)
    }
    order %= 2

    let railFenceEncrypted = encryptRailFence(plainText: plainText, numRails: keyStr.count)

    if order == 0 {
        let xorEncrypted = xorEncrypt(plainText: railFenceEncrypted, keyStr: keyStr)
        let encrypted = vigenereEncrypt(plainText: xorEncrypted, keyStr: keyStr)
        return Data(encrypted.utf8).base64EncodedString()
    }

    let vigenereEncrypted = vigenereEncrypt(plainText: railFenceEncrypted, keyStr: keyStr)
    let xorEncrypted = xorEncrypt(plainText: vigenereEncrypted, keyStr: keyStr)

    return Data(xorEncrypted.utf8).base64EncodedString()
}

func decryptKES(base64Cipher: String, keyStr: String) -> String {
    guard let base64DecodedData = Data(base64Encoded: base64Cipher) else {
        return ""
    }

    var order = 0

    for char in keyStr.utf8 {
        order += Int(char)
    }
    order %= 2

    var decrypted = ""

    if order == 0 {
        let decodedXor = xorDecrypt(base64Cipher: String(data: base64DecodedData, encoding: .utf8) ?? "", keyStr: keyStr)
        let decodedVigenere = vigenereDecrypt(hexCipher: decodedXor, keyStr: keyStr)
        decrypted = decryptRailFence(base64Cipher: decodedVigenere, numRails: keyStr.count)
    } else {
        let decodedXor = xorDecrypt(base64Cipher: String(data: base64DecodedData, encoding: .utf8) ?? "", keyStr: keyStr)
        let decodedVigenere = vigenereDecrypt(hexCipher: decodedXor, keyStr: keyStr)
        decrypted = decryptRailFence(base64Cipher: decodedVigenere, numRails: keyStr.count)
    }

    return decrypted
}

let encryptionKey = "KEY321"
let plaintext = "Hello, World! KES"

print("Original Data:", plaintext)

print("XOR")
let encryptedData = xorEncrypt(plainText: plaintext, keyStr: encryptionKey)
print("Encrypted Data:", encryptedData)
let decryptedData = xorDecrypt(base64Cipher: encryptedData, keyStr: encryptionKey)
print("Decrypted Data:", decryptedData)

print("VIGENERE")
let encryptedDataVigenere = vigenereEncrypt(plainText: plaintext, keyStr: encryptionKey)
print("Encrypted Data:", encryptedDataVigenere)
let decryptedDataVigenere = vigenereDecrypt(hexCipher: encryptedDataVigenere, keyStr: encryptionKey)
print("Decrypted Data:", decryptedDataVigenere)

print("RAILFENCE")
let encryptedDataRailFence = encryptRailFence(plainText: plaintext, numRails: encryptionKey.count)
print("Encrypted Data:", encryptedDataRailFence)
let decryptedDataRailFence = decryptRailFence(base64Cipher: encryptedDataRailFence, numRails: encryptionKey.count)
print("Decrypted Data:", decryptedDataRailFence)

print("KES")
let encryptedDataKES = encryptKES(plainText: plaintext, keyStr: encryptionKey)
print("Encrypted Data:", encryptedDataKES)
let decryptedDataKES = decryptKES(base64Cipher: encryptedDataKES, keyStr: encryptionKey)
print("Decrypted Data:", decryptedDataKES)


