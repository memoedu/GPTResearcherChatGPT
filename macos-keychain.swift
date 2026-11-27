import CryptoKit
import Foundation
import Security

enum KeychainError: Error {
    case invalidArguments
    case status(OSStatus)
    case locked
    case invalidKey
    case missingKey
    case invalidCiphertext
}

let service = "org.memoedu.gpt-researcher.chatgpt"

func requireSuccess(_ status: OSStatus) throws {
    guard status == errSecSuccess else { throw KeychainError.status(status) }
}

func defaultUnlockedKeychain() throws -> SecKeychain {
    try requireSuccess(SecKeychainSetUserInteractionAllowed(false))
    var keychain: SecKeychain?
    try requireSuccess(SecKeychainCopyDefault(&keychain))
    guard let keychain else { throw KeychainError.status(errSecNoDefaultKeychain) }
    var state: SecKeychainStatus = 0
    try requireSuccess(SecKeychainGetStatus(keychain, &state))
    guard state & SecKeychainStatus(kSecUnlockStateStatus) != 0 else { throw KeychainError.locked }
    return keychain
}

func loadKey(_ attributes: [String: Any], in keychain: SecKeychain) throws -> SymmetricKey? {
    var query = attributes
    query[kSecMatchSearchList as String] = [keychain]
    query[kSecReturnData as String] = true
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return nil }
    try requireSuccess(status)
    guard let data = result as? Data, data.count == 32 else { throw KeychainError.invalidKey }
    return SymmetricKey(data: data)
}

func createKey(_ attributes: [String: Any], in keychain: SecKeychain) throws -> SymmetricKey {
    let key = SymmetricKey(size: .bits256)
    var item = attributes
    item[kSecUseKeychain as String] = keychain
    item[kSecValueData as String] = key.withUnsafeBytes { Data($0) }
    let status = SecItemAdd(item as CFDictionary, nil)
    if status == errSecDuplicateItem {
        guard let existing = try loadKey(attributes, in: keychain) else { throw KeychainError.missingKey }
        return existing
    }
    try requireSuccess(status)
    return key
}

func main() throws {
    let arguments = CommandLine.arguments.dropFirst()
    guard let operation = arguments.first, (1...2).contains(arguments.count) else {
        throw KeychainError.invalidArguments
    }
    var account = "credential-encryption-v1"
    if let canary = arguments.dropFirst().first {
        guard let id = UUID(uuidString: canary) else { throw KeychainError.invalidArguments }
        account = "canary-\(id.uuidString.lowercased())"
    }
    let keychain = try defaultUnlockedKeychain()
    let attributes: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    let key = try loadKey(attributes, in: keychain)
    switch operation {
    case "check":
        return
    case "encrypt":
        let plaintext = FileHandle.standardInput.readDataToEndOfFile()
        let box = try AES.GCM.seal(plaintext, using: key ?? createKey(attributes, in: keychain))
        guard let ciphertext = box.combined else { throw KeychainError.invalidCiphertext }
        try FileHandle.standardOutput.write(contentsOf: ciphertext)
    case "decrypt":
        guard let key else { throw KeychainError.missingKey }
        let ciphertext = FileHandle.standardInput.readDataToEndOfFile()
        let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: ciphertext), using: key)
        try FileHandle.standardOutput.write(contentsOf: plaintext)
    default:
        throw KeychainError.invalidArguments
    }
}

do {
    try main()
} catch KeychainError.status(let status) {
    FileHandle.standardError.write(Data("Keychain operation failed (OSStatus \(status)).\n".utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("Keychain operation failed.\n".utf8))
    exit(1)
}
