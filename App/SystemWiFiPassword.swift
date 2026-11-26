import Foundation
import Security

/// Reads the Wi-Fi password iOS itself saved when joining a network, from the system keychain
/// (class: generic password, account = SSID).
///
/// Stock-signed builds cannot see those items: access requires the `apple-isc-keychain`
/// keychain-access-group, which the TrollStore IPA build grants via ldid entitlements.
/// Returns nil whenever the group is missing or the network was never joined — callers
/// fall back to manual entry.
enum SystemWiFiPassword {
    struct Probe {
        let service: String
        let status: OSStatus
        let password: String?
    }
    /// iOS and macOS have used both spellings for this service across versions.
    static let services = ["AirPort network password", "AirPort"]

    static func probes(forSSID ssid: String) -> [Probe] {
        guard !ssid.isEmpty else { return [] }
        return services.map { service in
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: ssid,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecReturnData as String: true,
            ]
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            let password = status == errSecSuccess ? (result as? Data).flatMap { String(data: $0, encoding: .utf8) } : nil
            return Probe(service: service, status: status, password: password)
        }
    }

    static func password(forSSID ssid: String) -> String? {
        probes(forSSID: ssid).compactMap { $0.password }.first { !$0.isEmpty }
    }
}
