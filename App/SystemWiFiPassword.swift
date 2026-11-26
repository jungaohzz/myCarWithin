import Foundation
import Security

/// Reads the Wi-Fi password iOS itself saved when joining a network, from the system keychain
/// (class: generic password, service "AirPort network password", account = SSID).
///
/// Stock-signed builds cannot see those items: access requires the `apple-isc-keychain`
/// keychain-access-group, which the TrollStore IPA build grants via ldid entitlements.
/// Returns nil whenever the group is missing or the network was never joined — callers
/// fall back to manual entry.
enum SystemWiFiPassword {
    static func password(forSSID ssid: String) -> String? {
        guard !ssid.isEmpty else { return nil }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "AirPort network password",
            kSecAttrAccount as String: ssid,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
