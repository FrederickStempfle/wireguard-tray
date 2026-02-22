import AppKit
import Foundation

private struct WireGuardSnapshot {
    let connectedDisplayNames: [String]
    let connectedWgInterfaces: [String]
    let connectedScutilServices: [String]
    let availableScutilServices: [String]
    let availableWgQuickTunnels: [String]

    var isConnected: Bool {
        !connectedDisplayNames.isEmpty
    }

    var hasAvailableTarget: Bool {
        !availableScutilServices.isEmpty || !availableWgQuickTunnels.isEmpty
    }

    var primaryConnectedName: String? {
        connectedDisplayNames.first
    }

    static let empty = WireGuardSnapshot(
        connectedDisplayNames: [],
        connectedWgInterfaces: [],
        connectedScutilServices: [],
        availableScutilServices: [],
        availableWgQuickTunnels: []
    )
}

private enum ActionOutcome {
    case success(String)
    case failure(String)

    var message: String {
        switch self {
        case .success(let text), .failure(let text):
            return text
        }
    }

    var succeeded: Bool {
        if case .success = self {
            return true
        }

        return false
    }
}

private func isUtunInterfaceName(_ name: String) -> Bool {
    let lower = name.lowercased()
    guard lower.hasPrefix("utun") else {
        return false
    }

    return lower.dropFirst(4).allSatisfy(\.isNumber)
}

private enum Shell {
    static func run(_ command: [String]) -> (exitCode: Int32, stdout: String, stderr: String)? {
        guard let executable = command.first else {
            return nil
        }

        let process = Process()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()

        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        if executable.contains("/") {
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = Array(command.dropFirst())
        } else {
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = command
        }

        do {
            try process.run()
        } catch {
            return nil
        }

        process.waitUntilExit()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        return (
            exitCode: process.terminationStatus,
            stdout: String(decoding: stdoutData, as: UTF8.self),
            stderr: String(decoding: stderrData, as: UTF8.self)
        )
    }
}

private final class WireGuardStatusMonitor {
    private let wgCommands: [String] = [
        "/opt/homebrew/bin/wg",
        "/usr/local/bin/wg",
        "/usr/bin/wg",
        "wg"
    ]

    private let wgQuickCommands: [String] = [
        "/opt/homebrew/bin/wg-quick",
        "/usr/local/bin/wg-quick",
        "/usr/bin/wg-quick",
        "wg-quick"
    ]

    private let modernBashCommands: [String] = [
        "/opt/homebrew/bin/bash",
        "/usr/local/bin/bash",
        "bash"
    ]

    private let wgConfigDirectories: [String] = [
        "/etc/wireguard",
        "/opt/homebrew/etc/wireguard",
        "/usr/local/etc/wireguard"
    ]

    private let configCacheTTL: TimeInterval = 30
    private var cachedWgQuickConfigs: [String] = []
    private var lastConfigScanDate: Date = .distantPast

    private lazy var wgExecutable = resolveExecutable(candidates: wgCommands)
    private lazy var wgQuickExecutable = resolveExecutable(candidates: wgQuickCommands)
    private lazy var modernBashExecutable = resolveModernBashExecutable()

    func snapshot(refreshConfigCache: Bool = false) -> WireGuardSnapshot {
        let wgConnected = connectedViaWg()
        let scutilServices = listScutilServices()
        let scutilConnected = scutilServices
            .filter { isConnectedScutilStatus($0.status) }
            .map(\.name)

        let availableScutil = scutilServices.map(\.name)
        let wgQuickConfigs = listWgQuickConfigNames(forceRefresh: refreshConfigCache)
        let wgDisplayNames = displayNamesForWgInterfaces(wgConnected, availableConfigs: wgQuickConfigs)

        return WireGuardSnapshot(
            connectedDisplayNames: dedupe(scutilConnected + wgDisplayNames),
            connectedWgInterfaces: dedupe(wgConnected),
            connectedScutilServices: dedupe(scutilConnected),
            availableScutilServices: dedupe(availableScutil),
            availableWgQuickTunnels: dedupe(wgQuickConfigs)
        )
    }

    func connect(preferredName: String?) -> ActionOutcome {
        let current = snapshot(refreshConfigCache: true)

        if current.isConnected {
            return .success("Already connected")
        }

        var errors: [String] = []
        let scutilCandidates = prioritized(current.availableScutilServices, preferred: preferredName)

        for service in scutilCandidates {
            guard let result = Shell.run(["scutil", "--nc", "start", service]) else {
                continue
            }

            if result.exitCode == 0 {
                return .success("Started \(service)")
            }

            errors.append("scutil start failed for \(service)")
        }

        let wgQuickCandidates = prioritized(current.availableWgQuickTunnels, preferred: preferredName)
        for tunnel in wgQuickCandidates {
            let outcome = runWgQuick(action: "up", tunnel: tunnel)
            if outcome.succeeded {
                return .success("Started \(tunnel)")
            }

            errors.append(outcome.message)
        }

        if errors.isEmpty {
            return .failure("No WireGuard profile found to start")
        }

        return .failure("Could not connect. \(errors[0])")
    }

    func disconnect() -> ActionOutcome {
        let current = snapshot(refreshConfigCache: true)

        if !current.isConnected {
            return .success("Already disconnected")
        }

        var errors: [String] = []

        for service in current.connectedScutilServices {
            guard let result = Shell.run(["scutil", "--nc", "stop", service]) else {
                errors.append("Could not run scutil stop for \(service)")
                continue
            }

            if result.exitCode != 0 {
                errors.append("scutil stop failed for \(service)")
            }
        }

        let afterScutilStop = snapshot()
        if !afterScutilStop.isConnected {
            return .success("Disconnected")
        }

        let candidates = wgQuickDisconnectCandidates(from: afterScutilStop)
        for tunnel in candidates {
            let outcome = runWgQuick(action: "down", tunnel: tunnel)
            if outcome.succeeded {
                if !snapshot().isConnected {
                    return .success("Disconnected")
                }
            } else {
                errors.append(outcome.message)
            }
        }

        let after = snapshot()
        if !after.isConnected {
            return .success("Disconnected")
        }

        if let firstError = errors.first {
            return .failure("Disconnect incomplete. \(firstError)")
        }

        return .failure("Disconnect incomplete. A tunnel is still active")
    }

    private func connectedViaWg() -> [String] {
        guard let wgExecutable else {
            return []
        }

        guard let result = Shell.run([wgExecutable, "show", "interfaces"]), result.exitCode == 0 else {
            return []
        }

        return result.stdout
            .split(whereSeparator: { $0.isWhitespace })
            .map(String.init)
            .filter { !$0.isEmpty }
    }

    private func listScutilServices() -> [(name: String, status: String)] {
        guard let result = Shell.run(["scutil", "--nc", "list"]), result.exitCode == 0 else {
            return []
        }

        var services: [(name: String, status: String)] = []

        for rawLine in result.stdout.split(separator: "\n") {
            let line = String(rawLine)

            guard let name = extractQuotedValue(from: line), isWireGuardName(name) else {
                continue
            }

            let status = extractParenthesizedValue(from: line) ?? "unknown"
            services.append((name: name, status: status.lowercased()))
        }

        return services
    }

    private func isConnectedScutilStatus(_ status: String) -> Bool {
        status == "connected" || status == "connecting"
    }

    private func listWgQuickConfigNames(forceRefresh: Bool) -> [String] {
        let now = Date()
        if !forceRefresh, now.timeIntervalSince(lastConfigScanDate) < configCacheTTL {
            return cachedWgQuickConfigs
        }

        let fileManager = FileManager.default
        var names: [String] = []

        for directory in wgConfigDirectories {
            guard let files = try? fileManager.contentsOfDirectory(atPath: directory) else {
                continue
            }

            for file in files where file.hasSuffix(".conf") {
                let name = String(file.dropLast(5))
                if !name.isEmpty {
                    names.append(name)
                }
            }
        }

        cachedWgQuickConfigs = dedupe(names)
        lastConfigScanDate = now
        return cachedWgQuickConfigs
    }

    private func runWgQuick(action: String, tunnel: String) -> ActionOutcome {
        guard let wgQuickExecutable else {
            return .failure("wg-quick command not found")
        }

        let command: [String]
        if let modernBash = modernBashExecutable {
            command = [modernBash, wgQuickExecutable, action, tunnel]
        } else {
            command = [wgQuickExecutable, action, tunnel]
        }

        if let result = Shell.run(command), result.exitCode == 0 {
            return .success("wg-quick \(action) \(tunnel)")
        }

        if runCommandAsAdmin(command) {
            return .success("wg-quick \(action) \(tunnel)")
        }

        if modernBashExecutable == nil {
            return .failure("wg-quick failed for \(tunnel). Install bash 4+ and retry")
        }

        return .failure("wg-quick \(action) failed for \(tunnel)")
    }

    private func prioritized(_ items: [String], preferred: String?) -> [String] {
        guard let preferred, !preferred.isEmpty else {
            return items
        }

        var ordered = items.filter { $0.caseInsensitiveCompare(preferred) == .orderedSame }
        ordered.append(contentsOf: items.filter { $0.caseInsensitiveCompare(preferred) != .orderedSame })
        return ordered
    }

    private func isWireGuardName(_ value: String) -> Bool {
        let lower = value.lowercased()
        return lower.contains("wireguard") || lower == "wg" || lower.hasPrefix("wg ") || lower.hasPrefix("wg-")
    }

    private func displayNamesForWgInterfaces(_ interfaces: [String], availableConfigs: [String]) -> [String] {
        if interfaces.isEmpty {
            return []
        }

        let nonUtun = interfaces.filter { !isUtunInterfaceName($0) }
        if !nonUtun.isEmpty {
            return nonUtun
        }

        if availableConfigs.count == 1, let onlyConfig = availableConfigs.first {
            return [onlyConfig]
        }

        return interfaces
    }

    private func wgQuickDisconnectCandidates(from snapshot: WireGuardSnapshot) -> [String] {
        var candidates = snapshot.connectedWgInterfaces.filter { !isUtunInterfaceName($0) }

        if let inferred = inferredConfigName(from: snapshot) {
            candidates.append(inferred)
        }

        candidates.append(contentsOf: snapshot.availableWgQuickTunnels)
        return dedupe(candidates)
    }

    private func inferredConfigName(from snapshot: WireGuardSnapshot) -> String? {
        if snapshot.availableWgQuickTunnels.count == 1 {
            return snapshot.availableWgQuickTunnels.first
        }

        for displayName in snapshot.connectedDisplayNames where !isUtunInterfaceName(displayName) {
            if snapshot.availableWgQuickTunnels.contains(where: { $0.caseInsensitiveCompare(displayName) == .orderedSame }) {
                return displayName
            }
        }

        return nil
    }

    private func resolveExecutable(candidates: [String]) -> String? {
        let fileManager = FileManager.default

        for command in candidates {
            if command.contains("/") {
                if fileManager.isExecutableFile(atPath: command) {
                    return command
                }
            } else if let resolved = resolveFromPath(command: command) {
                return resolved
            }
        }

        return nil
    }

    private func resolveModernBashExecutable() -> String? {
        let fileManager = FileManager.default

        for command in modernBashCommands {
            if command.contains("/") {
                if fileManager.isExecutableFile(atPath: command), isModernBash(command) {
                    return command
                }
            } else if let resolved = resolveFromPath(command: command), isModernBash(resolved) {
                return resolved
            }
        }

        return nil
    }

    private func isModernBash(_ executable: String) -> Bool {
        guard let result = Shell.run([executable, "--version"]), result.exitCode == 0 else {
            return false
        }

        guard let firstLine = result.stdout.split(separator: "\n").first else {
            return false
        }

        let line = firstLine.lowercased()
        if let versionIndex = line.range(of: "version ")?.upperBound {
            let versionText = line[versionIndex...]
            let majorText = versionText.split(separator: ".").first ?? ""
            if let major = Int(majorText) {
                return major >= 4
            }
        }

        return false
    }

    private func resolveFromPath(command: String) -> String? {
        guard let result = Shell.run(["which", command]), result.exitCode == 0 else {
            return nil
        }

        let resolved = result.stdout
            .split(whereSeparator: \.isNewline)
            .first
            .map(String.init)?
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let resolved, !resolved.isEmpty else {
            return nil
        }

        return resolved
    }

    private func runCommandAsAdmin(_ commandParts: [String]) -> Bool {
        let command = commandParts.map(shellEscaped).joined(separator: " ")
        let script = "do shell script \"\(appleScriptEscaped(command))\" with administrator privileges"
        guard let result = Shell.run(["/usr/bin/osascript", "-e", script]) else {
            return false
        }

        return result.exitCode == 0
    }

    private func shellEscaped(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private func appleScriptEscaped(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    private func extractQuotedValue(from text: String) -> String? {
        guard let firstQuote = text.firstIndex(of: "\"") else {
            return nil
        }

        let afterFirstQuote = text.index(after: firstQuote)
        guard let secondQuote = text[afterFirstQuote...].firstIndex(of: "\"") else {
            return nil
        }

        return String(text[afterFirstQuote..<secondQuote])
    }

    private func extractParenthesizedValue(from text: String) -> String? {
        guard let open = text.firstIndex(of: "(") else {
            return nil
        }

        let afterOpen = text.index(after: open)
        guard let close = text[afterOpen...].firstIndex(of: ")") else {
            return nil
        }

        return String(text[afterOpen..<close])
    }

    private func dedupe(_ items: [String]) -> [String] {
        var seen: Set<String> = []
        var ordered: [String] = []

        for item in items where !item.isEmpty {
            let key = item.lowercased()
            if seen.contains(key) {
                continue
            }

            seen.insert(key)
            ordered.append(item)
        }

        return ordered
    }
}

private final class StatusBarController: NSObject {
    private enum DefaultsKey {
        static let preferredName = "preferredWireGuardName"
    }

    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private let stateMenuItem = NSMenuItem(title: "Checking...", action: nil, keyEquivalent: "")
    private let toggleMenuItem = NSMenuItem(title: "Turn On", action: #selector(toggleConnection), keyEquivalent: "t")
    private let actionMessageMenuItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private let monitor = WireGuardStatusMonitor()
    private let queue = DispatchQueue(label: "wg.status.monitor")
    private var timer: Timer?
    private var snapshot = WireGuardSnapshot.empty
    private var isBusy = false
    private var preferredName: String?

    private lazy var iconOn = makeStatusIcon(systemName: "lock.fill")
    private lazy var iconOff = makeStatusIcon(systemName: "lock.open")

    override init() {
        preferredName = UserDefaults.standard.string(forKey: DefaultsKey.preferredName)

        super.init()
        configureMenu()
        configureStatusButton()
        refresh()

        timer = Timer.scheduledTimer(
            timeInterval: 5,
            target: self,
            selector: #selector(refresh),
            userInfo: nil,
            repeats: true
        )
        timer?.tolerance = 1
    }

    private func configureStatusButton() {
        statusItem.menu = menu
        statusItem.button?.title = ""
        statusItem.button?.imagePosition = .imageOnly
        statusItem.button?.image = iconOff
        statusItem.button?.toolTip = "Checking WireGuard status"
    }

    private func configureMenu() {
        stateMenuItem.isEnabled = false

        toggleMenuItem.target = self

        actionMessageMenuItem.isEnabled = false
        actionMessageMenuItem.isHidden = true

        let refreshItem = NSMenuItem(title: "Refresh", action: #selector(refresh), keyEquivalent: "r")
        refreshItem.target = self

        let openItem = NSMenuItem(title: "Open WireGuard", action: #selector(openWireGuard), keyEquivalent: "o")
        openItem.target = self

        let quitItem = NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self

        menu.addItem(stateMenuItem)
        menu.addItem(toggleMenuItem)
        menu.addItem(actionMessageMenuItem)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(refreshItem)
        menu.addItem(openItem)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(quitItem)
    }

    @objc private func refresh() {
        queue.async { [weak self] in
            guard let self else {
                return
            }

            let current = self.monitor.snapshot()

            DispatchQueue.main.async {
                self.snapshot = current
                self.apply(snapshot: current)
            }
        }
    }

    @objc private func toggleConnection() {
        guard !isBusy else {
            return
        }

        isBusy = true
        toggleMenuItem.isEnabled = false
        actionMessageMenuItem.isHidden = true

        queue.async { [weak self] in
            guard let self else {
                return
            }

            let outcome: ActionOutcome
            if self.snapshot.isConnected {
                outcome = self.monitor.disconnect()
            } else {
                outcome = self.monitor.connect(preferredName: self.preferredName)
            }

            let current = self.monitor.snapshot()

            DispatchQueue.main.async {
                self.snapshot = current
                self.isBusy = false
                self.showAction(outcome)
                self.apply(snapshot: current)
            }
        }
    }

    private func apply(snapshot: WireGuardSnapshot) {
        if let connectedName = snapshot.primaryConnectedName, !isUtunInterfaceName(connectedName) {
            preferredName = connectedName
            UserDefaults.standard.set(connectedName, forKey: DefaultsKey.preferredName)
        }

        if snapshot.isConnected {
            let displayNames = snapshot.connectedDisplayNames.joined(separator: ", ")
            statusItem.button?.image = iconOn
            statusItem.button?.title = ""
            statusItem.button?.toolTip = "Connected: \(displayNames)"
            stateMenuItem.title = "Connected: \(displayNames)"
            toggleMenuItem.title = "Turn Off"
            toggleMenuItem.isEnabled = !isBusy
            return
        }

        statusItem.button?.image = iconOff
        statusItem.button?.title = ""
        statusItem.button?.toolTip = "No active WireGuard tunnel"
        stateMenuItem.title = "Disconnected"

        if snapshot.hasAvailableTarget {
            toggleMenuItem.title = "Turn On"
            toggleMenuItem.isEnabled = !isBusy
        } else {
            toggleMenuItem.title = "Turn On (No Profile Found)"
            toggleMenuItem.isEnabled = false
        }
    }

    private func showAction(_ outcome: ActionOutcome) {
        if outcome.succeeded {
            actionMessageMenuItem.title = "Last action: \(outcome.message)"
        } else {
            actionMessageMenuItem.title = "Last action failed: \(outcome.message)"
        }

        actionMessageMenuItem.isHidden = false
    }

    private func makeStatusIcon(systemName: String) -> NSImage? {
        guard let image = NSImage(systemSymbolName: systemName, accessibilityDescription: "WireGuard") else {
            return nil
        }

        let configuration = NSImage.SymbolConfiguration(pointSize: 13, weight: .semibold)
        let configured = image.withSymbolConfiguration(configuration) ?? image
        configured.isTemplate = true
        return configured
    }

    @objc private func openWireGuard() {
        if let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.wireguard.macos") {
            let configuration = NSWorkspace.OpenConfiguration()
            NSWorkspace.shared.openApplication(at: appURL, configuration: configuration, completionHandler: nil)
            return
        }

        let defaultPath = URL(fileURLWithPath: "/Applications/WireGuard.app")
        if FileManager.default.fileExists(atPath: defaultPath.path) {
            NSWorkspace.shared.open(defaultPath)
        }
    }

    @objc private func quit() {
        NSApplication.shared.terminate(nil)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var controller: StatusBarController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        controller = StatusBarController()
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
