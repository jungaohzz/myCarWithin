import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        // Starts the per-launch log file before any scene traffic.
        AppLog.record("App 开始启动")
        let configuration = UISceneConfiguration(name: "Receiver", sessionRole: connectingSceneSession.role)
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }
}

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func sceneWillEnterForeground(_ scene: UIScene) { AppLog.record("App 回到前台") }
    func sceneDidBecomeActive(_ scene: UIScene) { AppLog.record("App 已激活") }
    func sceneWillResignActive(_ scene: UIScene) { AppLog.record("App 即将失去焦点") }
    func sceneDidEnterBackground(_ scene: UIScene) { AppLog.record("App 进入后台") }
    func sceneDidDisconnect(_ scene: UIScene) { AppLog.record("场景已断开") }

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene else { return }
        AppLog.record("主场景已连接")
        let window = UIWindow(windowScene: scene)
        let navigation = UINavigationController(rootViewController: ReceiverViewController())
        let appearance = UINavigationBarAppearance()
        appearance.configureWithDefaultBackground()
        appearance.titleTextAttributes = [.foregroundColor: UIColor.label]
        navigation.navigationBar.standardAppearance = appearance
        navigation.navigationBar.scrollEdgeAppearance = appearance
        navigation.navigationBar.tintColor = .systemBlue
        window.rootViewController = navigation
        window.makeKeyAndVisible()
        self.window = window
    }
}
