use reqwest;
use serde_json::Value;
use std::time::Duration;
use tang::keys::KeyManager;
use tang::server::create_router;
use tokio::time::sleep;

#[tokio::test]
async fn test_server_health() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Set secure permissions on temp dir for testing
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(temp_dir.path()).unwrap();
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(temp_dir.path(), permissions).unwrap();
    }

    let key_manager = std::sync::Arc::new(KeyManager::new(temp_dir.path()).unwrap());

    // Generate keys
    key_manager.generate_signing_key().unwrap();
    key_manager.generate_exchange_key().unwrap();

    let app = create_router(key_manager);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_advertise_endpoint() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Set secure permissions on temp dir for testing
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(temp_dir.path()).unwrap();
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(temp_dir.path(), permissions).unwrap();
    }

    let key_manager = std::sync::Arc::new(KeyManager::new(temp_dir.path()).unwrap());

    // Generate keys
    key_manager.generate_signing_key().unwrap();
    key_manager.generate_exchange_key().unwrap();

    let app = create_router(key_manager);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/adv", addr))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    let keys = body["keys"].as_array().unwrap();

    assert_eq!(keys.len(), 2); // One signing key, one exchange key
}

#[test]
fn test_key_generation() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Set secure permissions on temp dir for testing
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(temp_dir.path()).unwrap();
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(temp_dir.path(), permissions).unwrap();
    }

    let key_manager = KeyManager::new(temp_dir.path()).unwrap();

    let sig_kid = key_manager.generate_signing_key().unwrap();
    let exc_kid = key_manager.generate_exchange_key().unwrap();

    assert!(!sig_kid.is_empty());
    assert!(!exc_kid.is_empty());
    assert_ne!(sig_kid, exc_kid);

    // Verify keys can be loaded
    let sig_key = key_manager.load_key(&sig_kid).unwrap();
    let exc_key = key_manager.load_key(&exc_kid).unwrap();

    assert_eq!(
        sig_key.other.get("use").and_then(|v| v.as_str()),
        Some("sig")
    );
    assert_eq!(
        exc_key.other.get("use").and_then(|v| v.as_str()),
        Some("enc")
    );
}

#[test]
fn test_key_hiding() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Set secure permissions on temp dir for testing
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(temp_dir.path()).unwrap();
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(temp_dir.path(), permissions).unwrap();
    }

    let key_manager = KeyManager::new(temp_dir.path()).unwrap();

    let kid = key_manager.generate_exchange_key().unwrap();

    // Key should be visible
    let active_keys = key_manager.load_active_keys().unwrap();
    assert_eq!(active_keys.keys.len(), 1);

    // Hide the key
    key_manager.hide_key(&kid).unwrap();

    // Key should not be visible
    let active_keys = key_manager.load_active_keys().unwrap();
    assert_eq!(active_keys.keys.len(), 0);
}
