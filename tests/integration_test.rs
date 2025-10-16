use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

const BASE_URL: &str = "http://127.0.0.1:3000";
const NETWORK: &str = "testnet";
const API_KEY: &str = "custodian_dev_key_12345";
const TEST_PASSWORD: &str = "test_password_123";

struct TestContext {
    client: Client,
    wallet_id: Option<Uuid>,
}

impl TestContext {
    fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            wallet_id: None,
        }
    }

    fn wallet_url(&self, path: &str) -> String {
        if let Some(id) = self.wallet_id {
            format!("{}/{}/wallets/{}{}", BASE_URL, NETWORK, id, path)
        } else {
            format!("{}/{}/wallets{}", BASE_URL, NETWORK, path)
        }
    }
}

#[tokio::test]
async fn test_health_check() {
    let client = Client::new();
    let response = client
        .get(format!("{}/health", BASE_URL))
        .send()
        .await
        .expect("Failed to send health check request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["service"], "Bitcoin Wallet API");
}

#[tokio::test]
async fn test_create_wallet() {
    let client = Client::new();

    let payload = json!({
        "name": "Integration Test Wallet",
        "password": TEST_PASSWORD
    });

    let response = client
        .post(format!("{}/{}/wallets", BASE_URL, NETWORK))
        .header("X-API-Key", API_KEY)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create wallet");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");

    assert!(body["id"].is_string());
    assert_eq!(body["name"], "Integration Test Wallet");
    assert!(body["mnemonic"].is_string());
    assert!(body["descriptor"].is_string());

    let mnemonic = body["mnemonic"].as_str().unwrap();
    let word_count = mnemonic.split_whitespace().count();
    assert_eq!(word_count, 12, "Mnemonic should have 12 words");

    let _wallet_id = Uuid::parse_str(body["id"].as_str().unwrap())
        .expect("Should be valid UUID");
}

#[tokio::test]
async fn test_create_wallet_with_mnemonic() {
    let client = Client::new();

    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let payload = json!({
        "name": "Test Wallet With Mnemonic",
        "password": TEST_PASSWORD,
        "mnemonic": test_mnemonic
    });

    let response = client
        .post(format!("{}/{}/wallets", BASE_URL, NETWORK))
        .header("X-API-Key", API_KEY)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create wallet");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["mnemonic"], test_mnemonic);
}

#[tokio::test]
async fn test_list_wallets() {
    let ctx = TestContext::new();

    let payload = json!({
        "name": "Wallet for List Test",
        "password": TEST_PASSWORD
    });

    let response = ctx
        .client
        .post(format!("{}/{}/wallets", BASE_URL, NETWORK))
        .header("X-API-Key", API_KEY)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create wallet");

    assert_eq!(response.status(), StatusCode::OK);

    let response = ctx
        .client
        .get(format!("{}/{}/wallets", BASE_URL, NETWORK))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .expect("Failed to list wallets");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["wallets"].is_array());

    let wallets = body["wallets"].as_array().unwrap();
    assert!(!wallets.is_empty(), "Should have at least one wallet");

    for wallet in wallets {
        assert!(wallet["id"].is_string());
        assert!(wallet["name"].is_string());
        let _id = Uuid::parse_str(wallet["id"].as_str().unwrap())
            .expect("Wallet ID should be valid UUID");
    }
}

#[tokio::test]
async fn test_get_balance() {
    let mut ctx = TestContext::new();

    let payload = json!({
        "name": "Wallet for Balance Test",
        "password": TEST_PASSWORD
    });

    let create_response = ctx
        .client
        .post(format!("{}/{}/wallets", BASE_URL, NETWORK))
        .header("X-API-Key", API_KEY)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create wallet");

    let body: Value = create_response.json().await.expect("Failed to parse JSON");
    ctx.wallet_id = Some(
        Uuid::parse_str(body["id"].as_str().unwrap())
            .expect("Should be valid UUID")
    );

    let response = ctx
        .client
        .get(&ctx.wallet_url("/balance"))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .expect("Failed to get balance");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["confirmed"].is_number());
    assert!(body["unconfirmed"].is_number());
    assert!(body["total"].is_number());

    assert_eq!(body["confirmed"], 0);
    assert_eq!(body["unconfirmed"], 0);
    assert_eq!(body["total"], 0);
}

#[tokio::test]
async fn test_generate_address() {
    let mut ctx = TestContext::new();

    let payload = json!({
        "name": "Wallet for Address Test",
        "password": TEST_PASSWORD
    });

    let create_response = ctx
        .client
        .post(format!("{}/{}/wallets", BASE_URL, NETWORK))
        .header("X-API-Key", API_KEY)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create wallet");

    let body: Value = create_response.json().await.expect("Failed to parse JSON");
    ctx.wallet_id = Some(
        Uuid::parse_str(body["id"].as_str().unwrap())
            .expect("Should be valid UUID")
    );

    let response = ctx
        .client
        .get(&ctx.wallet_url("/address"))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .expect("Failed to generate address");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["address"].is_string());
    assert!(body["index"].is_number());

    let address = body["address"].as_str().unwrap();
    assert!(address.starts_with("tb1"), "Should be testnet segwit address");
    assert_eq!(body["index"], 0, "First address should have index 0");

    let second_response = ctx
        .client
        .get(&ctx.wallet_url("/address"))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .expect("Failed to generate second address");

    let second_body: Value = second_response.json().await.expect("Failed to parse JSON");
    assert_eq!(second_body["index"], 1, "Second address should have index 1");
    assert_ne!(
        second_body["address"].as_str().unwrap(),
        address,
        "Addresses should be different"
    );
}

#[tokio::test]
async fn test_wallet_not_found() {
    let client = Client::new();
    let fake_id = Uuid::new_v4();

    let response = client
        .get(format!("{}/{}/wallets/{}/balance", BASE_URL, NETWORK, fake_id))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body: Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn test_invalid_wallet_id() {
    let client = Client::new();

    let response = client
        .get(format!("{}/{}/wallets/not-a-uuid/balance", BASE_URL, NETWORK))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_invalid_network() {
    let client = Client::new();

    let payload = json!({
        "name": "Test Wallet",
        "password": TEST_PASSWORD
    });

    let response = client
        .post(format!("{}/invalidnetwork/wallets", BASE_URL))
        .header("X-API-Key", API_KEY)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_full_wallet_lifecycle() {
    let mut ctx = TestContext::new();

    println!("Creating wallet...");
    let payload = json!({
        "name": "Full Lifecycle Test Wallet",
        "password": TEST_PASSWORD
    });

    let create_response = ctx
        .client
        .post(format!("{}/{}/wallets", BASE_URL, NETWORK))
        .header("X-API-Key", API_KEY)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create wallet");

    assert_eq!(create_response.status(), StatusCode::OK);
    let create_body: Value = create_response.json().await.expect("Failed to parse JSON");
    ctx.wallet_id = Some(
        Uuid::parse_str(create_body["id"].as_str().unwrap())
            .expect("Should be valid UUID")
    );
    println!("Wallet created: {}", ctx.wallet_id.unwrap());

    println!("Generating first address...");
    let addr_response = ctx
        .client
        .get(&ctx.wallet_url("/address"))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .expect("Failed to generate address");
    assert_eq!(addr_response.status(), StatusCode::OK);
    let addr_body: Value = addr_response.json().await.expect("Failed to parse JSON");
    println!("Address: {}", addr_body["address"]);

    println!("Checking initial balance...");
    let balance_response = ctx
        .client
        .get(&ctx.wallet_url("/balance"))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .expect("Failed to get balance");
    assert_eq!(balance_response.status(), StatusCode::OK);
    let balance_body: Value = balance_response.json().await.expect("Failed to parse JSON");
    println!("Balance: {}", balance_body["total"]);

    println!("Checking balance after auto-sync...");
    let balance_after_sync = ctx
        .client
        .get(&ctx.wallet_url("/balance"))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .expect("Failed to get balance");
    assert_eq!(balance_after_sync.status(), StatusCode::OK);
    let balance_after_body: Value = balance_after_sync.json().await.expect("Failed to parse JSON");
    println!("Balance after sync: {}", balance_after_body["total"]);

    println!("Listing wallets...");
    let list_response = ctx
        .client
        .get(format!("{}/{}/wallets", BASE_URL, NETWORK))
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .expect("Failed to list wallets");
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body: Value = list_response.json().await.expect("Failed to parse JSON");

    let our_wallet = list_body["wallets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["id"].as_str().unwrap() == ctx.wallet_id.unwrap().to_string());
    assert!(our_wallet.is_some(), "Our wallet should be in the list");

    println!("Full lifecycle test completed successfully!");
}
