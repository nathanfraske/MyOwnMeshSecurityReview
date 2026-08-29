#![cfg(unix)]

//! R2 control-socket coverage for the shipped MFA CLI.
//!
//! The daemon is the real embedded control surface and the client for every
//! request is the built `myownmesh ctl` binary. This keeps the assertion at the
//! boundary users cross: an enrollment response is not a terminal custody
//! decision, and an exact transaction can be queried after a discarded reply.

use std::path::Path;
use std::process::{Output, Stdio};

use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};
use serde_json::Value;

fn test_resource_port() -> myownmesh_core::ResourceProviderPort {
    let claim = myownmesh_core::ResourceClaim::try_from_entries(
        myownmesh_core::ResourceClass::ALL
            .into_iter()
            .map(|class| (class, 1_000_000_000)),
    )
    .expect("the CLI control fixture claim is representable");
    myownmesh_core::ResourceProviderPort::new(myownmesh_core::FiniteResourceProvider::new(claim))
        .expect("the CLI control fixture provider opens")
}

async fn wait_for_socket(socket: &Path) {
    let name = socket
        .to_fs_name::<GenericFilePath>()
        .expect("the CLI control socket path is valid");
    tokio::time::timeout(std::time::Duration::from_secs(10), async move {
        loop {
            match LocalSocketStream::connect(name.clone()).await {
                Ok(stream) => {
                    drop(stream);
                    return;
                }
                Err(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .expect("the real control socket becomes ready");
}

async fn run_ctl(home: &Path, args: &[&str]) -> Output {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let rendered_args = args.join(" ");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_myownmesh"));
    command
        .arg("ctl")
        .arg("governance")
        .arg("mfa")
        .args(&args)
        .env("MYOWNMESH_HOME", home)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn shipped myownmesh ctl {rendered_args}: {error}"));
    tokio::time::timeout(std::time::Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap_or_else(|_| {
            panic!("shipped myownmesh ctl timed out after 10s for arguments: {rendered_args}")
        })
        .unwrap_or_else(|error| panic!("wait for shipped myownmesh ctl {rendered_args}: {error}"))
}

fn response(output: Output, what: &str) -> Value {
    assert!(
        output.status.success(),
        "{what} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{what} did not print JSON: {error}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn enroll_documents(output: Output, what: &str) -> (Value, Value) {
    assert!(
        output.status.success(),
        "{what} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let documents = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| {
            panic!(
                "{what} did not print valid JSON documents: {error}; stdout={}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
    assert_eq!(
        documents.len(),
        2,
        "{what} must print exactly enrollment material and its committed transaction"
    );
    let mut documents = documents.into_iter();
    (
        documents
            .next()
            .expect("enrollment material document exists"),
        documents
            .next()
            .expect("committed transaction document exists"),
    )
}

fn transaction_data<'a>(value: &'a Value, what: &str) -> &'a Value {
    value
        .get("data")
        .unwrap_or_else(|| panic!("{what} response has no data: {value}"))
}

fn field<'a>(data: &'a Value, key: &str, what: &str) -> &'a str {
    data.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{what} response has no string field {key}: {data}"))
}

#[tokio::test]
async fn shipped_ctl_mfa_prepare_commit_query_redeliver_and_stale_successor_are_exact() {
    let home = tempfile::tempdir().expect("isolated CLI home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let socket = home.path().join("private").join("daemon.sock");
    let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
    daemon_config.control_socket = Some(socket.clone());
    let mut services = myownmesh_core::MeshConfig::default().services;
    services.node.enabled = false;
    let config = myownmesh_core::MeshConfig {
        auto_update: myownmesh_core::AutoUpdateConfig {
            enabled: false,
            ..Default::default()
        },
        daemon: daemon_config,
        services,
        ..Default::default()
    };
    config
        .save()
        .expect("persist the CLI's isolated socket config");
    let daemon = myownmesh::embedded::start_infrastructure_only(config, test_resource_port())
        .await
        .expect("start the real embedded control server");
    wait_for_socket(&socket).await;

    let network = "ctl-r2-exact-mfa";

    // Explicit Prepare crosses the shipped CLI and real control socket while
    // leaving exact material durably Prepared for query/redelivery/abort.
    let prepared_initial = response(
        run_ctl(home.path(), &["prepare", network]).await,
        "ctl mfa prepare",
    );
    let prepared_data = transaction_data(&prepared_initial, "ctl mfa prepare");
    let first_transaction = field(prepared_data, "transaction_id", "ctl mfa prepare");
    let first_secret = field(prepared_data, "secret", "ctl mfa prepare");
    assert!(!first_transaction.is_empty());
    assert!(!first_secret.is_empty());

    let queried = response(
        run_ctl(home.path(), &["query", network, first_transaction]).await,
        "ctl mfa query prepared",
    );
    let queried_data = transaction_data(&queried, "ctl mfa query prepared");
    assert_eq!(
        field(queried_data, "state", "ctl mfa query prepared"),
        "prepared"
    );
    assert_eq!(
        field(queried_data, "transaction_id", "ctl mfa query prepared"),
        first_transaction
    );
    assert_eq!(
        field(queried_data, "secret", "ctl mfa query prepared"),
        first_secret
    );

    let redelivered = response(
        run_ctl(home.path(), &["redeliver", network, first_transaction]).await,
        "ctl mfa redeliver prepared",
    );
    let redelivered_data = transaction_data(&redelivered, "ctl mfa redeliver prepared");
    assert_eq!(
        field(
            redelivered_data,
            "transaction_id",
            "ctl mfa redeliver prepared"
        ),
        first_transaction
    );
    assert_eq!(
        field(redelivered_data, "secret", "ctl mfa redeliver prepared"),
        first_secret
    );

    let aborted = response(
        run_ctl(home.path(), &["abort", network, first_transaction]).await,
        "ctl mfa abort first transaction",
    );
    assert_eq!(
        field(
            transaction_data(&aborted, "ctl mfa abort first transaction"),
            "state",
            "ctl mfa abort first transaction"
        ),
        "absent"
    );

    // A fresh Prepare is a successor generation. The stale first transaction
    // can be queried or committed, but it must report Absent and never touch
    // this exact successor.
    let prepared = response(
        run_ctl(home.path(), &["prepare", network]).await,
        "ctl mfa prepare successor",
    );
    let prepared_data = transaction_data(&prepared, "ctl mfa prepare successor");
    let second_transaction = field(prepared_data, "transaction_id", "ctl mfa prepare successor");
    let second_secret = field(prepared_data, "secret", "ctl mfa prepare successor");
    assert_ne!(first_transaction, second_transaction);
    assert!(!second_secret.is_empty());

    let stale_commit = response(
        run_ctl(home.path(), &["commit", network, first_transaction]).await,
        "ctl mfa stale commit",
    );
    assert_eq!(
        field(
            transaction_data(&stale_commit, "ctl mfa stale commit"),
            "state",
            "ctl mfa stale commit"
        ),
        "absent"
    );
    let successor_query = response(
        run_ctl(home.path(), &["query", network, second_transaction]).await,
        "ctl mfa query successor after stale commit",
    );
    let successor_data = transaction_data(
        &successor_query,
        "ctl mfa query successor after stale commit",
    );
    assert_eq!(
        field(
            successor_data,
            "state",
            "ctl mfa query successor after stale commit"
        ),
        "prepared"
    );
    assert_eq!(
        field(
            successor_data,
            "secret",
            "ctl mfa query successor after stale commit"
        ),
        second_secret
    );

    // Discard the final commit response deliberately. Querying the same exact
    // transaction is the lost-ACK recovery path and must expose Committed;
    // a requested-state guess cannot satisfy this assertion.
    let _discarded_commit = run_ctl(home.path(), &["commit", network, second_transaction]).await;
    let recovered = response(
        run_ctl(home.path(), &["query", network, second_transaction]).await,
        "ctl mfa query after discarded commit response",
    );
    let recovered_data =
        transaction_data(&recovered, "ctl mfa query after discarded commit response");
    assert_eq!(
        field(
            recovered_data,
            "state",
            "ctl mfa query after discarded commit response"
        ),
        "committed"
    );
    assert!(recovered_data.get("secret").is_none());
    assert!(recovered_data.get("recovery_codes").is_none());

    let duplicate_commit = response(
        run_ctl(home.path(), &["commit", network, second_transaction]).await,
        "ctl mfa duplicate commit",
    );
    assert_eq!(
        field(
            transaction_data(&duplicate_commit, "ctl mfa duplicate commit"),
            "state",
            "ctl mfa duplicate commit"
        ),
        "committed"
    );
    let late_abort = response(
        run_ctl(home.path(), &["abort", network, second_transaction]).await,
        "ctl mfa late abort",
    );
    assert_eq!(
        field(
            transaction_data(&late_abort, "ctl mfa late abort"),
            "state",
            "ctl mfa late abort"
        ),
        "committed"
    );

    // Enroll is the shipped one-roundtrip user experience: it must explicitly
    // settle its exact prepared transaction before reporting success. The
    // follow-up query proves the returned material was not merely Prepared.
    let enroll_network = "ctl-r2-explicit-enroll";
    let (enrollment_material, enrolled) = enroll_documents(
        run_ctl(home.path(), &["enroll", enroll_network]).await,
        "ctl mfa enroll",
    );
    let enroll_transaction = field(
        &enrollment_material,
        "transaction_id",
        "ctl mfa enroll material",
    );
    let enroll_secret = field(&enrollment_material, "secret", "ctl mfa enroll material");
    assert!(!enroll_transaction.is_empty());
    assert!(!enroll_secret.is_empty());
    assert!(!field(
        &enrollment_material,
        "otpauth_uri",
        "ctl mfa enroll material"
    )
    .is_empty());
    assert!(!enrollment_material
        .get("recovery_codes")
        .and_then(Value::as_array)
        .expect("ctl mfa enroll material has recovery codes")
        .is_empty());
    assert_eq!(
        field(&enrolled, "network", "ctl mfa enroll committed"),
        enroll_network
    );
    assert_eq!(
        field(&enrolled, "transaction_id", "ctl mfa enroll committed"),
        enroll_transaction
    );
    assert_eq!(
        field(&enrolled, "state", "ctl mfa enroll committed"),
        "committed"
    );
    assert!(enrolled.get("secret").is_none());
    assert!(enrolled.get("recovery_codes").is_none());
    let enrolled_query = response(
        run_ctl(home.path(), &["query", enroll_network, enroll_transaction]).await,
        "ctl mfa query after enroll",
    );
    let enrolled_query_data = transaction_data(&enrolled_query, "ctl mfa query after enroll");
    assert_eq!(
        field(enrolled_query_data, "state", "ctl mfa query after enroll"),
        "committed"
    );
    assert!(enrolled_query_data.get("secret").is_none());
    assert!(enrolled_query_data.get("recovery_codes").is_none());

    daemon.shutdown().await;
    std::env::remove_var("MYOWNMESH_HOME");
}
