#![cfg(all(unix, feature = "transport-lab"))]

//! R2 control-socket coverage for network purge and bulk forget.
//!
//! These controls use the embedded daemon's real Unix socket and wire JSON,
//! rather than calling the dispatcher directly.  The dispatcher unit seam
//! owns the deterministic `WriterBusy` control: the public daemon surface
//! quiesces and releases the joined owner before purge, so there is no honest
//! external operation that can hold a competing semantic writer at that
//! boundary.  The socket controls below cover the reachable missing-owner,
//! filesystem-error, partial-bulk, and exact-success outcomes.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, MutexGuard};

use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

fn test_env_guard() -> MutexGuard<'static, ()> {
    TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn test_resource_port() -> myownmesh_core::ResourceProviderPort {
    let claim = myownmesh_core::ResourceClaim::try_from_entries(
        myownmesh_core::ResourceClass::ALL
            .into_iter()
            .map(|class| (class, 1_000_000_000)),
    )
    .expect("the purge fixture claim is representable");
    myownmesh_core::ResourceProviderPort::new(myownmesh_core::FiniteResourceProvider::new(claim))
        .expect("the purge fixture provider opens")
}

fn network(id: &str) -> myownmesh_core::NetworkConfig {
    let mut network = myownmesh_core::NetworkConfig::from_network_id(id, id);
    network.stun_servers.clear();
    network.turn_servers.clear();
    network.auto_approve = true;
    network
}

fn connector_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
    myownmesh_core::WebRtcConnectorCapablePolicy::new(
        test_resource_port(),
        myownmesh_core::WebRtcConnectorProfile::new(
            myownmesh_core::ConnectorCallbackPolicy::elastic_data_only(),
        ),
    )
}

async fn wait_for_socket(socket: &Path) {
    let name = socket
        .to_fs_name::<GenericFilePath>()
        .expect("the purge control socket path is valid");
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
    .expect("the purge control socket becomes ready");
}

async fn request(socket: &Path, request: &str) -> Value {
    let name = socket
        .to_fs_name::<GenericFilePath>()
        .expect("the purge control socket path is valid");
    let mut stream = LocalSocketStream::connect(name)
        .await
        .expect("connect the purge control socket");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the purge request");
    stream
        .write_all(b"\n")
        .await
        .expect("write the purge request terminator");
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        BufReader::new(stream).read_line(&mut line),
    )
    .await
    .expect("the purge response arrives")
    .expect("read the purge response");
    serde_json::from_str(&line).expect("the purge response is JSON")
}

async fn run_ctl_leave(home: &Path, network: &str) -> std::process::Output {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_myownmesh"))
            .args(["ctl", "networks", "leave", network])
            .env("MYOWNMESH_HOME", home)
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("the CLI purge response arrives")
    .expect("the CLI purge process exits")
}

fn snapshot_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("walk the isolated daemon state") {
            let entry = entry.expect("read an isolated daemon state entry");
            let path = entry.path();
            let file_type = entry
                .file_type()
                .expect("read an isolated daemon state entry type");
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with("-snapshot.json"))
            {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn error_text(response: &Value) -> &str {
    assert_eq!(response.get("ok").and_then(Value::as_bool), Some(false));
    response
        .get("error")
        .and_then(Value::as_str)
        .expect("a refused purge has an exact error")
}

fn cli_removed(response: &Value, expected: &str) {
    assert_eq!(
        response.get("removed").and_then(Value::as_str),
        Some(expected)
    );
}

#[tokio::test]
async fn purge_socket_success_deletes_exact_semantic_snapshot() {
    let _test_env_guard = test_env_guard();
    let home = tempfile::tempdir().expect("isolated purge home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let socket = home.path().join("private").join("daemon.sock");
    let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
    daemon_config.control_socket = Some(socket.clone());
    let mut services = myownmesh_core::MeshConfig::default().services;
    services.node.enabled = true;
    let net = network("purge-exact-success");
    let config = myownmesh_core::MeshConfig {
        identity_path: Some(home.path().join("identity.json")),
        auto_update: myownmesh_core::AutoUpdateConfig {
            enabled: false,
            ..Default::default()
        },
        daemon: daemon_config,
        services,
        networks: vec![net.clone()],
        ..Default::default()
    };
    config
        .save()
        .expect("persist the exact purge fixture config");
    let daemon = myownmesh::embedded::start_connector_capable(
        config,
        connector_policy(),
        myownmesh::control::RealtimeAdvert::unsupported(),
    )
    .await
    .expect("start the purge fixture daemon");
    wait_for_socket(&socket).await;
    let before = snapshot_files(home.path());
    assert_eq!(
        before.len(),
        1,
        "the joined network has one canonical snapshot"
    );

    let output = run_ctl_leave(home.path(), &net.id).await;
    assert!(
        output.status.success(),
        "ctl networks leave failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("the CLI purge response is JSON data");
    cli_removed(&response, "purge-exact-success");
    assert!(
        before.iter().all(|path| !path.exists()),
        "successful purge removes the exact canonical semantic snapshot"
    );

    daemon.shutdown().await;
}

#[tokio::test]
async fn purge_socket_surfaces_io_failure_and_bulk_aggregates_partial_result() {
    let _test_env_guard = test_env_guard();
    let home = tempfile::tempdir().expect("isolated bulk purge home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let socket = home.path().join("private").join("daemon.sock");
    let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
    daemon_config.control_socket = Some(socket.clone());
    let mut services = myownmesh_core::MeshConfig::default().services;
    services.node.enabled = true;
    let first = network("purge-bulk-first");
    let second = network("purge-bulk-second");
    let config = myownmesh_core::MeshConfig {
        identity_path: Some(home.path().join("identity.json")),
        auto_update: myownmesh_core::AutoUpdateConfig {
            enabled: false,
            ..Default::default()
        },
        daemon: daemon_config,
        services,
        networks: vec![first, second],
        ..Default::default()
    };
    config
        .save()
        .expect("persist the bulk purge fixture config");
    let daemon = myownmesh::embedded::start_connector_capable(
        config,
        connector_policy(),
        myownmesh::control::RealtimeAdvert::unsupported(),
    )
    .await
    .expect("start the bulk purge fixture daemon");
    wait_for_socket(&socket).await;
    let snapshots = snapshot_files(home.path());
    assert_eq!(snapshots.len(), 2, "both networks have canonical snapshots");
    let broken = snapshots[0].clone();
    std::fs::remove_file(&broken).expect("remove the fixture snapshot before replacement");
    std::fs::create_dir(&broken).expect("replace the snapshot with an I/O failure shape");

    let response = request(&socket, r#"{"op":"forget_all_networks"}"#).await;
    let error = error_text(&response);
    assert!(error.contains("forget all failed for 1 network(s)"));
    assert!(error.contains("purge-bulk-first"));
    assert!(error.contains("purge-bulk-second"));
    assert!(
        error.contains("completed:"),
        "bulk refusal reports the successful sibling as completed"
    );
    assert!(
        broken.is_dir(),
        "the failing snapshot was not silently deleted"
    );

    daemon.shutdown().await;
}

#[tokio::test]
async fn purge_socket_missing_owner_refuses_without_config_mutation() {
    let _test_env_guard = test_env_guard();
    let home = tempfile::tempdir().expect("isolated missing-owner home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let socket = home.path().join("private").join("daemon.sock");
    let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
    daemon_config.control_socket = Some(socket.clone());
    let mut services = myownmesh_core::MeshConfig::default().services;
    services.node.enabled = false;
    let config = myownmesh_core::MeshConfig {
        identity_path: Some(home.path().join("identity.json")),
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
        .expect("persist the missing-owner fixture config");
    let config_path = myownmesh_core::dirs::config_path().expect("resolve the fixture config");
    let before = std::fs::read(&config_path).expect("read the fixture config before refusal");
    let daemon = myownmesh::embedded::start_infrastructure_only(config, test_resource_port())
        .await
        .expect("start the missing-owner fixture daemon");
    wait_for_socket(&socket).await;

    let output = run_ctl_leave(home.path(), "purge-missing-owner").await;
    assert!(
        !output.status.success(),
        "missing-owner CLI request succeeded"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("daemon error: unknown network: purge-missing-owner"),
        "missing-owner CLI refusal was not preserved: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&config_path).expect("read the fixture config after refusal"),
        before,
        "missing-owner refusal does not mutate config"
    );

    daemon.shutdown().await;
}
