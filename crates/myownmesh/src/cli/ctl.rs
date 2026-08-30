//! `myownmesh ctl …` — talk to a running daemon over its control
//! socket. Wire format is line-delimited JSON; see
//! [`myownmesh::control`] for the request/response shapes.

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use interprocess::local_socket::tokio::prelude::*;
#[cfg(unix)]
use interprocess::local_socket::GenericFilePath;
#[cfg(not(unix))]
use interprocess::local_socket::GenericNamespaced;
use myownmesh_core::{NetworkConfig, ServicesConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use myownmesh::control::{Request, Response};

#[derive(Subcommand, Debug)]
pub enum CtlCmd {
    /// Print daemon status.
    Status,
    /// Networks: list / join / leave / topology.
    #[command(subcommand)]
    Networks(NetworksCmd),
    /// Per-peer info from the daemon.
    Peers {
        /// Network id to list peers from.
        network: String,
    },
    /// Stream live connection-state transitions for a network as
    /// JSONL — one record per line, each carrying the full liveness
    /// snapshot (status, tier, ICE/PC state, selected-pair class,
    /// rtt). Runs until interrupted; redirect to a file to capture a
    /// session for `scripts/merge-traces.py`:
    ///
    ///   myownmesh ctl trace home > trace-$(hostname).jsonl
    Trace {
        /// Network id to trace.
        network: String,
    },
    /// Roster ops on a saved network.
    #[command(subcommand)]
    Roster(RosterCmd),
    /// Host infrastructure services for the mesh: signaling / STUN / TURN.
    #[command(subcommand)]
    Services(ServicesCmd),
    /// Closed-network governance: state, proposals, and the per-device
    /// custody MFA that guards canonical authoring.
    #[command(subcommand)]
    Governance(GovernanceCmd),
}

#[derive(Subcommand, Debug)]
pub enum GovernanceCmd {
    /// Propose granting `target` a role: `member` | `controller` | `owner`.
    GrantRole {
        network: String,
        target: String,
        role: String,
        #[arg(long)]
        mfa_code: Option<String>,
    },
    /// Propose revoking `target`'s role (back to member).
    RevokeRole {
        network: String,
        target: String,
        #[arg(long)]
        mfa_code: Option<String>,
    },
    /// Per-device custody MFA (TOTP) that gates governance authoring.
    #[command(subcommand)]
    Mfa(MfaCmd),
}

#[derive(Subcommand, Debug)]
pub enum MfaCmd {
    /// Enroll a TOTP authenticator for a network on this device. Prints the
    /// secret, an `otpauth://` URI (for a QR), and one-time recovery codes.
    Enroll { network: String },
    /// Prepare an enrollment without settling it.
    Prepare { network: String },
    /// Query one exact enrollment transaction.
    Query {
        network: String,
        transaction_id: String,
    },
    /// Re-deliver one exact prepared enrollment.
    Redeliver {
        network: String,
        transaction_id: String,
    },
    /// Commit one exact prepared enrollment.
    Commit {
        network: String,
        transaction_id: String,
    },
    /// Abort one exact prepared enrollment.
    Abort {
        network: String,
        transaction_id: String,
    },
    /// Report whether this device holds a custody lock for a network.
    Status { network: String },
    /// Remove the custody lock (requires a valid current code).
    Disable { network: String, code: String },
}

#[derive(Subcommand, Debug)]
pub enum ServicesCmd {
    /// Show which services this device hosts and their listen addresses.
    Status,
    /// Turn a service on: node | signaling | stun | turn.
    /// `node` is mesh participation itself (off = pure-infrastructure
    /// box). TURN also needs credentials + a public IP — set those in
    /// config.json (or the GUI) first; an enabled-but-unconfigured TURN
    /// shows as not running.
    Enable {
        /// node | signaling | stun | turn
        service: String,
    },
    /// Turn a service off: node | signaling | stun | turn.
    Disable {
        /// node | signaling | stun | turn
        service: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum NetworksCmd {
    List,
    /// Join a network by id: persists it to config.json with the
    /// default signaling / STUN / TURN setup and attaches it on the
    /// live daemon. For a custom setup, edit config.json or use the GUI.
    Join {
        network_id: String,
    },
    /// Leave a network: detaches it on the live daemon and removes it
    /// from config.json. Accepts the network id or local config id.
    Leave {
        network_id: String,
    },
    /// Reconnect a network in place — redial signaling and renegotiate ICE
    /// without leaving the room (the non-destructive twin of leave+rejoin).
    /// Accepts the network id or local config id; pass `--peer <id>` to
    /// reconnect just one peer instead of every peer on the network.
    Reconnect {
        network_id: String,
        #[arg(long)]
        peer: Option<String>,
    },
    Topology {
        network_id: String,
        /// `ring`, `star`, `hubs`, or `full_mesh`. Local-config only —
        /// refused when the network's topology is governed (see
        /// `topology-propose`).
        topology: String,
        /// Hub spec: `star` takes a device id; `hubs` takes
        /// `id1,id2[,…][:spoke_redundancy]`.
        #[arg(long)]
        hub: Option<String>,
    },
    /// Deliberately dial one peer by device id on a joined network. On a
    /// `silent` network this is how a connection is opened at all (nothing
    /// connects on its own); on other kinds it's rarely needed since they
    /// auto-dial on presence.
    Connect {
        network_id: String,
        peer: String,
        /// Record a standing dial: the daemon redials this peer on
        /// every announce (even on a Silent network) and never gives
        /// up on it — the shape a support session needs. Persisted
        /// with the network config.
        #[arg(long)]
        pin: bool,
        /// Wait up to this many milliseconds for the peer to reach
        /// ACTIVE and report the real outcome (0 = return as soon as
        /// the dial is queued).
        #[arg(long, default_value_t = 0)]
        wait_ms: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum RosterCmd {
    List {
        network: String,
    },
    Approve {
        network: String,
        device_id: String,
        #[arg(long)]
        label: Option<String>,
    },
    Remove {
        network: String,
        device_id: String,
    },
}

pub async fn run(cmd: CtlCmd) -> Result<()> {
    let request = match cmd {
        // Services toggles are a read-modify-write against the live
        // config, so they take a dedicated path rather than one request.
        CtlCmd::Services(services_cmd) => return run_services(services_cmd).await,
        // Trace is a long-lived server-push stream, not a single
        // request/response, so it takes a dedicated streaming path.
        CtlCmd::Trace { network } => return run_trace(network).await,
        CtlCmd::Status => Request::Status,
        CtlCmd::Networks(NetworksCmd::List) => Request::NetworksList,
        CtlCmd::Networks(NetworksCmd::Join { network_id }) => {
            // Normalise client-side so the stored id matches what the
            // engine and `ctl networks list` use, and so an invalid id
            // fails with a clear message before we touch the daemon.
            let network_id = myownmesh_core::identity::normalize_network_id(&network_id)
                .with_context(|| format!("invalid network id '{network_id}'"))?;
            Request::NetworkAdd {
                config: NetworkConfig::from_network_id(network_id.clone(), network_id),
            }
        }
        CtlCmd::Networks(NetworksCmd::Leave { network_id }) => Request::NetworkRemove {
            network: network_id,
            // `ctl networks leave` is a deliberate forget — purge the signed
            // state + roster so a later rejoin doesn't reload a stale genesis.
            purge: true,
        },
        CtlCmd::Networks(NetworksCmd::Reconnect { network_id, peer }) => {
            Request::NetworkReconnect {
                network: network_id,
                peer,
            }
        }
        CtlCmd::Networks(NetworksCmd::Connect {
            network_id,
            peer,
            pin,
            wait_ms,
        }) => Request::NetworkConnectPeer {
            network: network_id,
            peer,
            pin,
            wait_ms,
        },
        CtlCmd::Networks(NetworksCmd::Topology {
            network_id,
            topology,
            hub,
        }) => Request::TopologySet {
            network: network_id,
            topology,
            hub,
        },
        CtlCmd::Peers { network } => Request::PeersList { network },
        CtlCmd::Roster(RosterCmd::List { network }) => Request::RosterList { network },
        CtlCmd::Roster(RosterCmd::Approve {
            network,
            device_id,
            label,
        }) => Request::RosterApprove {
            network,
            device_id,
            label,
        },
        CtlCmd::Roster(RosterCmd::Remove { network, device_id }) => {
            Request::RosterRemove { network, device_id }
        }
        CtlCmd::Governance(GovernanceCmd::GrantRole {
            network,
            target,
            role,
            mfa_code,
        }) => Request::GovernanceProposeRoleGrant {
            network,
            target,
            role: parse_role(&role)?,
            mfa_code,
        },
        CtlCmd::Governance(GovernanceCmd::RevokeRole {
            network,
            target,
            mfa_code,
        }) => Request::GovernanceProposeRoleRevoke {
            network,
            target,
            mfa_code,
        },
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Enroll { network })) => {
            return run_mfa_prepare_and_commit(network).await;
        }
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Prepare { network })) => {
            return run_mfa_material(Request::GovernanceMfaPrepare { network }, None).await;
        }
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Query {
            network,
            transaction_id,
        })) => {
            return run_mfa_transaction(Request::GovernanceMfaQuery {
                network,
                transaction_id,
            })
            .await
        }
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Redeliver {
            network,
            transaction_id,
        })) => {
            return run_mfa_material(
                Request::GovernanceMfaRedeliver {
                    network,
                    transaction_id: transaction_id.clone(),
                },
                Some(transaction_id),
            )
            .await;
        }
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Commit {
            network,
            transaction_id,
        })) => {
            return run_mfa_transaction(Request::GovernanceMfaCommit {
                network,
                transaction_id,
            })
            .await;
        }
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Abort {
            network,
            transaction_id,
        })) => {
            return run_mfa_transaction(Request::GovernanceMfaAbort {
                network,
                transaction_id,
            })
            .await;
        }
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Status { network })) => {
            Request::GovernanceMfaStatus { network }
        }
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Disable { network, code })) => {
            Request::GovernanceMfaDisable { network, code }
        }
    };
    let response = roundtrip(&request).await?;
    print_response(response)
}

/// Parse a CLI role argument.
fn parse_role(s: &str) -> Result<myownmesh_core::network_state::Role> {
    match s.to_ascii_lowercase().as_str() {
        "member" => Ok(myownmesh_core::network_state::Role::Member),
        "controller" => Ok(myownmesh_core::network_state::Role::Controller),
        "owner" => Ok(myownmesh_core::network_state::Role::Owner),
        other => bail!("invalid role '{other}' — expected member | controller | owner"),
    }
}

/// Pretty-print a daemon response's data payload, or bail on error.
fn print_response(response: Response) -> Result<()> {
    if !response.ok {
        let msg = response
            .error
            .unwrap_or_else(|| "(no error message)".into());
        bail!("daemon error: {msg}");
    }
    let body = response.data.unwrap_or(Value::Null);
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MfaEnrollmentData {
    secret: String,
    otpauth_uri: String,
    recovery_codes: Vec<String>,
    transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MfaTransactionData {
    network: String,
    transaction_id: String,
    state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    otpauth_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_codes: Option<Vec<String>>,
}

fn response_error(response: &Response) -> anyhow::Error {
    anyhow!(
        "{}",
        response
            .error
            .as_deref()
            .unwrap_or("daemon refused the MFA request")
    )
}

fn parse_mfa_enrollment(
    response: &Response,
    expected_transaction_id: Option<&str>,
) -> Result<MfaEnrollmentData> {
    if !response.ok {
        return Err(response_error(response));
    }
    let data = response
        .data
        .clone()
        .ok_or_else(|| anyhow!("MFA enrollment response has no data"))?;
    let enrollment: MfaEnrollmentData =
        serde_json::from_value(data).context("malformed MFA enrollment material")?;
    if enrollment.transaction_id.trim().is_empty()
        || enrollment.secret.trim().is_empty()
        || enrollment.otpauth_uri.trim().is_empty()
        || !enrollment.otpauth_uri.starts_with("otpauth://")
        || enrollment.recovery_codes.is_empty()
        || enrollment
            .recovery_codes
            .iter()
            .any(|code| code.trim().is_empty())
    {
        bail!("MFA enrollment response has incomplete or malformed material");
    }
    if let Some(expected) = expected_transaction_id {
        if enrollment.transaction_id != expected {
            bail!(
                "MFA response transaction_id '{}' does not match requested transaction '{}'",
                enrollment.transaction_id,
                expected
            );
        }
    }
    Ok(enrollment)
}

fn parse_mfa_transaction(
    response: &Response,
    expected_network: &str,
    expected_transaction_id: &str,
) -> Result<MfaTransactionData> {
    if !response.ok {
        return Err(response_error(response));
    }
    let data = response
        .data
        .clone()
        .ok_or_else(|| anyhow!("MFA transaction response has no data"))?;
    let transaction: MfaTransactionData =
        serde_json::from_value(data).context("malformed MFA transaction response")?;
    if transaction.network != expected_network
        || transaction.transaction_id != expected_transaction_id
    {
        bail!(
            "MFA response identity ({}, {}) does not match requested ({}, {})",
            transaction.network,
            transaction.transaction_id,
            expected_network,
            expected_transaction_id
        );
    }
    match transaction.state.as_str() {
        "prepared" => {
            if transaction
                .secret
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
                || transaction
                    .otpauth_uri
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty()
                || transaction.recovery_codes.as_ref().is_none_or(|codes| {
                    codes.is_empty() || codes.iter().any(|code| code.trim().is_empty())
                })
            {
                bail!("prepared MFA transaction has incomplete recovery material");
            }
        }
        "committed" | "absent" => {
            if transaction.secret.is_some()
                || transaction.otpauth_uri.is_some()
                || transaction.recovery_codes.is_some()
            {
                bail!(
                    "terminal MFA transaction '{}' unexpectedly carries recovery material",
                    transaction.state
                );
            }
        }
        other => bail!("unknown MFA transaction state '{other}'"),
    }
    Ok(transaction)
}

fn recovery_failure(
    network: &str,
    transaction_id: &str,
    detail: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow!(
        "MFA transaction '{transaction_id}' for network '{network}' could not be settled: {detail}; use `myownmesh ctl governance mfa query {network} {transaction_id}` and, if it is prepared, `myownmesh ctl governance mfa redeliver {network} {transaction_id}`"
    )
}

fn render_json_and_flush<T: Serialize>(value: &T) -> Result<()> {
    use std::io::Write as _;
    let rendered = serde_json::to_string_pretty(value)?;
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(rendered.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

async fn settle_mfa_with<S, Fut>(
    network: String,
    transaction_id: String,
    mut send: S,
) -> Result<MfaTransactionData>
where
    S: FnMut(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response>>,
{
    let commit_request = || Request::GovernanceMfaCommit {
        network: network.clone(),
        transaction_id: transaction_id.clone(),
    };
    match send(commit_request()).await {
        Ok(response) => {
            let transaction = parse_mfa_transaction(&response, &network, &transaction_id)
                .map_err(|error| recovery_failure(&network, &transaction_id, error))?;
            match transaction.state.as_str() {
                "committed" => return Ok(transaction),
                "prepared" => {}
                "absent" => {
                    return Err(recovery_failure(
                        &network,
                        &transaction_id,
                        "the exact transaction is absent",
                    ));
                }
                _ => unreachable!("validated transaction state"),
            }
        }
        Err(_) => return query_then_maybe_retry(network, transaction_id, &mut send).await,
    }

    retry_commit_then_query(network, transaction_id, &mut send).await
}

async fn query_then_maybe_retry<S, Fut>(
    network: String,
    transaction_id: String,
    send: &mut S,
) -> Result<MfaTransactionData>
where
    S: FnMut(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response>>,
{
    let response = send(Request::GovernanceMfaQuery {
        network: network.clone(),
        transaction_id: transaction_id.clone(),
    })
    .await
    .map_err(|error| recovery_failure(&network, &transaction_id, error))?;
    let transaction = parse_mfa_transaction(&response, &network, &transaction_id)
        .map_err(|error| recovery_failure(&network, &transaction_id, error))?;
    match transaction.state.as_str() {
        "committed" => Ok(transaction),
        "prepared" => retry_commit_then_query(network, transaction_id, send).await,
        "absent" => Err(recovery_failure(
            &network,
            &transaction_id,
            "the exact transaction is absent",
        )),
        _ => unreachable!("validated transaction state"),
    }
}

async fn retry_commit_then_query<S, Fut>(
    network: String,
    transaction_id: String,
    send: &mut S,
) -> Result<MfaTransactionData>
where
    S: FnMut(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response>>,
{
    let response = match send(Request::GovernanceMfaCommit {
        network: network.clone(),
        transaction_id: transaction_id.clone(),
    })
    .await
    {
        Ok(response) => response,
        Err(_) => return final_mfa_query(network, transaction_id, send).await,
    };
    let transaction = parse_mfa_transaction(&response, &network, &transaction_id)
        .map_err(|error| recovery_failure(&network, &transaction_id, error))?;
    match transaction.state.as_str() {
        "committed" => Ok(transaction),
        "prepared" => final_mfa_query(network, transaction_id, send).await,
        "absent" => Err(recovery_failure(
            &network,
            &transaction_id,
            "the exact transaction is absent",
        )),
        _ => unreachable!("validated transaction state"),
    }
}

async fn final_mfa_query<S, Fut>(
    network: String,
    transaction_id: String,
    send: &mut S,
) -> Result<MfaTransactionData>
where
    S: FnMut(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response>>,
{
    let response = send(Request::GovernanceMfaQuery {
        network: network.clone(),
        transaction_id: transaction_id.clone(),
    })
    .await
    .map_err(|error| recovery_failure(&network, &transaction_id, error))?;
    let transaction = parse_mfa_transaction(&response, &network, &transaction_id)
        .map_err(|error| recovery_failure(&network, &transaction_id, error))?;
    if transaction.state == "committed" {
        Ok(transaction)
    } else {
        Err(recovery_failure(
            &network,
            &transaction_id,
            format!(
                "final exact query returned '{}'; recovery remains available",
                transaction.state
            ),
        ))
    }
}

async fn enroll_with<S, Fut, O>(
    network: String,
    mut send: S,
    mut render: O,
) -> Result<MfaTransactionData>
where
    S: FnMut(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response>>,
    O: FnMut(&MfaEnrollmentData) -> Result<()>,
{
    let response = send(Request::GovernanceMfaPrepare {
        network: network.clone(),
    })
    .await?;
    let enrollment = parse_mfa_enrollment(&response, None)?;
    render(&enrollment)?;
    settle_mfa_with(network, enrollment.transaction_id, send).await
}

async fn run_mfa_prepare_and_commit(network: String) -> Result<()> {
    let final_state = enroll_with(
        network,
        |request| async move { roundtrip(&request).await },
        render_json_and_flush,
    )
    .await?;
    render_json_and_flush(&final_state)
}

async fn run_mfa_material(request: Request, expected_transaction_id: Option<String>) -> Result<()> {
    let response = roundtrip(&request).await?;
    let enrollment = parse_mfa_enrollment(&response, expected_transaction_id.as_deref())?;
    render_json_and_flush(&enrollment)
}

async fn run_mfa_transaction(request: Request) -> Result<()> {
    let (network, transaction_id) = match &request {
        Request::GovernanceMfaQuery {
            network,
            transaction_id,
        }
        | Request::GovernanceMfaCommit {
            network,
            transaction_id,
        }
        | Request::GovernanceMfaAbort {
            network,
            transaction_id,
        } => (network, transaction_id),
        _ => bail!("not an MFA transaction request"),
    };
    let response = roundtrip(&request).await?;
    if response.ok {
        parse_mfa_transaction(&response, network, transaction_id)?;
    }
    print_response(response)
}

/// Run a `services` subcommand. `status` is a plain request; `enable` /
/// `disable` are a read-modify-write: fetch the current services config,
/// flip the one service's `enabled` flag, and send it back.
async fn run_services(cmd: ServicesCmd) -> Result<()> {
    match cmd {
        ServicesCmd::Status => {
            let response = roundtrip(&Request::ServicesStatus).await?;
            print_response(response)
        }
        ServicesCmd::Enable { service } => set_service(&service, true).await,
        ServicesCmd::Disable { service } => set_service(&service, false).await,
    }
}

/// Open a connection-state trace stream and print each `ConnTrace`
/// record verbatim, one JSON object per line, until interrupted
/// (Ctrl-C) or the daemon shuts down. Output is clean JSONL by design
/// — pipe it straight into a file per machine and feed the files to
/// `scripts/merge-traces.py` to reconstruct a single cross-machine
/// timeline. See `docs/DEBUGGING-CONNECTIONS.md`.
async fn run_trace(network: String) -> Result<()> {
    let stream = connect_socket().await?;
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let line = serde_json::to_string(&Request::TraceSubscribe { network })? + "\n";
    writer
        .write_all(line.as_bytes())
        .await
        .context("write trace request")?;
    writer.flush().await.context("flush")?;

    // First line back is the subscribe ack (or an error for an unknown
    // network); everything after is the trace stream.
    let mut buf = String::new();
    let n = reader.read_line(&mut buf).await.context("read ack")?;
    if n == 0 {
        return Err(anyhow!("daemon closed connection without an ack"));
    }
    let ack: Response =
        serde_json::from_str(buf.trim()).with_context(|| format!("parse ack: {buf}"))?;
    if !ack.ok {
        bail!(
            "daemon error: {}",
            ack.error.unwrap_or_else(|| "(no error message)".into())
        );
    }

    use std::io::Write as _;
    let mut stdout = std::io::stdout();
    loop {
        buf.clear();
        let n = reader
            .read_line(&mut buf)
            .await
            .context("read trace line")?;
        if n == 0 {
            break; // daemon closed the stream
        }
        // `buf` already includes the trailing newline — print verbatim
        // so the output is byte-for-byte the daemon's JSONL.
        print!("{buf}");
        let _ = stdout.flush();
    }
    Ok(())
}

async fn set_service(service: &str, enabled: bool) -> Result<()> {
    let status = roundtrip(&Request::ServicesStatus).await?;
    if !status.ok {
        bail!(
            "daemon error: {}",
            status.error.unwrap_or_else(|| "(no error message)".into())
        );
    }
    let data = status.data.unwrap_or(Value::Null);
    let config_val = data
        .get("config")
        .cloned()
        .ok_or_else(|| anyhow!("daemon status missing services config"))?;
    let mut services: ServicesConfig =
        serde_json::from_value(config_val).context("parse current services config")?;
    match service {
        "node" => services.node.enabled = enabled,
        "signaling" => services.signaling.enabled = enabled,
        "stun" => services.stun.enabled = enabled,
        "turn" => services.turn.enabled = enabled,
        // `relay` was a name here. It selected ordinary-member application
        // payload forwarding, not TURN — a device that relays packets for peers
        // is `turn`. It falls through to the error below with the rest, which
        // is the point: an operator who types it is told the name does not
        // exist rather than quietly toggling something else.
        other => {
            bail!("unknown service '{other}' — expected node | signaling | stun | turn")
        }
    }
    // Capture the TURN port plan before `services` is moved, so we can
    // print the firewall checklist after a successful enable.
    let turn_help = if enabled && service == "turn" {
        Some((
            services.turn.port,
            services.turn.relay_port_min,
            services.turn.relay_port_max,
            services.turn.public_ip.clone(),
        ))
    } else {
        None
    };
    let response = roundtrip(&Request::ServicesSet { services }).await?;
    let ok = response.ok;
    print_response(response)?;
    if ok {
        if let Some((port, relay_min, relay_max, public_ip)) = turn_help {
            print_turn_firewall_help(port, relay_min, relay_max, &public_ip);
        }
    }
    Ok(())
}

/// Spell out the UDP ports a freshly-enabled TURN server needs reachable.
/// The #1 reason a self-hosted TURN "doesn't work" is that only the
/// control port (or nothing) is open — every relayed allocation flows
/// through a separate port in the relay range, and a cloud security group
/// blocks them even when the host firewall is off.
fn print_turn_firewall_help(port: u16, relay_min: u16, relay_max: u16, public_ip: &str) {
    println!();
    println!("TURN is on. For NAT'd peers to actually relay, these UDP ports must be");
    println!("reachable — at the host firewall AND your cloud/provider security group");
    println!("(a host firewall being inactive does NOT mean the provider lets them in):");
    println!("  • udp {port}  — STUN/TURN control");
    if relay_min == 0 {
        // Unbounded (default): relay sockets come from the OS ephemeral
        // range — open that whole range.
        println!("  • udp <OS ephemeral range>  — relay allocations (one port per active peer)");
        println!("    find your range:  sysctl net.ipv4.ip_local_port_range   (e.g. 32768 60999)");
        println!("ufw, if that's what you run (substitute your range):");
        println!("  sudo ufw allow {port}/udp");
        println!("  sudo ufw allow 32768:60999/udp");
        println!("(Want a smaller firewall rule? Pin services.turn.relay_port_min/max.)");
    } else {
        println!("  • udp {relay_min}:{relay_max}  — relay allocations (one port per active peer)");
        println!("ufw, if that's what you run:");
        println!("  sudo ufw allow {port}/udp");
        println!("  sudo ufw allow {relay_min}:{relay_max}/udp");
    }
    if public_ip.trim().is_empty() {
        println!(
            "Set services.turn.public_ip to this box's routable IP, too — TURN won't \
             start without it on a wildcard bind."
        );
    }
    println!("And point your stun./turn. DNS records at this box.");
}

/// Put the signaling relay behind a reverse proxy: enable it and bind it
/// to loopback so the only public door is the TLS one Caddy owns (no
/// plaintext `ws://host:4848` straight to the relay). Applied live via
/// the daemon — `ServicesSet` rebinds the listener without a restart.
/// Returns `Ok(true)` when applied, `Ok(false)` when the daemon isn't
/// reachable (the caller persists to config.json and asks for a restart
/// instead). Used by `myownmesh install caddy <domain>`.
pub(crate) async fn bind_signaling_loopback() -> Result<bool> {
    let status = match roundtrip(&Request::ServicesStatus).await {
        Ok(s) => s,
        Err(_) => return Ok(false), // daemon not running
    };
    if !status.ok {
        return Ok(false);
    }
    let Some(config_val) = status.data.unwrap_or(Value::Null).get("config").cloned() else {
        return Ok(false);
    };
    let mut services: ServicesConfig =
        serde_json::from_value(config_val).context("parse current services config")?;
    services.signaling.enabled = true;
    services.signaling.bind = "127.0.0.1".to_string();
    let response = roundtrip(&Request::ServicesSet { services }).await?;
    Ok(response.ok)
}

async fn roundtrip(request: &Request) -> Result<Response> {
    let stream = connect_socket().await?;
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let line = serde_json::to_string(request)? + "\n";
    writer
        .write_all(line.as_bytes())
        .await
        .context("write request")?;
    writer.flush().await.context("flush")?;

    let mut buf = String::new();
    let n = reader.read_line(&mut buf).await.context("read response")?;
    if n == 0 {
        return Err(anyhow!("daemon closed connection without a response"));
    }
    let resp: Response =
        serde_json::from_str(buf.trim()).with_context(|| format!("parse response: {buf}"))?;
    Ok(resp)
}

async fn connect_socket() -> Result<LocalSocketStream> {
    // Honor config.daemon.control_socket — the field exists precisely so
    // `myownmesh ctl` can reach a daemon whose socket was pinned elsewhere
    // (e.g. appliances whose data dir is exFAT, which cannot hold a Unix
    // socket at all — the NanoKVM pins it to tmpfs). Falling back to the
    // derived default keeps the no-config case working; a config that fails
    // to load falls back too rather than blocking a diagnostic tool.
    let pinned = myownmesh_core::MeshConfig::load()
        .ok()
        .and_then(|cfg| cfg.daemon.control_socket);
    let path = match pinned {
        Some(p) => p,
        None => myownmesh_core::dirs::data_dir()
            .context("data_dir")?
            .join("daemon.sock"),
    };
    #[cfg(unix)]
    let name = path
        .as_path()
        .to_fs_name::<GenericFilePath>()
        .context("path → fs_name")?;
    #[cfg(not(unix))]
    let name = "myownmesh.sock"
        .to_ns_name::<GenericNamespaced>()
        .context("default → ns_name")?;
    let _ = path;
    let stream = LocalSocketStream::connect(name)
        .await
        .context("connect daemon socket — is `myownmesh serve` running?")?;
    verify_local_server(&stream)?;
    Ok(stream)
}

#[cfg(windows)]
struct WindowsHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(windows)]
fn token_user_sid(token: windows_sys::Win32::Foundation::HANDLE) -> Result<Vec<u8>> {
    use windows_sys::Win32::Security::{GetLengthSid, GetTokenInformation, TokenUser, TOKEN_USER};

    let mut needed = 0_u32;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    anyhow::ensure!(needed != 0, "measure token user SID");
    let word = std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; (needed as usize).div_ceil(word)];
    anyhow::ensure!(
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } != 0,
        "read token user SID: {}",
        std::io::Error::last_os_error()
    );
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let sid_len = unsafe { GetLengthSid(token_user.User.Sid) };
    anyhow::ensure!(sid_len != 0, "token user SID has no length");
    Ok(unsafe {
        std::slice::from_raw_parts(token_user.User.Sid.cast::<u8>(), sid_len as usize).to_vec()
    })
}

#[cfg(windows)]
fn current_process_user_sid() -> Result<Vec<u8>> {
    use windows_sys::Win32::{
        Security::TOKEN_QUERY,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token = std::ptr::null_mut();
    anyhow::ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "open ctl process token: {}",
        std::io::Error::last_os_error()
    );
    let token = WindowsHandle(token);
    token_user_sid(token.0)
}

#[cfg(windows)]
fn process_user_sid(pid: u32) -> Result<Vec<u8>> {
    use windows_sys::Win32::{
        Security::TOKEN_QUERY,
        System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    };

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    anyhow::ensure!(
        !process.is_null(),
        "open named-pipe server process {pid}: {}",
        std::io::Error::last_os_error()
    );
    let process = WindowsHandle(process);
    let mut token = std::ptr::null_mut();
    anyhow::ensure!(
        unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } != 0,
        "open named-pipe server token {pid}: {}",
        std::io::Error::last_os_error()
    );
    let token = WindowsHandle(token);
    token_user_sid(token.0)
}

#[cfg(windows)]
fn verify_server_process_user(pid: u32, expected_sid: &[u8]) -> Result<()> {
    use windows_sys::Win32::Security::EqualSid;

    let server_sid = process_user_sid(pid)?;
    anyhow::ensure!(
        unsafe {
            EqualSid(
                server_sid.as_ptr().cast_mut().cast(),
                expected_sid.as_ptr().cast_mut().cast(),
            )
        } != 0,
        "named-pipe server process {pid} is not the ctl user"
    );
    Ok(())
}

#[cfg(windows)]
fn verify_local_server(stream: &LocalSocketStream) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let server_pid = match stream {
        LocalSocketStream::NamedPipe(pipe) => {
            let mut pid = 0_u32;
            anyhow::ensure!(
                unsafe { GetNamedPipeServerProcessId(pipe.inner().as_raw_handle(), &mut pid) } != 0
                    && pid != 0,
                "obtain named-pipe server process identity: {}",
                std::io::Error::last_os_error()
            );
            pid
        }
    };
    let expected_sid = current_process_user_sid()?;
    verify_server_process_user(server_pid, &expected_sid)
}

#[cfg(unix)]
fn verify_server_euid(server: u32, expected: u32) -> Result<()> {
    anyhow::ensure!(
        server == expected,
        "control server euid {server} does not match ctl euid {expected}"
    );
    Ok(())
}

#[cfg(unix)]
fn verify_local_server(stream: &LocalSocketStream) -> Result<()> {
    let credentials = stream
        .peer_creds()
        .context("read control server credentials")?;
    let server = credentials
        .euid()
        .context("control transport did not provide server euid")?;
    verify_server_euid(server, unsafe { libc::geteuid() })
}

#[cfg(not(any(unix, windows)))]
fn verify_local_server(_stream: &LocalSocketStream) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn enrollment_response(transaction_id: &str) -> Response {
        Response::ok(serde_json::json!({
            "secret": "JBSWY3DPEHPK3PXP",
            "otpauth_uri": "otpauth://totp/MyOwnMesh:laptop?secret=JBSWY3DPEHPK3PXP",
            "recovery_codes": ["alpha-beta", "gamma-delta"],
            "transaction_id": transaction_id,
        }))
    }

    fn transaction_response(network: &str, transaction_id: &str, state: &str) -> Response {
        let mut data = serde_json::json!({
            "network": network,
            "transaction_id": transaction_id,
            "state": state,
        });
        if state == "prepared" {
            data["secret"] = serde_json::json!("JBSWY3DPEHPK3PXP");
            data["otpauth_uri"] =
                serde_json::json!("otpauth://totp/MyOwnMesh:laptop?secret=JBSWY3DPEHPK3PXP");
            data["recovery_codes"] = serde_json::json!(["alpha-beta", "gamma-delta"]);
        }
        Response::ok(data)
    }

    fn request_operation(request: &Request) -> String {
        serde_json::to_value(request)
            .expect("request serializes")
            .get("op")
            .and_then(Value::as_str)
            .expect("request operation")
            .to_owned()
    }

    #[tokio::test]
    async fn mfa_enroll_displays_and_flushes_material_before_commit() {
        let network = "mesh".to_owned();
        let transaction_id = "txn-1";
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_send = Arc::clone(&seen);
        let mut responses = VecDeque::from([
            Ok(enrollment_response(transaction_id)),
            Ok(transaction_response(
                network.as_str(),
                transaction_id,
                "committed",
            )),
        ]);
        let displayed_and_flushed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let displayed_by_send = Arc::clone(&displayed_and_flushed);
        let displayed_by_render = Arc::clone(&displayed_and_flushed);
        let final_state = enroll_with(
            network,
            move |request| {
                let operation = request_operation(&request);
                if operation == "governance_mfa_commit" {
                    assert!(
                        displayed_by_send.load(std::sync::atomic::Ordering::SeqCst),
                        "commit cannot be sent before material is rendered and flushed"
                    );
                }
                seen_by_send.lock().unwrap().push(operation);
                let response = responses.pop_front().expect("scripted response");
                async move { response }
            },
            move |material| {
                assert_eq!(material.transaction_id, transaction_id);
                displayed_by_render.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .expect("enrollment settles");
        assert_eq!(final_state.state, "committed");
        assert!(displayed_and_flushed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            *seen.lock().unwrap(),
            ["governance_mfa_prepare", "governance_mfa_commit"]
        );
    }

    #[tokio::test]
    async fn mfa_lost_commit_ack_queries_exact_committed_transaction() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_send = Arc::clone(&seen);
        let mut responses = VecDeque::from([
            Ok(enrollment_response("txn-2")),
            Err(anyhow!("lost commit acknowledgement")),
            Ok(transaction_response("mesh", "txn-2", "committed")),
        ]);
        let final_state = enroll_with(
            "mesh".into(),
            move |request| {
                seen_by_send
                    .lock()
                    .unwrap()
                    .push(request_operation(&request));
                let response = responses.pop_front().expect("scripted response");
                async move { response }
            },
            |_| Ok(()),
        )
        .await
        .expect("query resolves committed transaction");
        assert_eq!(final_state.state, "committed");
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "governance_mfa_prepare",
                "governance_mfa_commit",
                "governance_mfa_query"
            ]
        );
    }

    #[tokio::test]
    async fn mfa_prepared_query_retries_one_exact_commit() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_send = Arc::clone(&seen);
        let mut responses = VecDeque::from([
            Ok(enrollment_response("txn-3")),
            Err(anyhow!("commit response lost")),
            Ok(transaction_response("mesh", "txn-3", "prepared")),
            Ok(transaction_response("mesh", "txn-3", "committed")),
        ]);
        let final_state = enroll_with(
            "mesh".into(),
            move |request| {
                seen_by_send
                    .lock()
                    .unwrap()
                    .push(request_operation(&request));
                let response = responses.pop_front().expect("scripted response");
                async move { response }
            },
            |_| Ok(()),
        )
        .await
        .expect("prepared query permits one retry");
        assert_eq!(final_state.state, "committed");
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "governance_mfa_prepare",
                "governance_mfa_commit",
                "governance_mfa_query",
                "governance_mfa_commit"
            ]
        );
    }

    #[tokio::test]
    async fn mfa_ambiguous_retry_queries_once_after_second_ambiguous_commit() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_send = Arc::clone(&seen);
        let mut responses = VecDeque::from([
            Ok(enrollment_response("txn-4")),
            Err(anyhow!("first commit acknowledgement lost")),
            Ok(transaction_response("mesh", "txn-4", "prepared")),
            Err(anyhow!("retry commit acknowledgement lost")),
            Ok(transaction_response("mesh", "txn-4", "committed")),
        ]);
        let final_state = enroll_with(
            "mesh".into(),
            move |request| {
                let value = serde_json::to_value(&request).expect("request serializes");
                seen_by_send.lock().unwrap().push(value);
                let response = responses.pop_front().expect("scripted response");
                async move { response }
            },
            |_| Ok(()),
        )
        .await
        .expect("final exact query resolves committed transaction");
        assert_eq!(final_state.state, "committed");
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.iter()
                .map(|request| request["op"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "governance_mfa_prepare",
                "governance_mfa_commit",
                "governance_mfa_query",
                "governance_mfa_commit",
                "governance_mfa_query"
            ]
        );
        for request in seen.iter().skip(1) {
            assert_eq!(request["network"], "mesh");
            assert_eq!(request["transaction_id"], "txn-4");
        }
    }

    #[tokio::test]
    async fn malformed_material_never_reaches_commit() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_send = Arc::clone(&seen);
        let malformed = Response::ok(serde_json::json!({
            "secret": "",
            "otpauth_uri": "not-an-otpauth-uri",
            "recovery_codes": [],
            "transaction_id": "txn-bad",
        }));
        let mut responses = VecDeque::from([Ok(malformed)]);
        let result = enroll_with(
            "mesh".into(),
            move |request| {
                seen_by_send
                    .lock()
                    .unwrap()
                    .push(request_operation(&request));
                let response = responses.pop_front().expect("scripted response");
                async move { response }
            },
            |_| panic!("malformed material must not be rendered"),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(*seen.lock().unwrap(), ["governance_mfa_prepare"]);
    }

    #[test]
    fn mfa_transaction_subcommands_preserve_exact_wire_mapping() {
        assert_eq!(
            request_operation(&Request::GovernanceMfaQuery {
                network: "mesh".into(),
                transaction_id: "txn".into()
            }),
            "governance_mfa_query"
        );
        assert_eq!(
            request_operation(&Request::GovernanceMfaRedeliver {
                network: "mesh".into(),
                transaction_id: "txn".into()
            }),
            "governance_mfa_redeliver"
        );
        assert_eq!(
            request_operation(&Request::GovernanceMfaCommit {
                network: "mesh".into(),
                transaction_id: "txn".into()
            }),
            "governance_mfa_commit"
        );
        assert_eq!(
            request_operation(&Request::GovernanceMfaAbort {
                network: "mesh".into(),
                transaction_id: "txn".into()
            }),
            "governance_mfa_abort"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_ctl_verifies_same_user_pipe_server_before_request() {
        use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced, ListenerOptions};

        let raw_name = format!(
            "myownmesh-ctl-auth-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        );
        let name = raw_name
            .clone()
            .to_ns_name::<GenericNamespaced>()
            .expect("pipe name is namespaced");
        let listener = ListenerOptions::new()
            .name(name)
            .create_tokio()
            .expect("same-user test pipe binds");
        let client_name = raw_name
            .to_ns_name::<GenericNamespaced>()
            .expect("pipe name is namespaced");
        let client = LocalSocketStream::connect(client_name)
            .await
            .expect("same-user ctl connects");
        verify_local_server(&client).expect("same-user server is verified before request");
        let server = listener.accept().await.expect("server accepts ctl");
        drop(server);
        drop(client);
        drop(listener);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_ctl_verifies_same_euid_server_before_request() {
        use interprocess::local_socket::{GenericFilePath, ListenerOptions};
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary control root");
        let parent = directory.path().join("private");
        std::fs::create_dir(&parent).expect("create private parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("make private parent owner-only");
        let path = parent.join("ctl.sock");
        let name = path
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("control socket path is a valid fs name");
        let listener = ListenerOptions::new()
            .name(name)
            .create_tokio()
            .expect("same-euid test socket binds");
        let client_name = path
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("control socket path is a valid fs name");
        let client = LocalSocketStream::connect(client_name)
            .await
            .expect("same-euid ctl connects");
        verify_local_server(&client).expect("same-euid server is verified before request");
        let server = listener.accept().await.expect("server accepts ctl");
        drop(server);
        drop(client);
        drop(listener);
    }

    #[cfg(unix)]
    #[test]
    fn unix_ctl_refuses_distinct_server_euid() {
        let expected = unsafe { libc::geteuid() };
        let foreign = expected ^ 1;
        verify_server_euid(expected, expected).expect("same euid is accepted");
        let error = verify_server_euid(foreign, expected).expect_err("foreign euid is refused");
        assert!(error.to_string().contains("does not match ctl euid"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_ctl_refuses_mismatched_or_unverifiable_server_sid() {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;

        let sid = current_process_user_sid().expect("current ctl SID");
        assert!(!sid.is_empty(), "current ctl SID is non-empty");
        verify_server_process_user(unsafe { GetCurrentProcessId() }, &sid)
            .expect("same-principal process SID matches");

        let mut mismatched_sid = sid.clone();
        *mismatched_sid.last_mut().expect("SID has bytes") ^= 1;
        let mismatch =
            verify_server_process_user(unsafe { GetCurrentProcessId() }, &mismatched_sid)
                .expect_err("mismatched SID is refused");
        assert!(mismatch.to_string().contains("not the ctl user"));

        assert!(
            verify_server_process_user(u32::MAX, &sid).is_err(),
            "an unverifiable server process is refused"
        );
    }
}
