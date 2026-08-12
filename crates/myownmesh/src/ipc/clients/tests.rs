//! Controls for the IPC client registry.
//!
//! One module rather than one per operation, because almost every control here
//! spans more than one of them: a disconnect is asserted against claims,
//! subscriptions and pending calls at once, and splitting them by subject would
//! have put the fixtures in one file and the assertions in another.

use super::*;

fn fresh_client(
    registry: &ClientRegistry,
) -> (
    Arc<ClientHandle>,
    myownmesh_core::ResourceMailboxReceiver<ServerOut>,
) {
    let (tx, rx) = myownmesh_core::resource_mailbox(crate::test_application_scope())
        .expect("the daemon test grant funds one client writer mailbox");
    let handle = registry
        .register(tx)
        .expect("the daemon test grant funds one client record");
    (handle, rx)
}

#[test]
fn client_id_roundtrips_through_string() {
    let id = ClientId(42);
    assert_eq!(id.to_string(), "c42");
    let parsed: ClientId = "c42".parse().expect("parse");
    assert_eq!(parsed, id);
    assert!("not-an-id".parse::<ClientId>().is_err());
    assert!("c-99".parse::<ClientId>().is_err());
}

#[test]
fn ids_are_monotonic_and_unique() {
    let reg = ClientRegistry::default();
    let (a, _ra) = fresh_client(&reg);
    let (b, _rb) = fresh_client(&reg);
    let (c, _rc) = fresh_client(&reg);
    assert_eq!(a.id, ClientId(0));
    assert_eq!(b.id, ClientId(1));
    assert_eq!(c.id, ClientId(2));
    assert!(reg.client(a.id).is_some());
    assert!(reg.client(ClientId(99)).is_none());
    assert!(reg.authenticate(a.id, reg.capability(&a)).is_some());
    assert!(reg.authenticate(b.id, reg.capability(&a)).is_none());
}

#[test]
fn disconnect_winner_returns_completed_install_to_its_sole_cleanup_owner() {
    #[derive(Debug)]
    struct Completed(Arc<AtomicU64>);
    impl Drop for Completed {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    let reg = ClientRegistry::default();
    let (owner, _) = fresh_client(&reg);
    reg.unregister(owner.id).expect("registered owner");
    let drops = Arc::new(AtomicU64::new(0));
    let installed = Arc::new(AtomicBool::new(false));
    let installed_probe = installed.clone();
    let returned = reg
        .install_if_live(
            &owner,
            LeasedMap::<ClaimKey, ()>::entry_claim(),
            Completed(drops.clone()),
            move |completed, _entry| {
                installed_probe.store(true, Ordering::Release);
                completed
            },
        )
        .expect_err("disconnect won the shared table seam");
    assert!(!installed.load(Ordering::Acquire));
    assert_eq!(drops.load(Ordering::Acquire), 0);
    drop(returned);
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

/// The other side of the seam from
/// `disconnect_winner_returns_completed_install_to_its_sole_cleanup_owner`:
/// an install that lands while its owner is still registered stays landed,
/// and the disconnect path hands back the very handle it landed in — which
/// is what lets the caller's drain find it and close it.
///
/// Bounded deliberately, and the bound is worth stating. A real
/// `RealtimeFlowHandle` is `pub(crate)` to core and cannot be minted from
/// this crate, so this drives `install_if_live` generically rather than
/// `install_realtime_flow`. The ordering under test lives entirely in that
/// seam — the flow table is only what the closure happens to write to — but
/// the consequence is that the end-to-end install → disconnect → drain →
/// close path is still uncovered here.
#[test]
fn an_install_that_wins_the_seam_survives_the_disconnect_that_must_clean_it_up() {
    let reg = ClientRegistry::default();
    let (owner, _) = fresh_client(&reg);
    let table: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));

    let landed = table.clone();
    reg.install_if_live(
        &owner,
        LeasedMap::<ClaimKey, ()>::entry_claim(),
        7_u32,
        move |value, _entry| landed.lock().push(value),
    )
    .expect("a registered, connected owner admits the install");
    assert_eq!(&*table.lock(), &[7], "the install ran");

    let returned = reg.unregister(owner.id).expect("registered owner");
    assert!(
        Arc::ptr_eq(&returned.handle, &owner),
        "disconnect answers with the same handle the install landed in"
    );
    assert_eq!(
        &*table.lock(),
        &[7],
        "unregister does not undo a completed install — the drain that runs \
         after it is what releases one, and it can only release what is \
         still there"
    );

    let refused = table.clone();
    assert!(
        reg.install_if_live(
            &owner,
            LeasedMap::<ClaimKey, ()>::entry_claim(),
            9_u32,
            move |value, _entry| refused.lock().push(value)
        )
        .is_err(),
        "the same owner admits nothing once it has disconnected"
    );
    assert_eq!(
        &*table.lock(),
        &[7],
        "and the refused value never reached the table"
    );
}

#[test]
fn claim_method_takes_ownership_and_displaces_prior() {
    let reg = ClientRegistry::default();
    let (a, _ra) = fresh_client(&reg);
    let (b, _rb) = fresh_client(&reg);
    let key = ("net".to_string(), "infer".to_string());

    let prev = reg
        .claim_method(key.clone(), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");
    assert!(prev.is_none());
    assert_eq!(reg.handler_owner(&key), Some(a.id));
    assert!(a.method_claims.holds(&key));

    let prev = reg
        .claim_method(key.clone(), a.id, HandlerMode::Single)
        .expect("re-claiming a method this client already holds funds nothing new");
    assert!(prev.is_none());

    let prev = reg
        .claim_method(key.clone(), b.id, HandlerMode::Stream)
        .expect("the daemon test grant funds the displacing claim");
    assert_eq!(prev, Some(a.id));
    assert_eq!(reg.handler_owner(&key), Some(b.id));
    assert_eq!(reg.handler_mode(&key), Some(HandlerMode::Stream));
    assert!(b.method_claims.holds(&key));
    assert!(!a.method_claims.holds(&key));
}

#[test]
fn release_method_only_succeeds_for_current_owner() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "infer".to_string());

    reg.claim_method(key.clone(), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");

    let foreign = reg.release_method(&key, b.id);
    assert!(!foreign.released);
    assert!(
        !foreign.forget,
        "a release that changed nothing cannot orphan the handler it left alone"
    );
    assert_eq!(reg.handler_owner(&key), Some(a.id));
    assert_eq!(reg.handler_mode(&key), Some(HandlerMode::Single));

    let owned = reg.release_method(&key, a.id);
    assert!(owned.released);
    assert!(
        owned.forget,
        "the last claim on a method leaves its synthetic handler serving nobody"
    );
    assert!(reg.handler_owner(&key).is_none());
    assert!(
        reg.handler_mode(&key).is_none(),
        "and the record of it is released with the claim rather than kept forever"
    );
    assert!(!a.method_claims.holds(&key));

    let again = reg.release_method(&key, a.id);
    assert!(!again.released);
    assert!(
        !again.forget,
        "forgetting is answered once; a second release has no handler to orphan"
    );
}

#[test]
fn unregister_drops_claims_and_subscriptions() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let method_key = ("net".to_string(), "infer".to_string());
    let channel_key = ("net".to_string(), "catalog".to_string());

    reg.claim_method(method_key.clone(), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");
    reg.subscribe_channel(channel_key.clone(), a.id)
        .expect("the daemon test grant funds one channel subscription");

    assert_eq!(reg.handler_owner(&method_key), Some(a.id));
    assert_eq!(reg.channel_subscribers(&channel_key), vec![a.id]);

    let removed = reg.unregister(a.id).expect("registered client");

    assert!(reg.handler_owner(&method_key).is_none());
    assert!(reg.channel_subscribers(&channel_key).is_empty());
    assert!(reg.client(a.id).is_none());
    assert_eq!(
        removed.forget,
        vec![method_key],
        "a disconnect is the last unclaim too, and it names the handler the \
         caller has to forget through its network"
    );
}

#[test]
fn unregister_doesnt_collateral_drop_a_displacing_claim() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "infer".to_string());

    reg.claim_method(key.clone(), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");
    reg.claim_method(key.clone(), b.id, HandlerMode::Single)
        .expect("the daemon test grant funds the displacing claim");
    assert_eq!(reg.handler_owner(&key), Some(b.id));

    let removed = reg.unregister(a.id).expect("registered client");
    assert_eq!(reg.handler_owner(&key), Some(b.id));
    assert!(
        removed.forget.is_empty(),
        "the displaced client is not the last claimant, so the handler b now \
         owns is not its to have forgotten"
    );
}

#[test]
fn channel_subscribe_first_subscriber_flag() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = ("net".to_string(), "catalog".to_string());

    assert!(
        reg.subscribe_channel(key.clone(), a.id)
            .expect("the daemon test grant funds one channel subscription"),
        "first sub"
    );
    assert!(
        !reg.subscribe_channel(key.clone(), b.id)
            .expect("the daemon test grant funds a second member"),
        "second sub"
    );
    assert!(
        !reg.subscribe_channel(key.clone(), b.id)
            .expect("re-subscribing funds no second member"),
        "a repeat subscription is not a first one"
    );
    assert_eq!(reg.channel_subscribers(&key), vec![a.id, b.id]);

    assert!(!reg.unsubscribe_channel(&key, b.id));
    assert!(reg.unsubscribe_channel(&key, a.id));
    assert!(
        reg.unsubscribe_channel(&key, a.id),
        "an emptied channel is removed with its last member, and an unknown \
         channel has no subscribers either"
    );
}

#[tokio::test]
async fn exact_owner_coordinates_and_operation_identity_all_match() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    let key = PendingKey {
        network: "n".into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: "same".into(),
        class: HandlerMode::Single,
    };
    let (tx, rx) = oneshot::channel();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Single(tx)) else {
        panic!("first claim must be vacant")
    };
    assert!(!reg.resolve_exact_single(
        &key,
        b.id,
        ticket.operation_id(),
        Ok(serde_json::json!("foreign"))
    ));
    assert!(!reg.resolve_exact_single(
        &key,
        a.id,
        ticket.operation_id() + 1,
        Ok(serde_json::json!("stale"))
    ));
    assert!(reg.resolve_exact_single(
        &key,
        a.id,
        ticket.operation_id(),
        Ok(serde_json::json!("mine"))
    ));
    assert_eq!(
        rx.await.expect("settled").expect("success"),
        serde_json::json!("mine")
    );
}

#[test]
fn collision_refuses_newcomer_and_disconnect_truthfully_settles_owner() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key = PendingKey {
        network: "n".into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: "same".into(),
        class: HandlerMode::Single,
    };
    let (first_tx, first_rx) = oneshot::channel();
    let Ok(_ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Single(first_tx))
    else {
        panic!("incumbent must be vacant")
    };
    let (new_tx, _new_rx) = oneshot::channel();
    assert!(reg
        .insert_exact_pending(key, a.id, PendingInbound::Single(new_tx))
        .is_err());
    reg.unregister(a.id);
    assert!(
        matches!(first_rx.blocking_recv(), Ok(Err(message)) if message.contains("disconnected"))
    );
}

#[test]
fn identical_remote_id_in_distinct_scopes_does_not_displace() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key = |network: &str| PendingKey {
        network: network.into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: "same".into(),
        class: HandlerMode::Single,
    };
    let (tx_a, _) = oneshot::channel();
    let (tx_b, _) = oneshot::channel();
    assert!(reg
        .insert_exact_pending(key("a"), a.id, PendingInbound::Single(tx_a))
        .is_ok());
    assert!(reg
        .insert_exact_pending(key("b"), a.id, PendingInbound::Single(tx_b))
        .is_ok());
}

#[tokio::test]
async fn handler_displacement_settles_only_that_exact_claim() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let (b, _) = fresh_client(&reg);
    reg.claim_method(("n".into(), "m".into()), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds one method claim");
    reg.claim_method(("n".into(), "other".into()), a.id, HandlerMode::Single)
        .expect("the daemon test grant funds a second method claim");
    let key = |method: &str| PendingKey {
        network: "n".into(),
        method: method.into(),
        remote_peer: "peer".into(),
        remote_request_id: "same".into(),
        class: HandlerMode::Single,
    };
    let (m_tx, m_rx) = oneshot::channel();
    let (other_tx, other_rx) = oneshot::channel();
    let Ok(_m) = reg.insert_exact_pending(key("m"), a.id, PendingInbound::Single(m_tx)) else {
        panic!("m")
    };
    let Ok(other) = reg.insert_exact_pending(key("other"), a.id, PendingInbound::Single(other_tx))
    else {
        panic!("other")
    };
    assert_eq!(
        reg.claim_method(("n".into(), "m".into()), b.id, HandlerMode::Single)
            .expect("the daemon test grant funds the displacing claim"),
        Some(a.id)
    );
    assert!(matches!(m_rx.await, Ok(Err(message)) if message.contains("displaced")));
    assert!(reg.resolve_exact_single(
        &key("other"),
        a.id,
        other.operation_id(),
        Ok(serde_json::json!("still-owned"))
    ));
    assert!(matches!(other_rx.await, Ok(Ok(value)) if value == serde_json::json!("still-owned")));
}

/// A stream mailbox for one control, funded from the test grant.
fn stream_mailbox() -> (
    myownmesh_core::ResourceMailboxSender<myownmesh_core::rpc::RpcStreamItem>,
    myownmesh_core::ResourceMailboxReceiver<myownmesh_core::rpc::RpcStreamItem>,
) {
    myownmesh_core::resource_mailbox(crate::test_application_scope())
        .expect("the daemon test grant funds one inbound stream queue")
}

fn stream_key(request_id: &str) -> PendingKey {
    PendingKey {
        network: "n".into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: request_id.into(),
        class: HandlerMode::Stream,
    }
}

fn next_item(
    delivery: Option<myownmesh_core::ResourceMailboxDelivery<myownmesh_core::rpc::RpcStreamItem>>,
) -> Option<myownmesh_core::rpc::RpcStreamItem> {
    delivery.map(|delivery| delivery.into_parts().0)
}

/// The terminal item is delivered behind a chunk already resident in the
/// queue, never ahead of it.
///
/// This replaces a control that proved the same ordering by filling a
/// one-item channel and watching the closer block. That proof is gone
/// because the capacity it depended on is gone: the queue is bounded by
/// what the owner funded, measured per chunk, not by a number of chunks.
/// The property it was protecting is unchanged and is asserted directly
/// here, with no fabricated blocked state standing in for it.
#[tokio::test]
async fn a_terminal_item_is_delivered_behind_a_resident_chunk() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key = stream_key("ordered");
    let (tx, mut rx) = stream_mailbox();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Stream(tx)) else {
        panic!("stream claim")
    };
    let operation_id = ticket.operation_id();
    assert!(reg.push_exact_stream(&key, a.id, operation_id, serde_json::json!(1)));
    assert!(reg.close_exact_stream(&key, a.id, operation_id, None));
    assert_eq!(
        next_item(rx.recv().await),
        Some(myownmesh_core::rpc::RpcStreamItem::Chunk(
            serde_json::json!(1)
        )),
        "the resident chunk is delivered first"
    );
    assert_eq!(
        next_item(rx.recv().await),
        Some(myownmesh_core::rpc::RpcStreamItem::End(Ok(()))),
        "the terminal item follows it rather than overtaking it"
    );
}

/// Once a stream has been settled, no further chunk can be written into it.
///
/// The settlement removes the record and fires its cancellation under the
/// registry's tables, before the terminal item goes out, so a later push
/// finds nothing to push into. That is what keeps a chunk from appearing
/// after the `End` its peer has already been told is final — and it is now
/// the whole of the guarantee, because with no queue capacity there is no
/// such thing as a chunk parked behind one.
#[tokio::test]
async fn a_chunk_cannot_be_written_after_terminal_settlement() {
    let reg = ClientRegistry::default();
    let (owner, _) = fresh_client(&reg);
    let owner_id = owner.id;
    let key = stream_key("settled");
    let (tx, mut rx) = stream_mailbox();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), owner_id, PendingInbound::Stream(tx))
    else {
        panic!("vacant stream")
    };
    let operation_id = ticket.operation_id();
    assert!(reg.push_exact_stream(&key, owner_id, operation_id, serde_json::json!(1)));
    assert!(reg.close_exact_stream(&key, owner_id, operation_id, None));
    assert!(
        !reg.push_exact_stream(&key, owner_id, operation_id, serde_json::json!(2)),
        "a chunk offered after settlement is refused rather than queued"
    );
    assert_eq!(
        next_item(rx.recv().await),
        Some(myownmesh_core::rpc::RpcStreamItem::Chunk(
            serde_json::json!(1)
        ))
    );
    assert_eq!(
        next_item(rx.recv().await),
        Some(myownmesh_core::rpc::RpcStreamItem::End(Ok(())))
    );
    assert!(
        next_item(rx.recv().await).is_none(),
        "nothing follows the terminal item"
    );
}

#[tokio::test]
async fn stream_terminal_error_is_preserved_exactly() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key = PendingKey {
        network: "n".into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: "err".into(),
        class: HandlerMode::Stream,
    };
    let (tx, mut rx) = stream_mailbox();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Stream(tx)) else {
        panic!("stream claim")
    };
    assert!(reg.close_exact_stream(&key, a.id, ticket.operation_id(), Some("denied".into())));
    assert_eq!(
        next_item(rx.recv().await),
        Some(myownmesh_core::rpc::RpcStreamItem::End(
            Err("denied".into())
        ))
    );
}

#[tokio::test]
async fn wrong_response_class_retains_same_operation_identity() {
    let reg = ClientRegistry::default();
    let (a, _) = fresh_client(&reg);
    let key = PendingKey {
        network: "n".into(),
        method: "m".into(),
        remote_peer: "peer".into(),
        remote_request_id: "typed".into(),
        class: HandlerMode::Stream,
    };
    let (tx, mut rx) = stream_mailbox();
    let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Stream(tx)) else {
        panic!("stream")
    };
    assert!(!reg.resolve_exact_single(
        &key,
        a.id,
        ticket.operation_id(),
        Ok(serde_json::json!("wrong"))
    ));
    assert!(reg.push_exact_stream(
        &key,
        a.id,
        ticket.operation_id(),
        serde_json::json!("same-op")
    ));
    assert_eq!(
        next_item(rx.recv().await),
        Some(myownmesh_core::rpc::RpcStreamItem::Chunk(
            serde_json::json!("same-op")
        ))
    );
}
