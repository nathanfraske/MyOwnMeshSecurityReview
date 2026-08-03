//! Minimal single-threaded reproduction of the create_offer wedge, for
//! debugger PC-sampling under qemu-user: one guest thread, current-thread
//! tokio runtime, straight into the wedge path.
fn callback_policy() -> myownmesh_core::ConnectorCallbackPolicy {
    let raw = std::env::var("MYOWNMESH_LAB_CALLBACK_CAPACITY")
        .expect("set MYOWNMESH_LAB_CALLBACK_CAPACITY for this transport-lab probe");
    let capacity = std::num::NonZeroUsize::new(
        raw.parse::<usize>()
            .expect("MYOWNMESH_LAB_CALLBACK_CAPACITY must be an integer"),
    )
    .expect("MYOWNMESH_LAB_CALLBACK_CAPACITY must be nonzero");
    myownmesh_core::ConnectorCallbackPolicy::new(
        myownmesh_core::ConnectorCallbackMailboxCapacities::new(capacity, capacity),
        myownmesh_core::ConnectorCallbackServiceWeights::data_only(capacity, capacity),
        myownmesh_core::RealtimeConnectorPolicy::Disabled,
    )
    .expect("the explicit transport-lab callback policy is valid")
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let t = myownmesh_core::transport::Transport::new().unwrap();
        let (session, _rx) = t
            .open_peer(
                myownmesh_core::transport::Role::Offerer,
                &[],
                &[],
                callback_policy(),
            )
            .await
            .unwrap();
        eprintln!("[min] entering create_offer");
        let offer = session.create_offer().await.unwrap();
        eprintln!("[min] create_offer done: {} sdp bytes", offer.sdp.len());
    });
}
