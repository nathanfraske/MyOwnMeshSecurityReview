use myownmesh_core::config::{StunServiceConfig, TurnCredential, TurnServiceConfig};
use myownmesh_services::{StunServer, TurnServer};

fn stun_config(port: u16) -> StunServiceConfig {
    StunServiceConfig {
        enabled: true,
        bind: "127.0.0.1".into(),
        port,
    }
}

fn turn_config(port: u16) -> TurnServiceConfig {
    TurnServiceConfig {
        enabled: true,
        bind: "127.0.0.1".into(),
        port,
        public_ip: "127.0.0.1".into(),
        realm: "restart-custody".into(),
        credentials: vec![TurnCredential {
            username: "restart-user".into(),
            password: "restart-password".into(),
        }],
        max_bps_per_connection: 0,
        relay_port_min: 0,
        relay_port_max: 0,
    }
}

#[tokio::test]
async fn awaited_stun_stop_releases_exact_listener_for_immediate_restart() {
    let first = StunServer::start(&stun_config(0))
        .await
        .expect("initial STUN listener starts");
    let exact_addr = first.local_addr();

    first
        .stop_and_wait()
        .await
        .expect("STUN listener task reaches terminal state");

    let replacement = StunServer::start(&stun_config(exact_addr.port()))
        .await
        .expect("same STUN address is immediately reusable");
    assert_eq!(replacement.local_addr(), exact_addr);
    replacement
        .stop_and_wait()
        .await
        .expect("replacement STUN listener task reaches terminal state");
}

#[tokio::test]
async fn awaited_turn_stop_releases_exact_listener_for_immediate_restart() {
    let first = TurnServer::start(&turn_config(0))
        .await
        .expect("initial TURN listener starts");
    let exact_addr = first.local_addr();

    first
        .stop()
        .await
        .expect("TURN close task reaches terminal state");

    let replacement = TurnServer::start(&turn_config(exact_addr.port()))
        .await
        .expect("same TURN address is immediately reusable");
    assert_eq!(replacement.local_addr(), exact_addr);
    replacement
        .stop()
        .await
        .expect("replacement TURN close task reaches terminal state");
}
