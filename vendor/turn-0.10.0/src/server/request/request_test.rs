use std::net::IpAddr;
use std::str::FromStr;

use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};
use util::vnet::net::*;

use super::*;
use crate::relay::relay_none::*;

const STATIC_KEY: &str = "ABC";

struct ChallengeAuth;

impl AuthHandler for ChallengeAuth {
    fn auth_handle(&self, username: &str, realm: &str, _: SocketAddr) -> Result<Vec<u8>> {
        if username == "user" && realm == "realm" {
            Ok(STATIC_KEY.as_bytes().to_vec())
        } else {
            Err(Error::ErrNoSuchUser)
        }
    }
}

fn nonce_budget() -> u64 {
    let charge = ResourceCharge::with_bytes(1, build_nonce().unwrap().capacity() as u64);
    charge.units + charge.retained_bytes.div_ceil(1024)
}

async fn challenge_fixture() -> Result<(
    Request,
    UdpSocket,
    Arc<crate::resource::BoundedTestAdmission>,
)> {
    let conn = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let allocation_manager = Arc::new(Manager::new(ManagerConfig {
        relay_addr_generator: Box::new(RelayAddressGeneratorNone {
            address: "127.0.0.1".to_owned(),
            net: Arc::new(Net::new(None)),
        }),
        alloc_close_notify: None,
        resource_admission: Arc::new(crate::resource::UnboundedTestAdmission),
        cleanup: crate::resource::CleanupStatus::new(&crate::resource::UnboundedTestAdmission)
            .expect("fixture manager cleanup"),
    }));
    let admission = Arc::new(crate::resource::BoundedTestAdmission::new(nonce_budget()));
    let mut request = Request::new(
        conn,
        client.local_addr()?,
        allocation_manager,
        Arc::new(ChallengeAuth),
    );
    request.resource_admission = Some(admission.clone());
    request.realm = "realm".to_owned();
    Ok((request, client, admission))
}

async fn receive_challenge(client: &UdpSocket, expected: ErrorCode) -> Result<String> {
    let mut bytes = [0; 1500];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut bytes))
        .await
        .expect("challenge response deadline")?;
    let mut message = Message {
        raw: bytes[..len].to_vec(),
        ..Default::default()
    };
    message.decode()?;
    let mut code = ErrorCodeAttribute::default();
    code.get_from(&message)?;
    assert!(code.code == expected, "unexpected challenge error code");
    let mut nonce = Nonce::new(ATTR_NONCE, String::new());
    nonce.get_from(&message)?;
    let mut realm = Realm::new(ATTR_REALM, String::new());
    realm.get_from(&message)?;
    assert_eq!(realm.text, "realm");
    Ok(nonce.text)
}

fn authenticated_challenge(nonce: String, key: &[u8]) -> Result<Message> {
    build_msg(
        Message::new().transaction_id,
        MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST),
        vec![
            Box::new(Username::new(ATTR_USERNAME, "user".to_owned())),
            Box::new(Realm::new(ATTR_REALM, "realm".to_owned())),
            Box::new(Nonce::new(ATTR_NONCE, nonce)),
            Box::new(MessageIntegrity(key.to_vec())),
        ],
    )
}

#[tokio::test]
async fn anonymous_challenges_reuse_one_budget_and_legitimate_authentication_survives() -> Result<()>
{
    let (mut request, client, admission) = challenge_fixture().await?;
    let anonymous = Message::new();
    let mut first = None;
    for _ in 0..64 {
        assert!(request
            .authenticate_request(&anonymous, METHOD_ALLOCATE)
            .await?
            .is_none());
        let nonce = receive_challenge(&client, CODE_UNAUTHORIZED).await?;
        if let Some((original, created)) = &first {
            assert!(original == &nonce, "challenge must be reused");
            assert!(request.nonces.lock().await.get(&nonce).unwrap().0 == *created);
        } else {
            let created = request.nonces.lock().await.get(&nonce).unwrap().0;
            first = Some((nonce, created));
        }
        assert_eq!(request.nonces.lock().await.len(), 1);
        assert_eq!(admission.remaining_for_test(), 0);
    }
    // A later legitimate client's fresh challenge still fits the same budget.
    assert!(request
        .authenticate_request(&anonymous, METHOD_ALLOCATE)
        .await?
        .is_none());
    let nonce = receive_challenge(&client, CODE_UNAUTHORIZED).await?;
    let valid = authenticated_challenge(nonce.clone(), STATIC_KEY.as_bytes())?;
    assert!(request
        .authenticate_request(&valid, METHOD_ALLOCATE)
        .await?
        .is_some());
    let invalid = authenticated_challenge(nonce, b"incorrect key")?;
    assert!(request
        .authenticate_request(&invalid, METHOD_ALLOCATE)
        .await
        .is_err());
    drop(request);
    assert_eq!(admission.remaining_for_test(), nonce_budget());
    Ok(())
}

#[tokio::test]
async fn expired_and_stale_challenges_release_before_replacement() -> Result<()> {
    let (mut request, client, admission) = challenge_fixture().await?;
    let old = request.current_nonce().await?;
    request.nonces.lock().await.get_mut(&old).unwrap().0 = Instant::now() - NONCE_LIFETIME;
    // Anonymous issuance must sweep an abandoned expired entry itself.
    assert!(request
        .authenticate_request(&Message::new(), METHOD_ALLOCATE)
        .await?
        .is_none());
    let current = receive_challenge(&client, CODE_UNAUTHORIZED).await?;
    assert!(current != old, "expired challenge must be replaced");
    assert!(!request.nonces.lock().await.contains_key(&old));
    assert_eq!(admission.remaining_for_test(), 0);
    // Presenting the old value must not consume another lease or authenticate.
    let stale = authenticated_challenge(old, STATIC_KEY.as_bytes())?;
    assert!(request
        .authenticate_request(&stale, METHOD_ALLOCATE)
        .await?
        .is_none());
    assert!(receive_challenge(&client, CODE_STALE_NONCE).await? == current);
    // Expiry on the authenticated path removes the presented entry as well.
    request.nonces.lock().await.get_mut(&current).unwrap().0 = Instant::now() - NONCE_LIFETIME;
    let stale = authenticated_challenge(current.clone(), STATIC_KEY.as_bytes())?;
    assert!(request
        .authenticate_request(&stale, METHOD_ALLOCATE)
        .await?
        .is_none());
    let replacement = receive_challenge(&client, CODE_STALE_NONCE).await?;
    assert!(
        replacement != current,
        "stale presented challenge must be replaced"
    );
    let valid = authenticated_challenge(replacement, STATIC_KEY.as_bytes())?;
    assert!(request
        .authenticate_request(&valid, METHOD_ALLOCATE)
        .await?
        .is_some());
    assert_eq!(request.nonces.lock().await.len(), 1);
    drop(request);
    assert_eq!(admission.remaining_for_test(), nonce_budget());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_challenge_issuance_funds_only_one_entry() -> Result<()> {
    let (request, _client, admission) = challenge_fixture().await?;
    let request = Arc::new(request);
    let barrier = Arc::new(tokio::sync::Barrier::new(17));
    let mut handles = Vec::new();
    for _ in 0..16 {
        let request = request.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            request.current_nonce().await
        }));
    }
    barrier.wait().await;
    let results = futures::future::join_all(handles).await;
    let expected = request.current_nonce().await?;
    for result in results {
        assert!(result.expect("issuer joined")? == expected);
    }
    assert_eq!(request.nonces.lock().await.len(), 1);
    assert_eq!(admission.remaining_for_test(), 0);
    drop(request);
    assert_eq!(admission.remaining_for_test(), nonce_budget());
    Ok(())
}

#[tokio::test]
async fn server_close_and_drop_release_shared_nonce_lease() -> Result<()> {
    use crate::resource::{BoundedTestAdmission, CleanupStatus};
    use crate::server::{
        config::{ConnConfig, ServerConfig},
        Server,
    };

    let cleanup_charge = CleanupStatus::charge().unwrap();
    let cleanup_slots = cleanup_charge.units + cleanup_charge.retained_bytes.div_ceil(1024);
    let limit = cleanup_slots + 2 + nonce_budget(); // read + command + one nonce
    for explicit_close in [true, false] {
        let admission = Arc::new(BoundedTestAdmission::new(limit));
        let conn = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let server_addr = conn.local_addr()?;
        let server = Server::new_with_resource_admission(
            ServerConfig {
                conn_configs: vec![ConnConfig {
                    conn,
                    relay_addr_generator: Box::new(RelayAddressGeneratorNone {
                        address: "127.0.0.1".to_owned(),
                        net: Arc::new(Net::new(None)),
                    }),
                }],
                realm: "realm".to_owned(),
                auth_handler: Arc::new(ChallengeAuth),
                channel_bind_timeout: Duration::ZERO,
                alloc_close_notify: None,
            },
            admission.clone(),
        )
        .await?;
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let anonymous = build_msg(
            Message::new().transaction_id,
            MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST),
            vec![],
        )?;
        client.send_to(&anonymous.raw, server_addr).await?;
        let _ = receive_challenge(&client, CODE_UNAUTHORIZED).await?;
        assert_eq!(admission.remaining_for_test(), 0);
        if explicit_close {
            server.close().await?;
            assert!(server.nonces.lock().await.is_empty());
            assert_eq!(admission.remaining_for_test(), limit - cleanup_slots);
            drop(server);
        } else {
            // Keep only join handles, not a server/map custodian. Dropping the
            // server closes its command sender; join its actual read tasks.
            let tasks = server.tasks.lock().await.take().unwrap();
            drop(server);
            let results = futures::future::join_all(tasks).await;
            for result in results {
                result.expect("dropped server read task joined")?;
            }
        }
        assert_eq!(admission.remaining_for_test(), limit);
    }
    Ok(())
}

#[tokio::test]
async fn test_allocation_lifetime_parsing() -> Result<()> {
    let lifetime = Lifetime(Duration::from_secs(5));

    let mut m = Message::new();
    let lifetime_duration = allocation_lifetime(&m);

    assert_eq!(
        lifetime_duration, DEFAULT_LIFETIME,
        "Allocation lifetime should be default time duration"
    );

    lifetime.add_to(&mut m)?;

    let lifetime_duration = allocation_lifetime(&m);
    assert_eq!(
        lifetime_duration, lifetime.0,
        "Expect lifetime_duration is {lifetime}, but {lifetime_duration:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_allocation_lifetime_overflow() -> Result<()> {
    let lifetime = Lifetime(MAXIMUM_ALLOCATION_LIFETIME * 2);

    let mut m2 = Message::new();
    lifetime.add_to(&mut m2)?;

    let lifetime_duration = allocation_lifetime(&m2);
    assert_eq!(
        lifetime_duration, DEFAULT_LIFETIME,
        "Expect lifetime_duration is {DEFAULT_LIFETIME:?}, but {lifetime_duration:?}"
    );

    Ok(())
}

struct TestAuthHandler;
impl AuthHandler for TestAuthHandler {
    fn auth_handle(&self, _username: &str, _realm: &str, _src_addr: SocketAddr) -> Result<Vec<u8>> {
        Ok(STATIC_KEY.as_bytes().to_vec())
    }
}

#[tokio::test]
async fn test_allocation_lifetime_deletion_zero_lifetime() -> Result<()> {
    //env_logger::init();

    let l = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    let allocation_manager = Arc::new(Manager::new(ManagerConfig {
        relay_addr_generator: Box::new(RelayAddressGeneratorNone {
            address: "0.0.0.0".to_owned(),
            net: Arc::new(Net::new(None)),
        }),
        alloc_close_notify: None,
        resource_admission: Arc::new(crate::resource::UnboundedTestAdmission),
        cleanup: crate::resource::CleanupStatus::new(&crate::resource::UnboundedTestAdmission)
            .expect("test cleanup admission"),
    }));

    let socket = SocketAddr::new(IpAddr::from_str("127.0.0.1")?, 5000);

    let mut r = Request::new(l, socket, allocation_manager, Arc::new(TestAuthHandler {}));

    {
        let mut nonces = r.nonces.lock().await;
        let nonce = STATIC_KEY.to_owned();
        let nonce_charge = ResourceCharge::with_bytes(
            1,
            u64::try_from(nonce.capacity()).map_err(|_| Error::ErrResourceAdmission)?,
        );
        let nonce_admission = crate::resource::BoundedTestAdmission::new(
            nonce_charge.units + nonce_charge.retained_bytes.div_ceil(1024),
        );
        let nonce_lease = nonce_admission
            .acquire(ResourceKind::Nonce, nonce_charge)
            .map_err(|_| Error::ErrResourceAdmission)?;
        nonces.insert(nonce, (Instant::now(), nonce_lease));
    }

    let five_tuple = FiveTuple {
        src_addr: r.src_addr,
        dst_addr: r.conn.local_addr()?,
        protocol: PROTO_UDP,
    };

    r.allocation_manager
        .create_allocation(
            five_tuple,
            Arc::clone(&r.conn),
            0,
            Duration::from_secs(3600),
            TextAttribute::new(ATTR_USERNAME, "user".into()),
            true,
        )
        .await?;
    assert!(r
        .allocation_manager
        .get_allocation(&five_tuple)
        .await
        .is_some());

    let m = build_msg(
        Message::new().transaction_id,
        MessageType::new(METHOD_REFRESH, CLASS_REQUEST),
        vec![
            Box::new(Lifetime::default()),
            Box::new(Nonce::new(ATTR_NONCE, STATIC_KEY.to_owned())),
            Box::new(Realm::new(ATTR_REALM, STATIC_KEY.to_owned())),
            Box::new(Username::new(ATTR_USERNAME, "user".to_owned())),
            Box::new(MessageIntegrity(STATIC_KEY.as_bytes().to_vec())),
        ],
    )?;

    r.handle_refresh_request(&m).await?;
    assert!(r
        .allocation_manager
        .get_allocation(&five_tuple)
        .await
        .is_none());

    Ok(())
}

struct AllocationOwnerAuth;

impl AuthHandler for AllocationOwnerAuth {
    fn auth_handle(&self, username: &str, realm: &str, _: SocketAddr) -> Result<Vec<u8>> {
        if matches!(username, "alice" | "bob") && realm == "realm" {
            Ok(generate_auth_key(username, realm, "owner-test-password"))
        } else {
            Err(Error::ErrNoSuchUser)
        }
    }
}

struct AllocationOwnerFixture {
    request: Request,
    client: UdpSocket,
    allocation: Arc<crate::allocation::Allocation>,
    five_tuple: FiveTuple,
    closed: tokio::sync::mpsc::Receiver<crate::allocation::AllocationInfo>,
}

async fn allocation_owner_fixture(lifetime: Duration) -> Result<AllocationOwnerFixture> {
    let conn = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let (close_tx, closed) = tokio::sync::mpsc::channel(1);
    let manager = Arc::new(Manager::new(ManagerConfig {
        relay_addr_generator: Box::new(RelayAddressGeneratorNone {
            address: "127.0.0.1".to_owned(),
            net: Arc::new(Net::new(None)),
        }),
        alloc_close_notify: Some(close_tx),
        resource_admission: Arc::new(crate::resource::UnboundedTestAdmission),
        cleanup: crate::resource::CleanupStatus::new(&crate::resource::UnboundedTestAdmission)
            .expect("owner fixture cleanup"),
    }));
    let mut request = Request::new(
        conn,
        client.local_addr()?,
        manager,
        Arc::new(AllocationOwnerAuth),
    );
    request.realm = "realm".to_owned();
    request.channel_bind_timeout = Duration::from_secs(600);
    let five_tuple = FiveTuple {
        src_addr: request.src_addr,
        dst_addr: request.conn.local_addr()?,
        protocol: PROTO_UDP,
    };
    let allocation = request
        .allocation_manager
        .create_allocation(
            five_tuple,
            request.conn.clone(),
            0,
            lifetime,
            Username::new(ATTR_USERNAME, "alice".to_owned()),
            true,
        )
        .await?;
    Ok(AllocationOwnerFixture {
        request,
        client,
        allocation,
        five_tuple,
        closed,
    })
}

async fn allocation_owner_message(
    request: &Request,
    method: Method,
    username: &str,
    mut attributes: Vec<Box<dyn Setter>>,
) -> Result<Message> {
    attributes.extend([
        Box::new(Username::new(ATTR_USERNAME, username.to_owned())) as Box<dyn Setter>,
        Box::new(Realm::new(ATTR_REALM, "realm".to_owned())),
        Box::new(Nonce::new(ATTR_NONCE, request.current_nonce().await?)),
        Box::new(MessageIntegrity(generate_auth_key(
            username,
            "realm",
            "owner-test-password",
        ))),
    ]);
    build_msg(
        Message::new().transaction_id,
        MessageType::new(method, CLASS_REQUEST),
        attributes,
    )
}

async fn receive_allocation_owner_response(client: &UdpSocket) -> Result<Message> {
    let mut bytes = [0; 1500];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut bytes))
        .await
        .expect("owner response deadline")?;
    let mut response = Message {
        raw: bytes[..len].to_vec(),
        ..Default::default()
    };
    response.decode()?;
    Ok(response)
}

async fn allocation_owner_response(
    client: &UdpSocket,
    request: &Message,
    username: &str,
    wrong_credentials: bool,
) -> Result<Message> {
    let mut response = receive_allocation_owner_response(client).await?;
    assert_eq!(response.transaction_id, request.transaction_id);
    assert!(response.typ.method == request.typ.method);
    assert!(
        response.typ.class
            == if wrong_credentials {
                CLASS_ERROR_RESPONSE
            } else {
                CLASS_SUCCESS_RESPONSE
            }
    );
    if wrong_credentials {
        let mut error = ErrorCodeAttribute::default();
        error.get_from(&response)?;
        assert!(error.code == CODE_WRONG_CREDENTIALS);
    }
    MessageIntegrity(generate_auth_key(username, "realm", "owner-test-password"))
        .check(&mut response)?;
    Ok(response)
}

async fn assert_original_allocation(fixture: &AllocationOwnerFixture) {
    let current = fixture
        .request
        .allocation_manager
        .get_allocation(&fixture.five_tuple)
        .await
        .expect("Alice's allocation must remain installed");
    assert!(Arc::ptr_eq(&current, &fixture.allocation));
    assert!(Manager::allocation_has_username(
        &current,
        &Username::new(ATTR_USERNAME, "alice".to_owned())
    ));
}

async fn close_allocation_owner_fixture(fixture: AllocationOwnerFixture) -> Result<()> {
    let AllocationOwnerFixture {
        request,
        allocation,
        five_tuple,
        ..
    } = fixture;
    request
        .allocation_manager
        .delete_allocation(&five_tuple)
        .await;
    // Remove the map owner and last test owner before joining the packet task:
    // its actual stop signal is the allocation's owned drop sender.
    drop(allocation);
    request.allocation_manager.close().await
}

#[tokio::test]
async fn allocation_username_refresh_rejects_other_user_without_extending_lifetime() -> Result<()> {
    let mut fixture = allocation_owner_fixture(Duration::from_secs(20)).await?;
    let message = allocation_owner_message(
        &fixture.request,
        METHOD_REFRESH,
        "bob",
        vec![Box::new(Lifetime(Duration::from_secs(600)))],
    )
    .await?;
    fixture.request.handle_refresh_request(&message).await?;
    allocation_owner_response(&fixture.client, &message, "bob", true).await?;
    assert_original_allocation(&fixture).await;
    // Complete real socket I/O before pausing time; only the allocation's
    // timer and its close notification participate in the virtual-time check.
    tokio::time::pause();
    // The original timer must still expire. A silently applied Bob refresh
    // would postpone this event to 600 seconds; virtual time keeps this bounded.
    let closed = tokio::time::timeout(Duration::from_secs(21), fixture.closed.recv())
        .await
        .expect("Bob must not extend Alice's original allocation lifetime")
        .expect("original allocation close notification");
    assert_eq!(closed.username, "alice");
    assert_eq!(closed.five_tuple, fixture.five_tuple);
    assert!(fixture
        .request
        .allocation_manager
        .get_allocation(&fixture.five_tuple)
        .await
        .is_none());
    drop(fixture.allocation);
    fixture.request.allocation_manager.close().await?;
    Ok(())
}

#[tokio::test]
async fn allocation_username_refresh_zero_rejects_other_user_and_owner_can_refresh_and_delete(
) -> Result<()> {
    let fixture = allocation_owner_fixture(Duration::from_secs(600)).await?;
    let AllocationOwnerFixture {
        mut request,
        client,
        allocation,
        five_tuple,
        ..
    } = fixture;
    let bob = allocation_owner_message(
        &request,
        METHOD_REFRESH,
        "bob",
        vec![Box::new(Lifetime(Duration::ZERO))],
    )
    .await?;
    request.handle_refresh_request(&bob).await?;
    allocation_owner_response(&client, &bob, "bob", true).await?;
    let current = request
        .allocation_manager
        .get_allocation(&five_tuple)
        .await
        .expect("Bob must not delete Alice's allocation");
    assert!(Arc::ptr_eq(&current, &allocation));
    drop(current);
    let refresh = allocation_owner_message(
        &request,
        METHOD_REFRESH,
        "alice",
        vec![Box::new(Lifetime(Duration::from_secs(300)))],
    )
    .await?;
    request.handle_refresh_request(&refresh).await?;
    let response = allocation_owner_response(&client, &refresh, "alice", false).await?;
    let mut lifetime = Lifetime::default();
    lifetime.get_from(&response)?;
    assert_eq!(lifetime.0, Duration::from_secs(300));
    let delete = allocation_owner_message(
        &request,
        METHOD_REFRESH,
        "alice",
        vec![Box::new(Lifetime(Duration::ZERO))],
    )
    .await?;
    request.handle_refresh_request(&delete).await?;
    allocation_owner_response(&client, &delete, "alice", false).await?;
    assert!(request
        .allocation_manager
        .get_allocation(&five_tuple)
        .await
        .is_none());
    drop(allocation);
    request.allocation_manager.close().await?;
    Ok(())
}

#[tokio::test]
async fn allocation_username_create_permission_rejects_other_user_without_mutation() -> Result<()> {
    let mut fixture = allocation_owner_fixture(Duration::from_secs(600)).await?;
    let peer: SocketAddr = "192.0.2.10:5000".parse()?;
    let attributes = || {
        vec![Box::new(PeerAddress {
            ip: peer.ip(),
            port: peer.port(),
        }) as Box<dyn Setter>]
    };
    let bob = allocation_owner_message(
        &fixture.request,
        METHOD_CREATE_PERMISSION,
        "bob",
        attributes(),
    )
    .await?;
    fixture
        .request
        .handle_create_permission_request(&bob)
        .await?;
    allocation_owner_response(&fixture.client, &bob, "bob", true).await?;
    assert_original_allocation(&fixture).await;
    assert!(!fixture.allocation.has_permission(&peer).await);
    assert!(fixture.allocation.get_channel_number(&peer).await.is_none());
    let alice = allocation_owner_message(
        &fixture.request,
        METHOD_CREATE_PERMISSION,
        "alice",
        attributes(),
    )
    .await?;
    fixture
        .request
        .handle_create_permission_request(&alice)
        .await?;
    allocation_owner_response(&fixture.client, &alice, "alice", false).await?;
    assert!(fixture.allocation.has_permission(&peer).await);
    close_allocation_owner_fixture(fixture).await?;
    Ok(())
}

#[tokio::test]
async fn allocation_username_channel_bind_rejects_other_user_without_mutation() -> Result<()> {
    let mut fixture = allocation_owner_fixture(Duration::from_secs(600)).await?;
    let peer: SocketAddr = "192.0.2.11:5001".parse()?;
    let channel = ChannelNumber(0x4000);
    let attributes = || {
        vec![
            Box::new(channel) as Box<dyn Setter>,
            Box::new(PeerAddress {
                ip: peer.ip(),
                port: peer.port(),
            }),
        ]
    };
    let bob = allocation_owner_message(&fixture.request, METHOD_CHANNEL_BIND, "bob", attributes())
        .await?;
    fixture.request.handle_channel_bind_request(&bob).await?;
    allocation_owner_response(&fixture.client, &bob, "bob", true).await?;
    assert_original_allocation(&fixture).await;
    assert!(!fixture.allocation.has_permission(&peer).await);
    assert!(fixture
        .allocation
        .get_channel_addr(&channel)
        .await
        .is_none());
    assert!(fixture.allocation.get_channel_number(&peer).await.is_none());
    let alice =
        allocation_owner_message(&fixture.request, METHOD_CHANNEL_BIND, "alice", attributes())
            .await?;
    fixture.request.handle_channel_bind_request(&alice).await?;
    allocation_owner_response(&fixture.client, &alice, "alice", false).await?;
    assert_eq!(
        fixture.allocation.get_channel_addr(&channel).await,
        Some(peer)
    );
    assert!(fixture.allocation.has_permission(&peer).await);
    close_allocation_owner_fixture(fixture).await?;
    Ok(())
}

#[tokio::test]
async fn allocation_username_stale_delete_preserves_replacement_at_same_tuple() -> Result<()> {
    let mut fixture = allocation_owner_fixture(Duration::from_secs(600)).await?;
    let manager = &fixture.request.allocation_manager;
    manager.delete_allocation(&fixture.five_tuple).await;
    let closed = fixture
        .closed
        .recv()
        .await
        .expect("original allocation closed");
    assert_eq!(closed.username, "alice");
    let replacement = manager
        .create_allocation(
            fixture.five_tuple,
            fixture.request.conn.clone(),
            0,
            Duration::from_secs(600),
            Username::new(ATTR_USERNAME, "bob".to_owned()),
            true,
        )
        .await?;
    assert!(
        !manager
            .delete_allocation_if_same(&fixture.five_tuple, &fixture.allocation)
            .await
    );
    let current = manager
        .get_allocation(&fixture.five_tuple)
        .await
        .expect("replacement must survive a stale exact-owner deletion");
    assert!(Arc::ptr_eq(&current, &replacement));
    assert!(Manager::allocation_has_username(
        &current,
        &Username::new(ATTR_USERNAME, "bob".to_owned())
    ));
    drop(current);
    drop(fixture.allocation);
    manager.delete_allocation(&fixture.five_tuple).await;
    drop(replacement);
    manager.close().await?;
    Ok(())
}

#[tokio::test]
async fn allocation_username_authentication_precedes_owner_rejection() -> Result<()> {
    let mut fixture = allocation_owner_fixture(Duration::from_secs(600)).await?;
    let peer: SocketAddr = "192.0.2.12:5002".parse()?;
    let channel = ChannelNumber(0x4001);
    for method in [
        METHOD_REFRESH,
        METHOD_CREATE_PERMISSION,
        METHOD_CHANNEL_BIND,
    ] {
        let mut message = allocation_owner_message(
            &fixture.request,
            method,
            "bob",
            vec![
                Box::new(Lifetime(Duration::ZERO)),
                Box::new(PeerAddress {
                    ip: peer.ip(),
                    port: peer.port(),
                }),
                Box::new(channel),
            ],
        )
        .await?;
        // Keep Bob's valid username and nonce but corrupt his final HMAC byte.
        // The request must fail authentication before the creator check.
        *message.raw.last_mut().expect("message integrity bytes") ^= 1;
        message.decode()?;
        assert!(fixture
            .request
            .process_message_handler(&message)
            .await
            .is_err());
        let response = receive_allocation_owner_response(&fixture.client).await?;
        assert_eq!(response.transaction_id, message.transaction_id);
        assert!(response.typ.method == method);
        assert!(response.typ.class == CLASS_ERROR_RESPONSE);
        let mut error = ErrorCodeAttribute::default();
        error.get_from(&response)?;
        assert!(error.code == CODE_BAD_REQUEST);
        assert_original_allocation(&fixture).await;
        assert!(!fixture.allocation.has_permission(&peer).await);
        assert!(fixture
            .allocation
            .get_channel_addr(&channel)
            .await
            .is_none());
    }
    close_allocation_owner_fixture(fixture).await
}
