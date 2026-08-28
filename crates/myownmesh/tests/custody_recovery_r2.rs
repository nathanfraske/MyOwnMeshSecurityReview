//! R2 process-death control for provisional MFA enrollment.
//!
//! The enrollment record is installed before its response is observable, but
//! it must become permanent only at the response's `Wrote::Sent` boundary. A
//! hard-dead child cannot run a Rust `Drop`, so this control keeps the two
//! orderings separate across a real process boundary: a prepared enrollment
//! must not strand a lock, while one whose material was acknowledged by the
//! caller must survive restart.
//!
//! The pipe is the lifecycle barrier. The parent blocks on the child's
//! explicit marker and then kills it; there are no timing guesses, polling
//! loops, sleeps, or test-side rollback calls for the prepared case.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

const CHILD_MODE: &str = "MYOWNMESH_R2_CHILD_MODE";
const CHILD_NETWORK: &str = "MYOWNMESH_R2_CHILD_NETWORK";

fn spawn_child(
    home: &std::path::Path,
    mode: &str,
) -> (Child, BufReader<std::process::ChildStdout>) {
    let mut child = Command::new(std::env::current_exe().expect("the integration test executable"))
        .arg("--exact")
        .arg("child_provisional_enrollment")
        .arg("--nocapture")
        .env("MYOWNMESH_HOME", home)
        .env(CHILD_MODE, mode)
        .env(CHILD_NETWORK, "r2-hard-death")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn provisional enrollment child");
    let stdout = child.stdout.take().expect("child stdout");
    (child, BufReader::new(stdout))
}

fn read_marker(reader: &mut BufReader<std::process::ChildStdout>) -> String {
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).expect("child lifecycle marker");
        assert!(
            read != 0,
            "child exited before publishing a lifecycle marker"
        );
        let marker = line.trim_end();
        if marker == "PREPARED"
            || marker == "KEPT"
            || (marker.starts_with("DELIVERED ") && marker.len() > "DELIVERED ".len())
        {
            return marker.to_owned();
        }
    }
}

#[test]
fn v4_r2_child_hard_death_distinguishes_prepared_from_delivered_enrollment() {
    let home = tempfile::tempdir().expect("isolated MyOwnMesh home");
    let network = "r2-hard-death";
    std::env::set_var("MYOWNMESH_HOME", home.path());

    // The child has installed the lock, but has not crossed the observable
    // response boundary. A hard stop is the real process-death edge: armed
    // Drop cannot run in the child, so restart must recover this provisional
    // record rather than treating it as a delivered enrollment.
    let (mut prepared, mut prepared_out) = spawn_child(home.path(), "prepared");
    assert_eq!(read_marker(&mut prepared_out), "PREPARED");
    assert!(
        myownmesh_core::custody::is_enrolled(network),
        "prepared child must first prove that its durable lock exists"
    );
    prepared.kill().expect("hard-stop prepared child");
    prepared.wait().expect("reap prepared child");
    assert!(
        !myownmesh_core::custody::is_enrolled(network),
        "restart must not strand a lock for material that never crossed Wrote::Sent"
    );

    // The delivered ordering uses the same child-side installation, but the
    // parent acknowledges the material before the child calls keep(). This is
    // the production equivalent of Wrote::Sent and must survive the child's
    // clean restart boundary.
    let (mut delivered, mut delivered_out) = spawn_child(home.path(), "delivered");
    let marker = read_marker(&mut delivered_out);
    let recovery_code = marker
        .strip_prefix("DELIVERED ")
        .expect("delivered enrollment marker carries one recovery code");
    assert!(
        !recovery_code.is_empty(),
        "the delivered marker must carry observable enrollment material"
    );
    assert!(myownmesh_core::custody::is_enrolled(network));
    delivered
        .stdin
        .as_mut()
        .expect("child stdin")
        .write_all(b"ACK\n")
        .expect("acknowledge delivered enrollment");
    assert_eq!(read_marker(&mut delivered_out), "KEPT");
    delivered.wait().expect("reap delivered child");
    assert!(
        myownmesh_core::custody::is_enrolled(network),
        "observably delivered enrollment remains after restart"
    );

    // Cleanup uses the material that was deliberately observable only in the
    // delivered branch. The prepared branch has no recovery material to use.
    myownmesh_core::custody::disable(network, recovery_code)
        .expect("disable delivered enrollment during test cleanup");
    assert!(!myownmesh_core::custody::is_enrolled(network));
}

#[test]
fn child_provisional_enrollment() {
    let (Some(mode), Some(network)) = (
        std::env::var_os(CHILD_MODE),
        std::env::var_os(CHILD_NETWORK),
    ) else {
        return;
    };
    let mode = mode.to_string_lossy();
    let network = network.to_string_lossy();
    let provisional = myownmesh_core::custody::install_provisional_enroll(&network, "r2-child")
        .expect("child installs provisional enrollment");

    if mode == "prepared" {
        println!("PREPARED");
    } else {
        let code = provisional
            .enrolled()
            .recovery_codes
            .first()
            .expect("enrollment has a recovery code");
        println!("DELIVERED {code}");
    }
    std::io::stdout()
        .flush()
        .expect("flush child lifecycle marker");

    let mut ack = String::new();
    std::io::stdin()
        .read_line(&mut ack)
        .expect("parent lifecycle acknowledgement");
    if mode == "delivered" && ack.trim() == "ACK" {
        provisional.keep();
        println!("KEPT");
        std::io::stdout().flush().expect("flush kept marker");
    }
}
