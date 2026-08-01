//! Asking the control server what it thinks happened.
//!
//! A check that only reads our own output proves we sent something, not that it
//! was understood. `headscale nodes list` is the server's own view, and it is
//! what makes "the node registered" a claim about the server rather than about
//! us.

use std::process::Command;

/// The lab container, started by `tests/lab/lab.sh up`.
const CONTAINER: &str = "headscale-lab";

/// One row of `headscale nodes list`.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: u64,
    pub name: String,
    pub node_key: String,
    pub machine_key: String,
    pub addresses: Vec<String>,
}

/// Every node the server knows about.
///
/// `Err` means the question could not be asked — the container is not running,
/// or `podman` is absent — which callers must report as a skip. A check that
/// failed because the lab was down would make the suite unsafe to gate on.
pub fn nodes() -> Result<Vec<Node>, String> {
    let output = Command::new("podman")
        .args([
            "exec",
            CONTAINER,
            "headscale",
            "nodes",
            "list",
            "--output",
            "json",
        ])
        .output()
        .map_err(|e| format!("could not run podman: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "headscale nodes list failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("headscale nodes list is not JSON: {e}"))?;
    let rows = parsed
        .as_array()
        .ok_or("headscale nodes list is not an array")?;

    Ok(rows
        .iter()
        .map(|row| Node {
            id: row["id"].as_u64().unwrap_or(0),
            name: row["name"].as_str().unwrap_or_default().to_string(),
            node_key: row["node_key"].as_str().unwrap_or_default().to_string(),
            machine_key: row["machine_key"].as_str().unwrap_or_default().to_string(),
            addresses: row["ip_addresses"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect())
}

/// Delete one node.
///
/// Used by [`crate::runscope::RunScope`] to remove what a run registered. A
/// failure is returned rather than ignored so that the caller can say how many
/// nodes it failed to clean up — silent partial cleanup is how the accumulation
/// this exists to prevent starts again.
pub fn delete_node(node_id: u64) -> Result<(), String> {
    let output = Command::new("podman")
        .args([
            "exec",
            CONTAINER,
            "headscale",
            "nodes",
            "delete",
            "--identifier",
            &node_id.to_string(),
            "--force",
        ])
        .output()
        .map_err(|e| format!("could not run podman: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "headscale nodes delete {node_id} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// The node holding a given node key, if the server has one.
pub fn find_by_node_key<'a>(nodes: &'a [Node], node_key: &str) -> Option<&'a Node> {
    nodes.iter().find(|n| n.node_key == node_key)
}

/// What a node advertises, what an operator has approved, and what it is
/// actually serving.
#[derive(Debug, Clone, Default)]
pub struct Routes {
    pub available: Vec<String>,
    pub approved: Vec<String>,
    pub serving: Vec<String>,
}

/// `headscale nodes list-routes`, for one node.
pub fn routes(node_id: u64) -> Result<Routes, String> {
    let output = Command::new("podman")
        .args([
            "exec",
            CONTAINER,
            "headscale",
            "nodes",
            "list-routes",
            "--output",
            "json",
        ])
        .output()
        .map_err(|e| format!("could not run podman: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "headscale nodes list-routes failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("list-routes is not JSON: {e}"))?;
    let rows = parsed.as_array().ok_or("list-routes is not an array")?;
    let row = rows
        .iter()
        .find(|row| row["id"].as_u64() == Some(node_id))
        .ok_or_else(|| format!("node {node_id} advertises no routes"))?;

    let strings = |field: &str| -> Vec<String> {
        row[field]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(Routes {
        available: strings("available_routes"),
        approved: strings("approved_routes"),
        // What the node is actually the primary router for. Distinct from
        // "approved": two nodes can advertise the same subnet and only one
        // serves it.
        serving: strings("subnet_routes"),
    })
}

/// Approve routes on a node, which is the operator action an exit node needs
/// before any client will use it.
pub fn approve_routes(node_id: u64, routes: &[&str]) -> Result<(), String> {
    let output = Command::new("podman")
        .args([
            "exec",
            CONTAINER,
            "headscale",
            "nodes",
            "approve-routes",
            "--identifier",
            &node_id.to_string(),
            "--routes",
            &routes.join(","),
        ])
        .output()
        .map_err(|e| format!("could not run podman: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "approve-routes failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}
