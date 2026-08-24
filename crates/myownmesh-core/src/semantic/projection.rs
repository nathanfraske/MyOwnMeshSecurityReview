//! Pure projection of the causal graph into exclusive semantic cells.

use std::collections::{BTreeMap, BTreeSet};

use super::causal::FactGraph;
use super::content::{DeviceId, ExclusiveCell, FactBody};
use super::FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellProjection {
    Value(FactId),
    Conflict(Vec<FactId>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandDown {
    pub target: DeviceId,
    pub proof: FactId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Projection {
    cells: BTreeMap<ExclusiveCell, CellProjection>,
    stand_down: BTreeMap<DeviceId, StandDown>,
}

/// Follow a same-cell resolution chain to the effective non-resolution head.
/// A malformed or cyclic chain is authority-negative; the visited set keeps
/// projection total even when a test or a future loader presents a graph that
/// was not admitted through the normal causal checks.
fn resolve_effective_head(
    graph: &FactGraph,
    cell: &ExclusiveCell,
    head: FactId,
    visited: &mut BTreeSet<FactId>,
) -> Option<FactId> {
    if !visited.insert(head) {
        return None;
    }
    let fact = graph.facts.get(&head)?;
    match &fact.content.body {
        FactBody::Resolution {
            cell: resolution_cell,
            cited_heads,
            selected_head,
        } if resolution_cell == cell => {
            let mut cited = cited_heads.clone();
            cited.sort();
            cited.dedup();
            if cited.len() < 2
                || cited.len() != cited_heads.len()
                || cited.as_slice() != cited_heads.as_slice()
                || !cited.contains(selected_head)
                || heads_at(graph, cell, head) != cited
            {
                return None;
            }
            let selected = graph.facts.get(selected_head)?;
            super::verify::body_advances_cell(&selected.content.body, cell)
                .then(|| resolve_effective_head(graph, cell, *selected_head, visited))?
        }
        body if super::verify::body_advances_cell(body, cell) => Some(head),
        _ => None,
    }
}

/// Return the complete incomparable head set visible immediately before one
/// resolution fact.  Looking at the whole graph would admit a resolution
/// against unrelated later branches, so this deliberately walks only the
/// candidate's causal parents.
fn heads_at(graph: &FactGraph, cell: &ExclusiveCell, resolution: FactId) -> Vec<FactId> {
    let mut visible = BTreeSet::new();
    let mut pending = graph
        .facts
        .get(&resolution)
        .into_iter()
        .flat_map(|fact| fact.content.parents.iter().copied())
        .collect::<Vec<_>>();
    while let Some(id) = pending.pop() {
        if !visible.insert(id) {
            continue;
        }
        if let Some(fact) = graph.facts.get(&id) {
            pending.extend(fact.content.parents.iter().copied());
        }
    }
    let candidates = visible
        .iter()
        .copied()
        .filter(|id| {
            graph
                .facts
                .get(id)
                .is_some_and(|fact| super::verify::body_advances_cell(&fact.content.body, cell))
        })
        .collect::<Vec<_>>();
    candidates
        .iter()
        .copied()
        .filter(|candidate| {
            !candidates.iter().any(|other| {
                candidate != other && is_ancestor_within(graph, &visible, candidate, other)
            })
        })
        .collect()
}

fn is_ancestor_within(
    graph: &FactGraph,
    visible: &BTreeSet<FactId>,
    ancestor: &FactId,
    descendant: &FactId,
) -> bool {
    let mut pending = vec![*descendant];
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(fact) = graph.facts.get(&id) else {
            continue;
        };
        for parent in &fact.content.parents {
            if parent == ancestor {
                return true;
            }
            if visible.contains(parent) {
                pending.push(*parent);
            }
        }
    }
    false
}

impl Projection {
    pub(crate) fn from_graph(graph: &FactGraph) -> Self {
        let mut cells = BTreeMap::new();
        let mut stand_down = BTreeMap::new();
        for (id, fact) in &graph.facts {
            match &fact.content.body {
                FactBody::EvictionProof { target, .. } => {
                    stand_down
                        .entry(target.clone())
                        .or_insert_with(|| StandDown {
                            target: target.clone(),
                            proof: *id,
                        });
                }
                FactBody::SelfStandDown { device_id, .. } => {
                    stand_down
                        .entry(device_id.clone())
                        .or_insert_with(|| StandDown {
                            target: device_id.clone(),
                            proof: *id,
                        });
                }
                _ => {}
            }
        }
        let all_cells: std::collections::BTreeSet<_> = graph
            .facts
            .values()
            .flat_map(|fact| fact.content.body.exclusive_cells())
            .collect();
        for cell in all_cells {
            let heads = graph.cell_heads(&cell);
            let value = match heads.as_slice() {
                [] => continue,
                [head] => resolve_effective_head(graph, &cell, *head, &mut BTreeSet::new())
                    .map(CellProjection::Value)
                    .unwrap_or_else(|| CellProjection::Conflict(vec![*head])),
                _ => CellProjection::Conflict(heads),
            };
            cells.insert(cell, value);
        }
        Self { cells, stand_down }
    }

    pub fn cell(&self, cell: &ExclusiveCell) -> Option<&CellProjection> {
        self.cells.get(cell)
    }

    pub fn cells(&self) -> impl Iterator<Item = (&ExclusiveCell, &CellProjection)> {
        self.cells.iter()
    }

    pub fn is_conflicted(&self, cell: &ExclusiveCell) -> bool {
        matches!(self.cell(cell), Some(CellProjection::Conflict(_)))
    }

    pub fn conflicted_cells(&self) -> impl Iterator<Item = &ExclusiveCell> {
        self.cells.iter().filter_map(|(cell, projection)| {
            matches!(projection, CellProjection::Conflict(_)).then_some(cell)
        })
    }

    pub fn value(&self, cell: &ExclusiveCell) -> Option<FactId> {
        match self.cell(cell) {
            Some(CellProjection::Value(id)) => Some(*id),
            _ => None,
        }
    }

    /// Read the projected role cell without allowing a caller to substitute a
    /// stringly-typed authority key.
    pub fn role_cell(&self, subject: &DeviceId) -> Option<&CellProjection> {
        self.cell(&ExclusiveCell::role(subject.clone()))
    }

    /// Read the projected membership cell for Closed session admission.
    pub fn membership_cell(&self, subject: &DeviceId) -> Option<&CellProjection> {
        self.cell(&ExclusiveCell::membership(subject.clone()))
    }

    pub fn stand_down(&self, target: &DeviceId) -> Option<&StandDown> {
        self.stand_down.get(target)
    }

    pub fn is_stood_down(&self, target: &DeviceId) -> bool {
        self.stand_down.contains_key(target)
    }

    pub fn stand_down_targets(&self) -> impl Iterator<Item = &DeviceId> {
        self.stand_down.keys()
    }
}
