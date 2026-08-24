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
            selected_head,
            ..
        } if resolution_cell == cell => {
            let selected = graph.facts.get(selected_head)?;
            super::verify::body_advances_cell(&selected.content.body, cell)
                .then(|| resolve_effective_head(graph, cell, *selected_head, visited))?
        }
        body if super::verify::body_advances_cell(body, cell) => Some(head),
        _ => None,
    }
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
