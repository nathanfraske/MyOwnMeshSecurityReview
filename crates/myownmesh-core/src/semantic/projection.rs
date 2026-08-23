//! Pure projection of the causal graph into exclusive semantic cells.

use std::collections::BTreeMap;

use super::causal::FactGraph;
use super::content::{ExclusiveCell, FactBody};
use super::FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellProjection {
    Value(FactId),
    Conflict(Vec<FactId>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandDown {
    pub target: String,
    pub proof: FactId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Projection {
    cells: BTreeMap<ExclusiveCell, CellProjection>,
    stand_down: BTreeMap<String, StandDown>,
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
                [head] => match &graph.facts[head].content.body {
                    FactBody::Resolution { selected_head, .. } => {
                        CellProjection::Value(*selected_head)
                    }
                    _ => CellProjection::Value(*head),
                },
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

    pub fn stand_down(&self, target: &str) -> Option<&StandDown> {
        self.stand_down.get(target)
    }

    pub fn is_stood_down(&self, target: &str) -> bool {
        self.stand_down.contains_key(target)
    }

    pub fn stand_down_targets(&self) -> impl Iterator<Item = &str> {
        self.stand_down.keys().map(String::as_str)
    }
}
