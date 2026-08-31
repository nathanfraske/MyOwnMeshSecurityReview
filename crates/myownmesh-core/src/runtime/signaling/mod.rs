//! Target-owned runtime signaling namespace.
//!
//! The active typed ingress ports live at their authority-bearing engine
//! boundaries (`engine::semantic_ingress` and `engine::signaling_ingress`).
//! This runtime namespace deliberately contains no re-export or compatibility
//! facade, so it cannot become a second queue, parser, resource owner, or
//! authority store.
