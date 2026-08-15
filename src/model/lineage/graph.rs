use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LineageGraph {
    pub nodes: Vec<LineageNode>,
    pub edges: Vec<LineageEdge>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageNode {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageEdge {
    pub parent: String,
    pub child: String,
    pub relation: super::ClaimedRelation,
}
impl LineageGraph {
    pub fn cycle(&self) -> Option<Vec<String>> {
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for e in &self.edges {
            adj.entry(&e.parent).or_default().push(&e.child)
        }
        for v in adj.values_mut() {
            v.sort()
        }
        let mut done = BTreeSet::new();
        let mut active = BTreeSet::new();
        let mut stack = Vec::new();
        fn dfs<'a>(
            n: &'a str,
            adj: &BTreeMap<&'a str, Vec<&'a str>>,
            done: &mut BTreeSet<&'a str>,
            active: &mut BTreeSet<&'a str>,
            stack: &mut Vec<&'a str>,
        ) -> Option<Vec<String>> {
            if active.contains(n) {
                let i = stack.iter().position(|x| *x == n).unwrap_or(0);
                return Some(
                    stack[i..]
                        .iter()
                        .map(|x| (*x).to_owned())
                        .chain(std::iter::once(n.to_owned()))
                        .collect(),
                );
            }
            if done.contains(n) {
                return None;
            }
            active.insert(n);
            stack.push(n);
            if let Some(next) = adj.get(n) {
                for c in next {
                    if let Some(v) = dfs(c, adj, done, active, stack) {
                        return Some(v);
                    }
                }
            }
            stack.pop();
            active.remove(n);
            done.insert(n);
            None
        }
        let mut ids = self.nodes.iter().map(|n| n.id.as_str()).collect::<Vec<_>>();
        ids.sort();
        for id in ids {
            if let Some(c) = dfs(id, &adj, &mut done, &mut active, &mut stack) {
                return Some(c);
            }
        }
        None
    }
}
