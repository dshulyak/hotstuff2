use std::collections::BTreeMap;

use hotstuff2::types::{Certificate, View, Vote};

pub(crate) struct History {
    voted: View,
    locked: Option<Certificate<Vote>>,
    commits: BTreeMap<View, Certificate<Vote>>,
}

impl History {
    pub(crate) fn new() -> Self {
        Self {
            voted: View(0),
            locked: None,
            commits: BTreeMap::new(),
        }
    }

    pub(crate) fn voted(&self) -> View {
        self.voted
    }

    pub(crate) fn empty(&self) -> bool {
        self.locked.is_none() && self.commits.is_empty()
    }

    pub(crate) fn last_view(&self) -> View {
        let mut last = self.voted;
        if let Some(locked) = &self.locked {
            last = last.max(locked.inner.view);
        }
        if let Some(commit) = self.commits.last_key_value() {
            if *commit.0 != View(0) {
                last = last.max(*commit.0 + 1);
            }
        }
        last
    }

    pub(crate) fn locked(&self) -> Certificate<Vote> {
        self.locked.as_ref().unwrap().clone()
    }

    pub(crate) fn last_commit(&self) -> Certificate<Vote> {
        self.commits.last_key_value().unwrap().1.clone()
    }

    pub(crate) fn first_after(&self, view: View) -> Option<Certificate<Vote>> {
        self.commits.range(view..).next().map(|(_, c)| c.clone())
    }

    pub(crate) fn update(
        &mut self,
        voted: Option<View>,
        locked: Option<Certificate<Vote>>,
        commit: Option<Certificate<Vote>>,
    ) -> anyhow::Result<()> {
        if let Some(voted) = voted {
            self.voted = voted;
        }
        if let Some(locked) = locked {
            self.locked = Some(locked);
        }
        if let Some(commit) = commit {
            self.commits.insert(commit.inner.view, commit);
        }
        Ok(())
    }
}
