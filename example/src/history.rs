use std::collections::BTreeMap;

use hotstuff2::types::{Certificate, Sync as SyncMsg, View, Vote};

pub(crate) struct History {
    pub(crate) voted: View,
    pub(crate) locked: Option<Certificate<Vote>>,
    pub(crate) commits: BTreeMap<View, Certificate<Vote>>,
}

impl History {
    pub(crate) fn new() -> Self {
        Self {
            voted: View(0),
            locked: None,
            commits: BTreeMap::new(),
        }
    }

    pub(crate) fn last_view(&self) -> View {
        let mut last = self.voted;
        if let Some(locked) = &self.locked {
            last = last.max(locked.inner.view);
        }
        if let Some(commit) = self.commits.last_key_value() {
            last = last.max(*commit.0 + 1);
        }
        last
    }

    pub(crate) fn lock(&self) -> Certificate<Vote> {
        self.locked.as_ref().unwrap().clone()
    }

    pub(crate) fn last_commit(&self) -> Certificate<Vote> {
        self.commits.last_key_value().unwrap().1.clone()
    }

    pub(crate) fn sync_state(&self) -> SyncMsg {
        SyncMsg {
            locked: self.locked.clone(),
            double: Some(self.last_commit()),
        }
    }

    pub(crate) fn get(&self, view: View) -> SyncMsg {
        let commit = self.commits.get(&view).cloned();
        if commit.is_none() {
            return SyncMsg {
                locked: self.locked.clone(),
                double: None,
            };
        } else {
            SyncMsg {
                locked: None,
                double: commit,
            }
        }
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
