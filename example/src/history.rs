use anyhow::{Context, Result};
use hotstuff2::{
    sequential::StateChange,
    types::{Certificate, ToBytes, View, Vote},
};
use parking_lot::Mutex;
use sqlx::{migrate::MigrateDatabase, Row, Sqlite, SqlitePool};

use crate::codec::{AsyncDecode, AsyncEncode};

pub(crate) async fn inmemory() -> Result<SqlitePool> {
    sqlite("sqlite::memory:").await
}

pub async fn open(path: &str) -> Result<SqlitePool> {
    sqlite(&format!("sqlite:{}", path)).await
}

pub async fn sqlite(url: &str) -> Result<SqlitePool> {
    if !Sqlite::database_exists(url).await.context("db exists")? {
        Sqlite::create_database(url).await.context("create db")?;
    }
    let pool = SqlitePool::connect(url).await.context("pool connect")?;
    sqlx::query(schema())
        .execute(&pool)
        .await
        .context("create tables")?;
    Ok(pool)
}

const SAFETY_TAG: i32 = 1;

fn schema() -> &'static str {
    r#"
    create table if not exists safety (
        tag integer primary key not null,
        voted integer not null,
        locked blob not null
    ) without rowid;

    create table if not exists history (
        view integer primary key not null,
        height integer not null,
        block char(32) not null,
        certificate blob not null
    );
    "#
}

pub(crate) async fn insert_genesis(pool: &SqlitePool, genesis: &Certificate<Vote>) -> Result<()> {
    let count: i64 = sqlx::query_scalar("select count(*) from safety")
        .fetch_one(pool)
        .await?;
    if count == 1 {
        return Ok(());
    }
    sqlx::query("insert into safety (tag, voted, locked) values (?, ?, ?)")
        .bind(SAFETY_TAG)
        .bind(genesis.inner.view.0 as i64)
        .bind(genesis.encode_to_bytes().await?)
        .execute(pool)
        .await
        .context("insert genesis")?;
    Ok(())
}

pub(crate) async fn get_voted_locked(pool: &SqlitePool) -> Result<(View, Certificate<Vote>)> {
    let row = sqlx::query("select voted, locked from safety where tag = ?")
        .bind(SAFETY_TAG)
        .fetch_one(pool)
        .await
        .context("fetch safety")?;
    let voted: i64 = row.get(0);
    let locked = Certificate::decode_from_bytes(row.get(1))
        .await
        .context("decode locked")?;
    Ok((View(voted as u64), locked))
}

pub(crate) async fn get_last_commit(pool: &SqlitePool) -> Result<Option<Certificate<Vote>>> {
    let rst = sqlx::query("select certificate from history order by view desc limit 1")
        .fetch_optional(pool).await
        .context("fetch last commit")?;
    if let Some(row) = rst {
        let buf: &[u8] = row.get(0);
        Ok(Some(Certificate::decode_from_bytes(buf).await?))
    } else {
        Ok(None)
    }
}

async fn first_commit_after_view(
    pool: &SqlitePool,
    view: View,
) -> Result<Option<Certificate<Vote>>> {
    let rst = sqlx::query("select certificate from history where view >= ? order by view asc limit 1")
        .bind(view.0 as i64)
        .fetch_optional(pool)
        .await
        .context("fetch first commit after view")?;
    if let Some(row) = rst {
        let buf: &[u8] = row.get(0);
        Ok(Some(Certificate::decode_from_bytes(buf).await?))
    } else {
        Ok(None)
    }
}

async fn update_state_change(pool: &SqlitePool, change: &StateChange) -> Result<()> {
    let mut tx = pool.begin().await.context("begin tx")?;
    if let Some(voted) = &change.voted {
        sqlx::query("update safety set voted = ? where tag = ?")
            .bind(voted.0 as i64)
            .bind(SAFETY_TAG)
            .execute(&mut *tx)
            .await
            .context("update voted")?;
    }
    if let Some(locked) = &change.lock {
        sqlx::query("update safety set locked = ? where tag = ?")
            .bind(locked.encode_to_bytes().await?)
            .bind(SAFETY_TAG)
            .execute(&mut *tx)
            .await
            .context("update locked")?;
    }
    if let Some(commit) = &change.commit {
        sqlx::query("insert into history (view, height, block, certificate) values (?, ?, ?, ?)")
            .bind(commit.inner.view.0 as i64)
            .bind(commit.inner.height as i64)
            .bind(commit.inner.block.to_bytes())
            .bind(commit.encode_to_bytes().await?)
            .execute(&mut *tx)
            .await
            .context("insert commit")?;
    }
    tx.commit().await.context("commit tx")?;
    Ok(())
}

struct State {
    voted: View,
    locked: Option<Certificate<Vote>>,
    committed: Option<Certificate<Vote>>,
}


impl State {
    pub(crate) fn voted(&self) -> View {
        self.voted
    }

    pub(crate) fn last_view(&self) -> View {
        let mut last = self.voted;
        if let Some(locked) = &self.locked {
            last = last.max(locked.inner.view);
        }
        if let Some(committed) = &self.committed {
            last = last.max(committed.inner.view);
        }
        last
    }

    pub(crate) fn locked(&self) -> Certificate<Vote> {
        self.locked.as_ref().unwrap().clone()
    }

    pub(crate) fn last_commit(&self) -> Certificate<Vote> {
        self.committed.as_ref().unwrap().clone()
    }

    pub(crate) fn update(&mut self, change: &StateChange) {
        if let Some(voted) = &change.voted {
            self.voted = voted.clone();
        }
        if let Some(locked) = &change.lock {
            self.locked = Some(locked.clone());
        }
        if let Some(commit) = &change.commit {
            self.committed = Some(commit.clone());
        }
    }
}

pub(crate) struct History {
    db: SqlitePool,
    state: Mutex<State>
}

impl History {
    pub(crate) fn new(db: SqlitePool) -> Self {
        Self {
            db,
            state: Mutex::new(State {
                voted: View(0),
                locked: None,
                committed: None,
            }),
        }
    }

    pub(crate) async fn from_db(db: SqlitePool) -> Result<Self> {
        let (voted, locked) = get_voted_locked(&db).await?;
        let mut committed = get_last_commit(&db).await?;
        if committed.is_none() {
            committed = Some(locked.clone());
        }
        Ok(Self {
            db,
            state: Mutex::new(State {
                voted,
                locked: Some(locked),
                committed,
            }),
        })
    }

    pub(crate) fn voted(&self) -> View {
        self.state.lock().voted()
    }

    pub(crate) fn last_view(&self) -> View {
        self.state.lock().last_view()
    }

    pub(crate) fn locked(&self) -> Certificate<Vote> {
        self.state.lock().locked()
    }

    pub(crate) fn last_commit(&self) -> Certificate<Vote> {
        self.state.lock().last_commit()
    }

    pub(crate) async fn first_after(&self, view: View) -> Option<Certificate<Vote>> {
        first_commit_after_view(&self.db, view)
            .await
            .expect("first after view")
    }

    pub(crate) async fn update(&self, state_change: &StateChange) -> anyhow::Result<()> {
        update_state_change(&self.db, state_change).await?;
        self.state.lock().update(state_change);
        Ok(())
    }
}
