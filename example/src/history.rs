use anyhow::{Context, Result};
use hotstuff2::{
    sequential::StateChange,
    types::{Certificate, ToBytes, View, Vote},
};
use sqlx::{migrate::MigrateDatabase, Row, Sqlite, SqlitePool};

use crate::codec::{AsyncDecode, AsyncEncode};

pub async fn open(url: &str) -> Result<SqlitePool> {
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
        commit blob not null
    );
    "#
}

async fn insert_genesis(pool: &SqlitePool, genesis: &Certificate<Vote>) -> Result<()> {
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

async fn get_voted_locked(pool: &SqlitePool) -> Result<(View, Certificate<Vote>)> {
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

async fn last_commit_view(pool: &SqlitePool) -> Result<Option<View>> {
    let view: Option<i64> = sqlx::query_scalar("select max(view) from history")
        .fetch_one(pool)
        .await
        .context("fetch last commit view")?;
    Ok(view.map(|v| View(v as u64)))
}

async fn first_commit_after_view(
    pool: &SqlitePool,
    view: View,
) -> Result<Option<Certificate<Vote>>> {
    let rst = sqlx::query("select commit from history where view >= ? order by view asc limit 1")
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
        sqlx::query("insert into history (view, height, block, commit) values (?, ?, ?, ?)")
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

pub(crate) struct History {
    db: SqlitePool,
    voted: View,
    locked: Option<Certificate<Vote>>,
    committed: Option<Certificate<Vote>>,
}

impl History {
    pub(crate) fn new(db: SqlitePool) -> Self {
        Self {
            db,
            voted: View(0),
            locked: None,
            committed: None,
        }
    }

    pub(crate) fn voted(&self) -> View {
        self.voted
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
