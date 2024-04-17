use anyhow::{Context, Result};
use hotstuff2::{
    sequential::StateChange,
    types::{Certificate, ToBytes, View, Vote},
};
use parking_lot::Mutex;
use sqlx::{migrate::MigrateDatabase, sqlite::SqliteRow, Row, Sqlite, SqlitePool};

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
    tracing::info!("connected to db");
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
        locked_height integer not null,
        locked_view integer not null,
        locked_block_id char(32) not null,
        locked_prev char(32) not null,
        locked_signature blob not null,
        locked_signers blob not null,
        timeout_view integer,
        timeout_signature blob,
        timeout_signers blob
    ) without rowid;

    create table if not exists history (
        height integer primary key not null,
        view integer not null,
        block_id char(32) not null,
        block_prev char(32) not null,
        signature blob not null,
        signers blob not null
    );
    create unique index if not exists history_by_view on history(view asc);
    "#
}

pub(crate) async fn insert_genesis(pool: &SqlitePool, genesis: &Certificate<Vote>) -> Result<()> {
    let count: i64 = sqlx::query_scalar("select count(*) from safety")
        .fetch_one(pool)
        .await?;
    if count == 1 {
        return Ok(());
    }
    sqlx::query("insert into safety 
        (tag, voted, locked_height, locked_view, locked_block_id, locked_prev, locked_signature, locked_signers) 
        values (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(SAFETY_TAG)
        .bind(genesis.inner.view.0 as i64)
        .bind(genesis.inner.height as i64)
        .bind(genesis.inner.view.0 as i64)
        .bind(genesis.inner.block.id.as_bytes())
        .bind(genesis.inner.block.prev.as_bytes())
        .bind(genesis.signature.to_bytes())
        .bind(genesis.signers.to_bytes())
        .execute(pool)
        .await
        .context("insert genesis")?;
    Ok(())
}

pub(crate) async fn get_voted_locked_timeout(
    pool: &SqlitePool,
) -> Result<(View, Certificate<Vote>, Option<Certificate<View>>)> {
    let row = sqlx::query(
        "select voted, 
        locked_height, locked_view, locked_block_id, locked_prev, locked_signature, locked_signers, 
        timeout_view, timeout_signature, timeout_signers 
        from safety where tag = ?",
    )
    .bind(SAFETY_TAG)
    .fetch_one(pool)
    .await
    .context("fetch safety")?;

    let voted: i64 = row.get(0);
    let locked = {
        let locked_height: i64 = row.get(1);
        let locked_view: i64 = row.get(2);
        let locked_id: &[u8] = row.get(3);
        let locked_prev: &[u8] = row.get(4);
        let signature: &[u8] = row.get(5);
        let signers: &[u8] = row.get(6);
        Certificate::<Vote> {
            inner: Vote {
                view: View(locked_view as u64),
                block: hotstuff2::types::Block {
                    height: locked_height as u64,
                    id: locked_id.try_into().context("locked id")?,
                    prev: locked_prev.try_into().context("locked prev")?,
                },
            },
            signature: signature.try_into().context("locked signature")?,
            signers: signers.try_into().context("locked signers")?,
        }
    };
    let timeout = {
        let timeout_view: Option<i64> = row.get(7);
        match timeout_view {
            None => None,
            Some(view) => {
                let timeout_signature: &[u8] = row.get(8);
                let timeout_signers: &[u8] = row.get(9);
                Some(Certificate::<View> {
                    inner: View(view as u64),
                    signature: timeout_signature.try_into().context("timeout signature")?,
                    signers: timeout_signers.try_into().context("timeout signers")?,
                })
            }
        }
    };
    Ok((View(voted as u64), locked, timeout))
}

fn decode_row_into_cert(rst: Option<SqliteRow>) -> Option<Certificate<Vote>> {
    rst.map(|row| {
        let height: i64 = row.get(0);
        let view: i64 = row.get(1);
        let block_id: &[u8] = row.get(2);
        let block_prev: &[u8] = row.get(3);
        let signature: &[u8] = row.get(4);
        let signers: &[u8] = row.get(5);
        Certificate::<Vote> {
            inner: Vote {
                view: View(view as u64),
                block: hotstuff2::types::Block {
                    height: height as u64,
                    id: block_id.try_into().context("block id").unwrap(),
                    prev: block_prev.try_into().context("block prev").unwrap(),
                },
            },
            signature: signature.try_into().context("signature").unwrap(),
            signers: signers.try_into().context("signers").unwrap(),
        }
    })
}

pub(crate) async fn get_last_commit(pool: &SqlitePool) -> Result<Option<Certificate<Vote>>> {
    let rst = sqlx::query("
    select height, view, block_id, block_prev, signature, signers 
    from history order by view desc limit 1")
        .fetch_optional(pool)
        .await
        .context("fetch last commit")?;
    Ok(decode_row_into_cert(rst))
}

async fn first_commit_after_view(
    pool: &SqlitePool,
    view: View,
) -> Result<Option<Certificate<Vote>>> {
    let rst = sqlx::query(
        "select height, view, block_id, block_prev, signature, signers
            from history where view >= ? order by view asc limit 1",
    )
    .bind(view.0 as i64)
    .fetch_optional(pool)
    .await
    .context("fetch first commit after view")?;
    Ok(decode_row_into_cert(rst))
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
    if let Some(locked) = &change.locked {
        sqlx::query(
            "update safety set 
            locked_height = ?, 
            locked_view = ?, 
            locked_block_id = ?, 
            locked_prev = ?, 
            locked_signature = ?, 
            locked_signers =? 
            where tag = ?",
        )
        .bind(locked.inner.block.height as i64)
        .bind(locked.inner.view.0 as i64)
        .bind(locked.inner.block.id.as_bytes())
        .bind(locked.inner.block.prev.as_bytes())
        .bind(locked.signature.to_bytes())
        .bind(locked.signers.to_bytes())
        .bind(SAFETY_TAG)
        .execute(&mut *tx)
        .await
        .context("update locked")?;
    }
    if let Some(timeout) = &change.timeout {
        sqlx::query(
            "update safety set 
            timeout_view = ?,
            timeout_signature = ?, 
            timeout_signers = ? 
            where tag = ?",
        )
        .bind(timeout.inner.0 as i64)
        .bind(timeout.signature.to_bytes())
        .bind(timeout.signers.to_bytes())
        .bind(SAFETY_TAG)
        .execute(&mut *tx)
        .await
        .context("update timeout")?;
    }
    if let Some(commit) = &change.commit {
        sqlx::query(
            "
insert or replace into history 
(view, height, block_id, block_prev, signature, signers) 
values (?1, ?2, ?3, ?4, ?5, ?6);            
        ",
        )
        .bind(commit.inner.view.0 as i64)
        .bind(commit.inner.height as i64)
        .bind(commit.inner.block.id.as_bytes())
        .bind(commit.inner.block.prev.as_bytes())
        .bind(commit.signature.to_bytes())
        .bind(commit.signers.to_bytes())
        .execute(&mut *tx)
        .await
        .context("insert commit")?;
    }
    tx.commit().await.context("commit tx")?;
    Ok(())
}

struct State {
    voted: View,
    timeout: Option<Certificate<View>>,
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
        if let Some(timeout) = &self.timeout {
            last = last.max(timeout.inner);
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
        if let Some(locked) = &change.locked {
            self.locked = Some(locked.clone());
        }
        if let Some(commit) = &change.commit {
            self.committed = Some(commit.clone());
        }
    }
}

pub(crate) struct History {
    db: SqlitePool,
    state: Mutex<State>,
}

impl History {
    pub(crate) fn new(db: SqlitePool) -> Self {
        Self {
            db,
            state: Mutex::new(State {
                voted: View(0),
                locked: None,
                committed: None,
                timeout: None,
            }),
        }
    }

    pub(crate) async fn from_db(db: SqlitePool) -> Result<Self> {
        let (voted, locked, timeout) = get_voted_locked_timeout(&db).await?;
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
                timeout,
            }),
        })
    }

    pub(crate) fn voted(&self) -> View {
        self.state.lock().voted()
    }

    pub(crate) fn timeout(&self) -> Option<Certificate<View>> {
        self.state.lock().timeout.clone()
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
