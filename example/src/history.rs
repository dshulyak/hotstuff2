use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use hotstuff2::types::{Certificate, ToBytes, View, Vote};
use sqlx::{
    migrate::MigrateDatabase,
    sqlite::{SqliteArguments, SqliteRow},
    Row, Sqlite, SqlitePool,
};

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
    let count: i64 = sqlx::query_scalar("select count(*) from safety")
        .fetch_one(&pool)
        .await?;
    if count == 0 {
        sqlx::query("insert into safety (voted, commit_height) values (?, ?)")
            .bind(0)
            .bind(0)
            .execute(&pool)
            .await
            .context("insert single row into safety table")?;
    }

    Ok(pool)
}

fn schema() -> &'static str {
    r#"
    create table if not exists safety (
        voted integer not null,
        commit_height integer not null,
        timeout_view integer,
        timeout_signature blob,
        timeout_signers blob
    );

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
    let count: i64 = sqlx::query_scalar("select count(*) from history")
        .fetch_one(pool)
        .await?;
    if count >= 1 {
        return Ok(());
    }

    encode_cert(genesis)
        .execute(pool)
        .await
        .context("insert genesis")?;
    Ok(())
}

fn encode_cert(cert: &Certificate<Vote>) -> sqlx::query::Query<'_, Sqlite, SqliteArguments> {
    sqlx::query(
        "insert or replace into history 
        (view, height, block_id, block_prev, signature, signers) 
        values (?, ?, ?, ?, ?, ?)",
    )
    .bind(cert.inner.view.0 as i64)
    .bind(cert.inner.height as i64)
    .bind(cert.inner.block.id.as_bytes())
    .bind(cert.inner.block.prev.as_bytes())
    .bind(cert.signature.to_bytes())
    .bind(cert.signers.to_bytes())
}

fn decode_row_into_cert(row: SqliteRow) -> Certificate<Vote> {
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
}

pub(crate) struct Stats {
    pub(crate) last: View,
    pub(crate) voted: View,
    pub(crate) commit: Certificate<Vote>,
    pub(crate) last_cert: Certificate<Vote>,
}

pub(crate) struct History(SqlitePool);

impl History {
    pub(crate) fn new(db: SqlitePool) -> Self {
        Self(db)
    }

    pub(crate) async fn commit_cert(&self) -> Result<Certificate<Vote>> {
        Ok(decode_row_into_cert(
            sqlx::query(
                "
                select 
                height, view, block_id, block_prev, signature, signers 
                from history 
                where height = (select commit_height from safety)
                ",
            )
            .fetch_one(&self.0)
            .await
            .context("fetch commit")?,
        ))
    }

    pub(crate) async fn stats(&self) -> Result<Stats> {
        let voted: i64 = sqlx::query_scalar("select voted from safety")
            .fetch_one(&self.0)
            .await
            .context("fetch voted")?;
        let timeout_view: Option<i64> = sqlx::query_scalar("select timeout_view from safety")
            .fetch_one(&self.0)
            .await
            .context("fetch timeout view")?;

        let commit_cert = self.commit_cert().await?;

        let last_cert = {
            decode_row_into_cert(sqlx::query(
                "select max(height), view, block_id, block_prev, signature, signers from history",
            )
            .fetch_one(&self.0)
            .await
            .context("fetch last")?)
        };
        let last = View(0)
            .max(timeout_view.map(|v| View(v as u64)).unwrap_or(View(0)))
            .max(last_cert.inner.view);
        Ok(Stats {
            last: if last == View(0) { last } else { last + 1 },
            voted: (voted as u64).into(),
            commit: commit_cert,
            last_cert: last_cert,
        })
    }

    pub(crate) async fn load_chain_after(&self, height: u64) -> Result<Vec<Certificate<Vote>>> {
        let mut rows = sqlx::query(
            "select height, view, block_id, block_prev, signature, signers from history 
            where height > ?",
        )
        .bind(height as i64)
        .fetch(&self.0);

        let mut chain = Vec::new();
        while let Some(row) = rows.try_next().await.context("fetch chain")? {
            chain.push(decode_row_into_cert(row));
        }
        Ok(chain)
    }

    pub(crate) async fn load_chain_from(&self, height: u64) -> Result<Vec<Certificate<Vote>>> {
        let mut rows = sqlx::query(
            "select height, view, block_id, block_prev, signature, signers from history 
            where height >= ?",
        )
        .bind(height as i64)
        .fetch(&self.0);

        let mut chain = Vec::new();
        while let Some(row) = rows.try_next().await.context("fetch chain")? {
            chain.push(decode_row_into_cert(row));
        }
        Ok(chain)
    }

    pub(crate) async fn timeout(&self) -> Result<Option<Certificate<View>>> {
        let row =
            sqlx::query("select timeout_view, timeout_signature, timeout_signers from safety")
                .fetch_one(&self.0)
                .await
                .context("fetch timeout")?;
        let timeout_view: Option<i64> = row.get(0);
        match timeout_view {
            None => Ok(None),
            Some(view) => {
                let timeout_signature: &[u8] = row.get(1);
                let timeout_signers: &[u8] = row.get(2);
                Ok(Some(Certificate::<View> {
                    inner: View(view as u64),
                    signature: timeout_signature.try_into().context("timeout signature")?,
                    signers: timeout_signers.try_into().context("timeout signers")?,
                }))
            }
        }
    }

    pub(crate) async fn update(
        &self,
        voted: Option<View>,
        commit: Option<u64>,
        timeout: Option<Certificate<View>>,
        chain: Vec<Certificate<Vote>>,
    ) -> anyhow::Result<()> {
        let mut tx = self.0.begin().await.context("begin tx")?;
        if let Some(voted) = voted {
            sqlx::query("update safety set voted = ?")
                .bind(voted.0 as i64)
                .execute(&mut *tx)
                .await
                .context("update voted")?;
        }
        if let Some(commit) = commit {
            sqlx::query("update safety set commit_height = ?")
                .bind(commit as i64)
                .execute(&mut *tx)
                .await
                .context("update voted")?;
        }
        if let Some(timeout) = &timeout {
            sqlx::query(
                "update safety set 
            timeout_view = ?,
            timeout_signature = ?, 
            timeout_signers = ?",
            )
            .bind(timeout.inner.0 as i64)
            .bind(timeout.signature.to_bytes())
            .bind(timeout.signers.to_bytes())
            .execute(&mut *tx)
            .await
            .context("update timeout")?;
        }
        for cert in chain {
            tracing::info!(height=%cert.height, view=%cert.view, id=%cert.id, prev=%cert.prev, "save certificate");
            encode_cert(&cert)
                .execute(&mut *tx)
                .await
                .context("insert commit")?;
        }
        tx.commit().await.context("commit tx")?;
        Ok(())
    }
}
