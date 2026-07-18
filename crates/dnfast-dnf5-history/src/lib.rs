#![deny(warnings)]

use std::{
    ffi::{CString, c_char, c_int, c_void},
    os::fd::AsRawFd,
    path::Path,
    ptr, slice,
};

use libloading::Library;
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use thiserror::Error;

const HISTORY_DIRECTORY: &str = "/usr/lib/sysimage/libdnf5";
const HISTORY_DATABASE: &str = "transaction_history.sqlite";
const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_OPEN_READONLY: c_int = 0x0000_0001;
const SQLITE_OPEN_URI: c_int = 0x0000_0040;
const SQLITE_OPEN_NOMUTEX: c_int = 0x0000_8000;
const MAX_DATABASE_BYTES: i64 = 4 * 1024 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_TRANSACTION_ITEMS: usize = 1_000_000;

type Sqlite = c_void;
type Statement = c_void;

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("DNF5 history requires EUID 0")]
    NotRoot,
    #[error("DNF5 history path is unsafe: {0}")]
    UnsafePath(String),
    #[error("DNF5 history SQLite ABI is unavailable: {0}")]
    Abi(String),
    #[error("DNF5 history database is incompatible or corrupt: {0}")]
    Database(String),
    #[error("DNF5 history limit exceeded: {0}")]
    Limit(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    pub id: i64,
    pub begin_unix: i64,
    pub end_unix: Option<i64>,
    pub state: String,
    pub user_id: i64,
    pub releasever: String,
    pub description: String,
    pub item_count: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionItem {
    pub name: String,
    pub epoch: i64,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub repository: String,
    pub action: String,
    pub reason: String,
    pub state: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionDetail {
    pub transaction: Transaction,
    pub items: Vec<TransactionItem>,
}

pub fn list_system(limit: u16) -> Result<Vec<Transaction>, HistoryError> {
    require_root()?;
    if limit == 0 {
        return Err(HistoryError::Limit("transaction list"));
    }
    let directory = verified_history_directory()?;
    let database = Database::open(&directory)?;
    database.verify_schema()?;
    database.transactions(Some(i64::from(limit)))
}

pub fn info_system(id: i64) -> Result<Option<TransactionDetail>, HistoryError> {
    require_root()?;
    if id <= 0 {
        return Ok(None);
    }
    let directory = verified_history_directory()?;
    let database = Database::open(&directory)?;
    database.verify_schema()?;
    let Some(transaction) = database.transaction(id)? else {
        return Ok(None);
    };
    let items = database.items(id)?;
    Ok(Some(TransactionDetail { transaction, items }))
}

fn require_root() -> Result<(), HistoryError> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err(HistoryError::NotRoot)
    }
}

fn verified_history_directory() -> Result<std::os::fd::OwnedFd, HistoryError> {
    let directory = open(
        Path::new(HISTORY_DIRECTORY),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| HistoryError::UnsafePath(error.to_string()))?;
    verify_fd(&directory, FileType::Directory, false, i64::MAX)?;
    for name in [
        HISTORY_DATABASE,
        "transaction_history.sqlite-wal",
        "transaction_history.sqlite-shm",
    ] {
        match openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => verify_fd(&file, FileType::RegularFile, true, MAX_DATABASE_BYTES)?,
            Err(rustix::io::Errno::NOENT) if name != HISTORY_DATABASE => {}
            Err(error) => return Err(HistoryError::UnsafePath(error.to_string())),
        }
    }
    Ok(directory)
}

fn verify_fd(
    descriptor: &impl std::os::fd::AsFd,
    expected: FileType,
    one_link: bool,
    maximum: i64,
) -> Result<(), HistoryError> {
    let metadata =
        fstat(descriptor).map_err(|error| HistoryError::UnsafePath(error.to_string()))?;
    if FileType::from_raw_mode(metadata.st_mode) != expected
        || metadata.st_uid != 0
        || metadata.st_mode & 0o022 != 0
        || (one_link && metadata.st_nlink != 1)
        || metadata.st_size < 0
        || metadata.st_size > maximum
    {
        return Err(HistoryError::UnsafePath(
            "ownership, mode, type, link count, or size differs".into(),
        ));
    }
    Ok(())
}

struct Api {
    _library: Library,
    open_v2: unsafe extern "C" fn(*const c_char, *mut *mut Sqlite, c_int, *const c_char) -> c_int,
    close_v2: unsafe extern "C" fn(*mut Sqlite) -> c_int,
    prepare_v2: unsafe extern "C" fn(
        *mut Sqlite,
        *const c_char,
        c_int,
        *mut *mut Statement,
        *mut *const c_char,
    ) -> c_int,
    step: unsafe extern "C" fn(*mut Statement) -> c_int,
    finalize: unsafe extern "C" fn(*mut Statement) -> c_int,
    column_int64: unsafe extern "C" fn(*mut Statement, c_int) -> i64,
    column_text: unsafe extern "C" fn(*mut Statement, c_int) -> *const u8,
    column_bytes: unsafe extern "C" fn(*mut Statement, c_int) -> c_int,
    column_type: unsafe extern "C" fn(*mut Statement, c_int) -> c_int,
    errmsg: unsafe extern "C" fn(*mut Sqlite) -> *const c_char,
    busy_timeout: unsafe extern "C" fn(*mut Sqlite, c_int) -> c_int,
}

impl Api {
    fn load() -> Result<Self, HistoryError> {
        // SAFETY: the fixed SONAME is loaded only to resolve the documented
        // SQLite C ABI. Every copied symbol is retained with the Library in
        // this value, so no function pointer can outlive its shared object.
        let library = unsafe { Library::new("libsqlite3.so.0") }
            .map_err(|error| HistoryError::Abi(error.to_string()))?;
        macro_rules! symbol {
            ($name:literal, $kind:ty) => {{
                // SAFETY: each symbol name and function type is the exact
                // stable SQLite C declaration used by supported Fedora.
                let symbol = unsafe { library.get::<$kind>($name) }
                    .map_err(|error| HistoryError::Abi(error.to_string()))?;
                *symbol
            }};
        }
        let open_v2 = symbol!(
            b"sqlite3_open_v2\0",
            unsafe extern "C" fn(*const c_char, *mut *mut Sqlite, c_int, *const c_char) -> c_int
        );
        let close_v2 = symbol!(
            b"sqlite3_close_v2\0",
            unsafe extern "C" fn(*mut Sqlite) -> c_int
        );
        let prepare_v2 = symbol!(
            b"sqlite3_prepare_v2\0",
            unsafe extern "C" fn(
                *mut Sqlite,
                *const c_char,
                c_int,
                *mut *mut Statement,
                *mut *const c_char,
            ) -> c_int
        );
        let step = symbol!(
            b"sqlite3_step\0",
            unsafe extern "C" fn(*mut Statement) -> c_int
        );
        let finalize = symbol!(
            b"sqlite3_finalize\0",
            unsafe extern "C" fn(*mut Statement) -> c_int
        );
        let column_int64 = symbol!(
            b"sqlite3_column_int64\0",
            unsafe extern "C" fn(*mut Statement, c_int) -> i64
        );
        let column_text = symbol!(
            b"sqlite3_column_text\0",
            unsafe extern "C" fn(*mut Statement, c_int) -> *const u8
        );
        let column_bytes = symbol!(
            b"sqlite3_column_bytes\0",
            unsafe extern "C" fn(*mut Statement, c_int) -> c_int
        );
        let column_type = symbol!(
            b"sqlite3_column_type\0",
            unsafe extern "C" fn(*mut Statement, c_int) -> c_int
        );
        let errmsg = symbol!(
            b"sqlite3_errmsg\0",
            unsafe extern "C" fn(*mut Sqlite) -> *const c_char
        );
        let busy_timeout = symbol!(
            b"sqlite3_busy_timeout\0",
            unsafe extern "C" fn(*mut Sqlite, c_int) -> c_int
        );
        Ok(Self {
            _library: library,
            open_v2,
            close_v2,
            prepare_v2,
            step,
            finalize,
            column_int64,
            column_text,
            column_bytes,
            column_type,
            errmsg,
            busy_timeout,
        })
    }
}

struct Database {
    api: Api,
    raw: *mut Sqlite,
}

impl Database {
    fn open(directory: &impl std::os::fd::AsFd) -> Result<Self, HistoryError> {
        let api = Api::load()?;
        let uri = CString::new(format!(
            "file:/proc/self/fd/{}/{}?mode=ro",
            directory.as_fd().as_raw_fd(),
            HISTORY_DATABASE
        ))
        .expect("fixed history URI has no NUL");
        let mut raw = ptr::null_mut();
        // SAFETY: uri is NUL terminated, raw is a valid out pointer, and the
        // returned connection is owned and closed by Database::drop.
        let status = unsafe {
            (api.open_v2)(
                uri.as_ptr(),
                &mut raw,
                SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX,
                ptr::null(),
            )
        };
        if status != SQLITE_OK || raw.is_null() {
            let message = if raw.is_null() {
                format!("sqlite3_open_v2 status {status}")
            } else {
                error_message(&api, raw)
            };
            if !raw.is_null() {
                // SAFETY: failed open still returns a closeable SQLite handle.
                unsafe { (api.close_v2)(raw) };
            }
            return Err(HistoryError::Database(message));
        }
        // SAFETY: raw is a live SQLite connection; a bounded wait lets a
        // concurrent root DNF5 writer finish without indefinite blocking.
        if unsafe { (api.busy_timeout)(raw, 5_000) } != SQLITE_OK {
            // SAFETY: raw is live and not shared.
            unsafe { (api.close_v2)(raw) };
            return Err(HistoryError::Database("busy timeout failed".into()));
        }
        Ok(Self { api, raw })
    }

    fn verify_schema(&self) -> Result<(), HistoryError> {
        let mut statement =
            self.prepare("SELECT value FROM config WHERE key='version' AND value='1.1' LIMIT 1")?;
        if statement.step()? != Step::Row || statement.text(0)? != "1.1" {
            return Err(HistoryError::Database(
                "unsupported DNF5 history schema".into(),
            ));
        }
        if statement.step()? != Step::Done {
            return Err(HistoryError::Database(
                "ambiguous DNF5 history schema".into(),
            ));
        }
        Ok(())
    }

    fn transactions(&self, limit: Option<i64>) -> Result<Vec<Transaction>, HistoryError> {
        let suffix = limit
            .map(|value| format!(" LIMIT {value}"))
            .unwrap_or_default();
        let sql = format!(
            "SELECT t.id,t.dt_begin,t.dt_end,COALESCE(s.name,'Unknown'),t.user_id,\
             t.releasever,COALESCE(t.description,''),COUNT(i.id) FROM trans t \
             LEFT JOIN trans_state s ON s.id=t.state_id LEFT JOIN trans_item i ON i.trans_id=t.id \
             GROUP BY t.id,t.dt_begin,t.dt_end,s.name,t.user_id,t.releasever,t.description \
             ORDER BY t.id DESC{suffix}"
        );
        let mut statement = self.prepare(&sql)?;
        let mut rows = Vec::new();
        while statement.step()? == Step::Row {
            rows.push(transaction_row(&statement)?);
        }
        Ok(rows)
    }

    fn transaction(&self, id: i64) -> Result<Option<Transaction>, HistoryError> {
        let sql = format!(
            "SELECT t.id,t.dt_begin,t.dt_end,COALESCE(s.name,'Unknown'),t.user_id,\
             t.releasever,COALESCE(t.description,''),COUNT(i.id) FROM trans t \
             LEFT JOIN trans_state s ON s.id=t.state_id LEFT JOIN trans_item i ON i.trans_id=t.id \
             WHERE t.id={id} GROUP BY t.id,t.dt_begin,t.dt_end,s.name,t.user_id,t.releasever,t.description"
        );
        let mut statement = self.prepare(&sql)?;
        if statement.step()? == Step::Done {
            return Ok(None);
        }
        let value = transaction_row(&statement)?;
        if statement.step()? != Step::Done {
            return Err(HistoryError::Database(
                "duplicate DNF5 transaction id".into(),
            ));
        }
        Ok(Some(value))
    }

    fn items(&self, id: i64) -> Result<Vec<TransactionItem>, HistoryError> {
        let sql = format!(
            "SELECT n.name,r.epoch,r.version,r.release,a.name,COALESCE(repo.repoid,''),\
             action.name,reason.name,state.name FROM trans_item ti \
             JOIN rpm r ON r.item_id=ti.item_id JOIN pkg_name n ON n.id=r.name_id \
             JOIN arch a ON a.id=r.arch_id LEFT JOIN repo ON repo.id=ti.repo_id \
             JOIN trans_item_action action ON action.id=ti.action_id \
             JOIN trans_item_reason reason ON reason.id=ti.reason_id \
             JOIN trans_item_state state ON state.id=ti.state_id \
             WHERE ti.trans_id={id} ORDER BY ti.id"
        );
        let mut statement = self.prepare(&sql)?;
        let mut rows = Vec::new();
        while statement.step()? == Step::Row {
            if rows.len() >= MAX_TRANSACTION_ITEMS {
                return Err(HistoryError::Limit("transaction items"));
            }
            rows.push(TransactionItem {
                name: statement.text(0)?,
                epoch: statement.integer(1),
                version: statement.text(2)?,
                release: statement.text(3)?,
                arch: statement.text(4)?,
                repository: statement.text(5)?,
                action: statement.text(6)?,
                reason: statement.text(7)?,
                state: statement.text(8)?,
            });
        }
        Ok(rows)
    }

    fn prepare(&self, sql: &str) -> Result<Query<'_>, HistoryError> {
        let sql =
            CString::new(sql).map_err(|_| HistoryError::Database("query contains NUL".into()))?;
        let mut raw = ptr::null_mut();
        // SAFETY: self.raw is live, SQL is NUL terminated, raw is a valid out
        // pointer, and Query finalizes the returned statement.
        let status =
            unsafe { (self.api.prepare_v2)(self.raw, sql.as_ptr(), -1, &mut raw, ptr::null_mut()) };
        if status != SQLITE_OK || raw.is_null() {
            return Err(HistoryError::Database(error_message(&self.api, self.raw)));
        }
        Ok(Query {
            database: self,
            raw,
            finished: false,
        })
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: Database exclusively owns this live connection.
            unsafe { (self.api.close_v2)(self.raw) };
            self.raw = ptr::null_mut();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Row,
    Done,
}

struct Query<'a> {
    database: &'a Database,
    raw: *mut Statement,
    finished: bool,
}

impl Query<'_> {
    fn step(&mut self) -> Result<Step, HistoryError> {
        if self.finished {
            return Ok(Step::Done);
        }
        // SAFETY: raw is a live statement exclusively advanced by this Query.
        match unsafe { (self.database.api.step)(self.raw) } {
            SQLITE_ROW => Ok(Step::Row),
            SQLITE_DONE => {
                self.finished = true;
                Ok(Step::Done)
            }
            _ => Err(HistoryError::Database(error_message(
                &self.database.api,
                self.database.raw,
            ))),
        }
    }

    fn integer(&self, column: c_int) -> i64 {
        // SAFETY: raw is live and column indexes are fixed by each query.
        unsafe { (self.database.api.column_int64)(self.raw, column) }
    }

    fn optional_integer(&self, column: c_int) -> Option<i64> {
        // SQLITE_NULL is 5. All other types are converted by SQLite.
        // SAFETY: raw is live and the column index is fixed by the query.
        (unsafe { (self.database.api.column_type)(self.raw, column) } != 5)
            .then(|| self.integer(column))
    }

    fn text(&self, column: c_int) -> Result<String, HistoryError> {
        // SAFETY: SQLite owns the pointer until the next step/finalize. We
        // copy exactly column_bytes before either operation occurs.
        let bytes = unsafe { (self.database.api.column_bytes)(self.raw, column) };
        if bytes < 0 || usize::try_from(bytes).unwrap_or(usize::MAX) > MAX_TEXT_BYTES {
            return Err(HistoryError::Limit("text column"));
        }
        // SAFETY: same live row guarantee; non-NULL text of this length is
        // readable. NULL with length zero is normalized to an empty string.
        let pointer = unsafe { (self.database.api.column_text)(self.raw, column) };
        if pointer.is_null() {
            return if bytes == 0 {
                Ok(String::new())
            } else {
                Err(HistoryError::Database("NULL text pointer".into()))
            };
        }
        // SAFETY: SQLite returned a buffer with at least column_bytes bytes.
        let value = unsafe { slice::from_raw_parts(pointer, bytes as usize) };
        std::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_| HistoryError::Database("text is not UTF-8".into()))
    }
}

impl Drop for Query<'_> {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: Query exclusively owns this live statement.
            unsafe { (self.database.api.finalize)(self.raw) };
            self.raw = ptr::null_mut();
        }
    }
}

fn transaction_row(statement: &Query<'_>) -> Result<Transaction, HistoryError> {
    let id = statement.integer(0);
    let item_count = statement.integer(7);
    if id <= 0 || item_count < 0 {
        return Err(HistoryError::Database(
            "invalid transaction identity or item count".into(),
        ));
    }
    Ok(Transaction {
        id,
        begin_unix: statement.integer(1),
        end_unix: statement.optional_integer(2),
        state: statement.text(3)?,
        user_id: statement.integer(4),
        releasever: statement.text(5)?,
        description: statement.text(6)?,
        item_count,
    })
}

fn error_message(api: &Api, database: *mut Sqlite) -> String {
    if database.is_null() {
        return "SQLite handle is null".into();
    }
    // SAFETY: database is live and sqlite3_errmsg returns a stable
    // NUL-terminated string until the next call on that connection.
    let pointer = unsafe { (api.errmsg)(database) };
    if pointer.is_null() {
        return "SQLite error message is null".into();
    }
    // SAFETY: sqlite3_errmsg guarantees a NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_root_system_access_fails_before_library_or_path_access() {
        if rustix::process::geteuid().as_raw() != 0 {
            assert!(matches!(list_system(20), Err(HistoryError::NotRoot)));
        }
    }

    #[test]
    fn zero_list_limit_is_rejected() {
        if rustix::process::geteuid().as_raw() == 0 {
            assert!(matches!(list_system(0), Err(HistoryError::Limit(_))));
        }
    }
}
