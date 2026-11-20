using Microsoft.Data.Sqlite;

namespace SecureFileManager;

public sealed record UserRow(long Id, string Username, string PasswordHash, int FailedAttempts, string? LockedUntil);
public sealed record FileRecord(long Id, string Filename, string CreatedAt, long Size, string Location, string? Sha256);
public sealed record AuditRow(string Timestamp, string Action, string Target, bool Success, string Details);

/// <summary>Весь SQL приложения. Значения передаются только через параметры.</summary>
public sealed class Database : IDisposable
{
    private const string Schema = """
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(username) <= 50),
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS Files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL CHECK (length(filename) <= 255),
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            size INTEGER NOT NULL CHECK (size >= 0),
            location TEXT NOT NULL,
            sha256 TEXT,
            deleted_at TEXT,
            owner_id INTEGER NOT NULL REFERENCES Users(id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_files_active
            ON Files(owner_id, location) WHERE deleted_at IS NULL;
        CREATE TABLE IF NOT EXISTS Operations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            operation_type TEXT NOT NULL CHECK (operation_type IN ('create','modify','delete')),
            file_id INTEGER NOT NULL REFERENCES Files(id),
            user_id INTEGER NOT NULL REFERENCES Users(id)
        );
        CREATE TABLE IF NOT EXISTS AuditLog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            user_id INTEGER REFERENCES Users(id),
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            success INTEGER NOT NULL CHECK (success IN (0,1)),
            details TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS operations_no_update BEFORE UPDATE ON Operations
            BEGIN SELECT RAISE(ABORT, 'Operations is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS operations_no_delete BEFORE DELETE ON Operations
            BEGIN SELECT RAISE(ABORT, 'Operations is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON AuditLog
            BEGIN SELECT RAISE(ABORT, 'AuditLog is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON AuditLog
            BEGIN SELECT RAISE(ABORT, 'AuditLog is append-only'); END;
        """;

    private readonly SqliteConnection _connection;
    private SqliteTransaction? _tx;

    public Database(string path)
    {
        using (new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.ReadWrite | FileShare.Delete,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        })) { }

        _connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            ForeignKeys = true,
            Pooling = false,
        }.ToString());
        _connection.Open();
        Exec("PRAGMA busy_timeout = 10000;");
        Exec("PRAGMA journal_mode = WAL;");
        TxRun(() => Exec(Schema));
    }

    public void Dispose() => _connection.Dispose();

    private SqliteCommand Cmd(string sql, params (string Name, object? Value)[] args)
    {
        var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.Transaction = _tx;
        foreach (var (name, value) in args) cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return cmd;
    }

    private void Exec(string sql, params (string Name, object? Value)[] args)
    {
        using var cmd = Cmd(sql, args);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Транзакция BEGIN IMMEDIATE: блокировка записи берётся сразу, поэтому нет гонки чтение-проверка-запись.</summary>
    public T Tx<T>(Func<T> body)
    {
        if (_tx is not null) throw new InvalidOperationException("Nested transaction");
        _tx = _connection.BeginTransaction();
        try
        {
            var result = body();
            _tx.Commit();
            return result;
        }
        catch
        {
            _tx.Rollback();
            throw;
        }
        finally
        {
            _tx.Dispose();
            _tx = null;
        }
    }

    public void TxRun(Action body) => Tx(() => { body(); return true; });

    // ---------- Users ----------

    public long InsertUser(string username, string passwordHash)
    {
        Exec("INSERT INTO Users (username, password_hash) VALUES (@u, @p);", ("@u", username), ("@p", passwordHash));
        return LastId();
    }

    public UserRow? FindUser(string username)
    {
        using var cmd = Cmd(
            "SELECT id, username, password_hash, failed_attempts, locked_until FROM Users WHERE username = @u;",
            ("@u", username));
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new UserRow(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetInt32(3), r.IsDBNull(4) ? null : r.GetString(4));
    }

    public void RegisterLoginFailure(long userId, int maxAttempts, string lockUntil) => Exec(
        """
        UPDATE Users SET
            failed_attempts = failed_attempts + 1,
            locked_until = CASE WHEN failed_attempts + 1 >= @max THEN @until ELSE locked_until END
        WHERE id = @id;
        """,
        ("@max", maxAttempts), ("@until", lockUntil), ("@id", userId));

    public void ResetLoginFailures(long userId) =>
        Exec("UPDATE Users SET failed_attempts = 0, locked_until = NULL WHERE id = @id;", ("@id", userId));

    // ---------- Files ----------

    private const string FileColumns = "id, filename, created_at, size, location, sha256";

    private static FileRecord ReadFile(SqliteDataReader r) => new(
        r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetInt64(3), r.GetString(4), r.IsDBNull(5) ? null : r.GetString(5));

    public FileRecord? FindActiveFile(long ownerId, string location)
    {
        using var cmd = Cmd(
            $"SELECT {FileColumns} FROM Files WHERE owner_id = @o AND location = @l AND deleted_at IS NULL;",
            ("@o", ownerId), ("@l", location));
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadFile(r) : null;
    }

    public List<FileRecord> ListActiveFiles(long ownerId, string? underPrefix = null)
    {
        // substr вместо LIKE: символы % и _ в имени каталога не становятся шаблоном.
        using var cmd = Cmd(
            $"""
            SELECT {FileColumns} FROM Files
            WHERE owner_id = @o AND deleted_at IS NULL
              AND (@p IS NULL OR substr(location, 1, length(@p)) = @p)
            ORDER BY location;
            """,
            ("@o", ownerId), ("@p", underPrefix));
        using var r = cmd.ExecuteReader();
        var result = new List<FileRecord>();
        while (r.Read()) result.Add(ReadFile(r));
        return result;
    }

    public long TotalSize(long ownerId)
    {
        using var cmd = Cmd("SELECT COALESCE(SUM(size), 0) FROM Files WHERE owner_id = @o AND deleted_at IS NULL;", ("@o", ownerId));
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    public long InsertFile(long ownerId, string filename, long size, string location, string? sha256)
    {
        Exec(
            "INSERT INTO Files (filename, size, location, sha256, owner_id) VALUES (@n, @s, @l, @h, @o);",
            ("@n", filename), ("@s", size), ("@l", location), ("@h", sha256), ("@o", ownerId));
        return LastId();
    }

    public void UpdateFile(long id, long size, string? sha256) =>
        Exec("UPDATE Files SET size = @s, sha256 = @h WHERE id = @id;", ("@s", size), ("@h", sha256), ("@id", id));

    public void MarkDeleted(long id) => Exec(
        "UPDATE Files SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = @id;", ("@id", id));

    public void AddOperation(string type, long fileId, long userId) => Exec(
        "INSERT INTO Operations (operation_type, file_id, user_id) VALUES (@t, @f, @u);",
        ("@t", type), ("@f", fileId), ("@u", userId));

    private long LastId()
    {
        using var cmd = Cmd("SELECT last_insert_rowid();");
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    // ---------- Audit ----------

    public void Audit(long? userId, string username, string action, string target, bool success, string details = "") => Exec(
        "INSERT INTO AuditLog (user_id, username, action, target, success, details) VALUES (@i, @u, @a, @t, @s, @d);",
        ("@i", userId), ("@u", Text.Clean(username)), ("@a", Text.Clean(action)),
        ("@t", Text.Clean(target)), ("@s", success ? 1 : 0), ("@d", Text.Clean(details)));

    public List<AuditRow> ReadAudit(long userId, int limit)
    {
        using var cmd = Cmd(
            "SELECT timestamp, action, target, success, details FROM AuditLog WHERE user_id = @u ORDER BY id DESC LIMIT @n;",
            ("@u", userId), ("@n", limit));
        using var r = cmd.ExecuteReader();
        var rows = new List<AuditRow>();
        while (r.Read()) rows.Add(new AuditRow(r.GetString(0), r.GetString(1), r.GetString(2), r.GetInt32(3) == 1, r.GetString(4)));
        return rows;
    }
}
