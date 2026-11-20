using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace SecureFileManager;

public static class PasswordHasher
{
    private const int Iterations = 600_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, Iterations, HashBytes);
        return string.Create(CultureInfo.InvariantCulture,
            $"pbkdf2-sha256${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}");
    }

    public static bool Verify(string password, string stored)
    {
        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2-sha256") return false;
        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var iterations)
            || iterations < 100_000 || iterations > 10_000_000) return false;
        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            if (expected.Length == 0) return false;
            return CryptographicOperations.FixedTimeEquals(Derive(password, salt, iterations, expected.Length), expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] Derive(string password, byte[] salt, int iterations, int length) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, length);
}

public sealed partial class AuthService(Database db)
{
    // Хеш для несуществующего логина: время ответа не выдаёт, есть ли такой пользователь.
    private static readonly string DummyHash = PasswordHasher.Hash(Guid.NewGuid().ToString());

    [GeneratedRegex("^[A-Za-z0-9_.-]{3,50}$")]
    private static partial Regex UsernameRegex();

    public void Register(string username, string password)
    {
        if (!UsernameRegex().IsMatch(username))
            throw new AppException("Логин: 3-50 символов, только латиница, цифры и _ . -");
        if (password.Length < 8 || password.Length > 128)
            throw new AppException("Пароль: от 8 до 128 символов.");

        var hash = PasswordHasher.Hash(password);
        try
        {
            db.TxRun(() =>
            {
                var id = db.InsertUser(username, hash);
                db.Audit(id, username, "register", username, true);
            });
        }
        catch (SqliteException e) when (e.SqliteErrorCode == 19) // SQLITE_CONSTRAINT: уникальность проверяет сама БД
        {
            db.Audit(null, username, "register", username, false, "duplicate");
            throw new AppException("Этот логин занят.");
        }
    }

    public Session? Login(string username, string password)
    {
        var user = db.FindUser(username);
        if (user is null)
        {
            PasswordHasher.Verify(password, DummyHash);
            db.Audit(null, username, "login", username, false, "unknown user");
            return null;
        }

        var now = DateTime.UtcNow;
        if (user.LockedUntil is not null)
        {
            var until = DateTime.Parse(user.LockedUntil, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
            if (until > now)
            {
                PasswordHasher.Verify(password, DummyHash);
                db.Audit(user.Id, user.Username, "login", user.Username, false, "locked");
                return null;
            }
            db.ResetLoginFailures(user.Id);
        }

        if (!PasswordHasher.Verify(password, user.PasswordHash))
        {
            db.TxRun(() =>
            {
                var lockUntil = now.AddMinutes(Limits.LockoutMinutes).ToString("O", CultureInfo.InvariantCulture);
                db.RegisterLoginFailure(user.Id, Limits.MaxLockoutAttempts, lockUntil);
                db.Audit(user.Id, user.Username, "login", user.Username, false, "bad password");
            });
            return null;
        }

        db.TxRun(() =>
        {
            db.ResetLoginFailures(user.Id);
            db.Audit(user.Id, user.Username, "login", user.Username, true);
        });
        return new Session(user.Id, user.Username);
    }
}
