using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace BrowserExtractorCS
{
    public static class Debugger
    {
        public static IntPtr FindTargetAddress(IntPtr hProcess, IntPtr baseAddr, string browserName)
        {
            Win32.IMAGE_DOS_HEADER dosHeader = new Win32.IMAGE_DOS_HEADER();
            byte[] dosHeaderBytes = new byte[Marshal.SizeOf(typeof(Win32.IMAGE_DOS_HEADER))];
            if (!Win32.ReadProcessMemory(hProcess, baseAddr, dosHeaderBytes, dosHeaderBytes.Length, out _))
                return IntPtr.Zero;

            GCHandle handle = GCHandle.Alloc(dosHeaderBytes, GCHandleType.Pinned);
            try { dosHeader = Marshal.PtrToStructure<Win32.IMAGE_DOS_HEADER>(handle.AddrOfPinnedObject()); }
            finally { handle.Free(); }

            IntPtr ntHeadersPtr = baseAddr + dosHeader.e_lfanew;
            Win32.IMAGE_NT_HEADERS64 ntHeaders = new Win32.IMAGE_NT_HEADERS64();
            byte[] ntHeadersBytes = new byte[Marshal.SizeOf(typeof(Win32.IMAGE_NT_HEADERS64))];
            if (!Win32.ReadProcessMemory(hProcess, ntHeadersPtr, ntHeadersBytes, ntHeadersBytes.Length, out _))
                return IntPtr.Zero;

            handle = GCHandle.Alloc(ntHeadersBytes, GCHandleType.Pinned);
            try { ntHeaders = Marshal.PtrToStructure<Win32.IMAGE_NT_HEADERS64>(handle.AddrOfPinnedObject()); }
            finally { handle.Free(); }

            int sectionCount = ntHeaders.FileHeader.NumberOfSections;
            IntPtr sectionHeaderPtr = ntHeadersPtr + Marshal.SizeOf(typeof(Win32.IMAGE_NT_HEADERS64));
            Win32.IMAGE_SECTION_HEADER[] sections = new Win32.IMAGE_SECTION_HEADER[sectionCount];

            for (int i = 0; i < sectionCount; i++)
            {
                byte[] sectionBytes = new byte[Marshal.SizeOf(typeof(Win32.IMAGE_SECTION_HEADER))];
                Win32.ReadProcessMemory(hProcess, sectionHeaderPtr + (i * Marshal.SizeOf(typeof(Win32.IMAGE_SECTION_HEADER))), sectionBytes, sectionBytes.Length, out _);
                handle = GCHandle.Alloc(sectionBytes, GCHandleType.Pinned);
                try { sections[i] = Marshal.PtrToStructure<Win32.IMAGE_SECTION_HEADER>(handle.AddrOfPinnedObject()); }
                finally { handle.Free(); }
            }

            string targetString = "OSCrypt.AppBoundProvider.Decrypt.ResultCode";
            byte[] targetBytes = Encoding.ASCII.GetBytes(targetString);
            IntPtr stringVa = IntPtr.Zero;

            foreach (var section in sections)
            {
                string name = Encoding.ASCII.GetString(section.Name).TrimEnd('\0');
                if (name == ".rdata")
                {
                    byte[] sectionData = Utils.ReadProcessMemoryChunk(hProcess, baseAddr + (int)section.VirtualAddress, (int)section.VirtualSize);
                    int pos = Utils.FindSubsequence(sectionData, targetBytes);
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
                string name = Encoding.ASCII.GetString(section.Name).TrimEnd('\0');
                if (name == ".text")
                {
                    IntPtr sectionStart = baseAddr + (int)section.VirtualAddress;
                    byte[] sectionData = Utils.ReadProcessMemoryChunk(hProcess, sectionStart, (int)section.VirtualSize);

                    for (int pos = 0; pos <= sectionData.Length - 7; pos++)
                    {
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
                    }
                }
            }

            Console.WriteLine($"Could not find matching LEA instruction in {browserName}'s .text section");
            return IntPtr.Zero;
        }

        public static List<uint> GetAllThreads(uint processId)
        {
            List<uint> threads = new List<uint>();
            IntPtr snapshot = Win32.CreateToolhelp32Snapshot(Win32.TH32CS_SNAPTHREAD, 0);
            if (snapshot != (IntPtr)(-1))
            {
                Win32.THREADENTRY32 te = new Win32.THREADENTRY32();
                te.dwSize = (uint)Marshal.SizeOf(typeof(Win32.THREADENTRY32));
                if (Win32.Thread32First(snapshot, ref te))
                {
                    do
                    {
                        if (te.th32OwnerProcessID == processId)
                        {
                            threads.Add(te.th32ThreadID);
                        }
                    } while (Win32.Thread32Next(snapshot, ref te));
                }
                Win32.CloseHandle(snapshot);
            }
            return threads;
        }

        public static void SetHardwareBreakpoint(uint threadId, IntPtr address)
        {
            IntPtr hThread = Win32.OpenThread(Win32.THREAD_GET_CONTEXT | Win32.THREAD_SET_CONTEXT | Win32.THREAD_SUSPEND_RESUME, false, threadId);
            if (hThread == IntPtr.Zero) return;

            Win32.SuspendThread(hThread);

            Win32.CONTEXT context = new Win32.CONTEXT();
            context.ContextFlags = Win32.CONTEXT_DEBUG_REGISTERS;
            if (Win32.GetThreadContext(hThread, ref context))
            {
                context.Dr0 = (ulong)address;
                context.Dr7 = (context.Dr7 & ~0x3uL) | 0x1uL; // Enable DR0 local
                Win32.SetThreadContext(hThread, ref context);
            }

            Win32.ResumeThread(hThread);
            Win32.CloseHandle(hThread);
        }

        public static void ClearHardwareBreakpoints(uint processId)
        {
            foreach (uint threadId in GetAllThreads(processId))
            {
                IntPtr hThread = Win32.OpenThread(Win32.THREAD_GET_CONTEXT | Win32.THREAD_SET_CONTEXT | Win32.THREAD_SUSPEND_RESUME, false, threadId);
                if (hThread != IntPtr.Zero)
                {
                    Win32.SuspendThread(hThread);
                    Win32.CONTEXT context = new Win32.CONTEXT();
                    context.ContextFlags = Win32.CONTEXT_DEBUG_REGISTERS;
                    if (Win32.GetThreadContext(hThread, ref context))
                    {
                        context.Dr0 = 0;
                        context.Dr7 &= ~0x3uL; // Disable DR0
                        Win32.SetThreadContext(hThread, ref context);
                    }
                    Win32.ResumeThread(hThread);
                    Win32.CloseHandle(hThread);
                }
            }
        }

        public static void SetResumeFlag(uint threadId)
        {
            IntPtr hThread = Win32.OpenThread(Win32.THREAD_GET_CONTEXT | Win32.THREAD_SET_CONTEXT | Win32.THREAD_SUSPEND_RESUME, false, threadId);
            if (hThread == IntPtr.Zero) return;

            Win32.SuspendThread(hThread);

            Win32.CONTEXT context = new Win32.CONTEXT();
            context.ContextFlags = Win32.CONTEXT_CONTROL;
            if (Win32.GetThreadContext(hThread, ref context))
            {
                context.EFlags |= 0x10000; // Set RF (Resume Flag)
                Win32.SetThreadContext(hThread, ref context);
            }

            Win32.ResumeThread(hThread);
            Win32.CloseHandle(hThread);
        }

        public static void DebugLoop(IntPtr hProcess, BrowserConfig config, string userDataDir)
        {
            Win32.DEBUG_EVENT debugEvent;
            IntPtr targetAddress = IntPtr.Zero;

            while (Win32.WaitForDebugEvent(out debugEvent, Win32.INFINITE))
            {
                switch (debugEvent.dwDebugEventCode)
                {
                    case Win32.LOAD_DLL_DEBUG_EVENT:
                        var loadDll = debugEvent.u.LoadDll;
                        StringBuilder sb = new StringBuilder(260);
                        uint len = Win32.GetFinalPathNameByHandleW(loadDll.hFile, sb, (uint)sb.Capacity, 0);
                        if (len > 0)
                        {
                            string path = sb.ToString();
                            if (path.Contains(config.DllName, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine($"Found {config.DllName} at {loadDll.lpBaseOfDll:X}");
                                targetAddress = FindTargetAddress(hProcess, loadDll.lpBaseOfDll, config.Name);
                                if (targetAddress != IntPtr.Zero)
                                {
                                    var threads = GetAllThreads(debugEvent.dwProcessId);
                                    Console.WriteLine($"Setting hardware breakpoints for {config.Name} on {threads.Count} threads");
                                    foreach (uint threadId in threads)
                                    {
                                        SetHardwareBreakpoint(threadId, targetAddress);
                                    }
                                }
                            }
                        }
                        break;

                    case Win32.CREATE_THREAD_DEBUG_EVENT:
                        if (targetAddress != IntPtr.Zero)
                        {
                            SetHardwareBreakpoint(debugEvent.dwThreadId, targetAddress);
                        }
                        break;

                    case Win32.EXCEPTION_DEBUG_EVENT:
                        var exception = debugEvent.u.Exception;
                        if (exception.ExceptionRecord.ExceptionCode == Win32.EXCEPTION_SINGLE_STEP)
                        {
                            if (exception.ExceptionRecord.ExceptionAddress == targetAddress)
                            {
                                Console.WriteLine("Target breakpoint hit!");
                                if (Extractor.ExtractKey(debugEvent.dwThreadId, hProcess, config, userDataDir))
                                {
                                    ClearHardwareBreakpoints(debugEvent.dwProcessId);
                                    Win32.TerminateProcess(hProcess, 0);
                                }
                            }
                            SetResumeFlag(debugEvent.dwThreadId);
                        }
                        break;

                    case Win32.EXIT_PROCESS_DEBUG_EVENT:
                        Win32.ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, Win32.DBG_CONTINUE);
                        return;
                }

                Win32.ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, Win32.DBG_CONTINUE);
            }
        }
    }
}
