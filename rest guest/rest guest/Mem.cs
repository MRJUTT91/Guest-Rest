using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GTC
{
    public class GTCMem
    {
        // Native imports
        [DllImport("kernel32.dll")]
        private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, UIntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, UIntPtr dwLength);

        [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION32 lpBuffer, UIntPtr dwLength);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

       
        // Constants
        private const uint MEM_PRIVATE = 0x20000;
        private const uint MEM_IMAGE = 0x1000000;
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const int MAX_DEGREE_OF_PARALLELISM = 8;
        private const int READ_CHUNK_SIZE = 1024 * 1024;
        private const int MIN_REGION_SIZE_TO_SCAN = 4096;
        private const uint THREAD_SUSPEND_RESUME = 0x0002;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const string SE_DEBUG_NAME = "SeDebugPrivilege";
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;


        // Structs
        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        // Process handles and caches
        private IntPtr _pHandle;
        private Process _theProc;
        private Dictionary<string, IntPtr> _modules = new Dictionary<string, IntPtr>();
        private ProcessModule _mainModule;
        private bool _is64Bit;
        private ConcurrentDictionary<string, List<MemoryRegionResult>> _regionCache = new ConcurrentDictionary<string, List<MemoryRegionResult>>();

        public bool Is64Bit => _is64Bit;
        public Process TheProcess => _theProc;

        #region Memory Scanning
        public async Task<IEnumerable<long>> AoBScan(long start, long end, string search, bool writable = false, bool executable = false, string file = "")
        {
            return await AoBScan(start, end, search, true, writable, executable, file);
        }

        public async Task<IEnumerable<long>> AoBScan(long start, long end, string search, bool readable, bool writable, bool executable, string file = "")
        {
            return await Task.Run(() =>
            {
                var parsedPattern = ParsePattern(search, file);
                var pattern = parsedPattern.pattern;
                var mask = parsedPattern.mask;

                var regions = GetMemoryRegions(start, end, readable, writable, executable)
                    .Where(r => r.RegionSize >= MIN_REGION_SIZE_TO_SCAN)
                    .ToList();

                var results = new ConcurrentBag<long>();

                Parallel.ForEach(regions, new ParallelOptions
                {
                    MaxDegreeOfParallelism = MAX_DEGREE_OF_PARALLELISM
                }, region =>
                {
                    try
                    {
                        var matches = ScanRegionOptimized(region, pattern, mask);
                        foreach (var match in matches)
                            results.Add(match);
                    }
                    catch { }
                });

                return results.OrderBy(x => x).AsEnumerable();
            });
        }

        private (byte[] pattern, byte[] mask) ParsePattern(string search, string file)
        {
            string patternStr = string.IsNullOrEmpty(file) ? search : LoadCodeFromFile(search, file);
            string[] bytes = patternStr.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            byte[] pattern = new byte[bytes.Length];
            byte[] mask = new byte[bytes.Length];

            for (int i = 0; i < bytes.Length; i++)
            {
                string byteStr = bytes[i];
                if (byteStr == "??" || byteStr == "?")
                {
                    mask[i] = 0x00;
                    pattern[i] = 0x00;
                }
                else if (byteStr.Length == 2 && byteStr[1] == '?')
                {
                    mask[i] = 0xF0;
                    pattern[i] = Convert.ToByte(byteStr[0] + "0", 16);
                }
                else if (byteStr.Length == 2 && byteStr[0] == '?')
                {
                    mask[i] = 0x0F;
                    pattern[i] = Convert.ToByte("0" + byteStr[1], 16);
                }
                else
                {
                    mask[i] = 0xFF;
                    pattern[i] = Convert.ToByte(byteStr, 16);
                }
            }

            return (pattern, mask);
        }

        private unsafe long[] ScanRegionOptimized(MemoryRegionResult region, byte[] pattern, byte[] mask)
        {
            byte[] buffer = new byte[Math.Min(region.RegionSize, 100 * 1024 * 1024)];
            if (!ReadMemoryFast(_pHandle, region.CurrentBaseAddress, buffer))
                return Array.Empty<long>();

            var matches = new List<long>();
            int patternLength = pattern.Length;
            int maxIndex = buffer.Length - patternLength;

            byte firstMask = mask[0];
            byte firstPattern = (byte)(pattern[0] & firstMask);

            fixed (byte* bufferPtr = buffer)
            fixed (byte* patternPtr = pattern)
            fixed (byte* maskPtr = mask)
            {
                for (int i = 0; i <= maxIndex; i++)
                {
                    if ((bufferPtr[i] & firstMask) != firstPattern)
                        continue;

                    bool match = true;
                    for (int j = 1; j < patternLength; j++)
                    {
                        if ((bufferPtr[i + j] & maskPtr[j]) != (patternPtr[j] & maskPtr[j]))
                        {
                            match = false;
                            break;
                        }
                    }

                    if (match)
                    {
                        matches.Add((long)region.CurrentBaseAddress.ToUInt64() + i);
                        i += patternLength - 1;
                    }
                }
            }

            return matches.ToArray();
        }

        private bool ReadMemoryFast(IntPtr hProcess, UIntPtr address, byte[] buffer)
        {
            int totalRead = 0;
            int remaining = buffer.Length;
            byte[] readBuffer = new byte[Math.Min(READ_CHUNK_SIZE, remaining)];

            while (remaining > 0)
            {
                int toRead = Math.Min(readBuffer.Length, remaining);

                if (!ReadProcessMemory(hProcess,
                                     UIntPtr.Add(address, totalRead),
                                     readBuffer,
                                     (UIntPtr)toRead,
                                     IntPtr.Zero))
                {
                    return false;
                }

                Buffer.BlockCopy(readBuffer, 0, buffer, totalRead, toRead);
                totalRead += toRead;
                remaining -= toRead;
            }

            return true;
        }

        private List<MemoryRegionResult> GetMemoryRegions(long start, long end, bool readable, bool writable, bool executable)
        {
            string cacheKey = $"{start:X}-{end:X}-{readable}-{writable}-{executable}";
            if (_regionCache.TryGetValue(cacheKey, out var cached))
                return cached;

            var regions = new List<MemoryRegionResult>();
            GetSystemInfo(out SYSTEM_INFO sysInfo);

            start = Math.Max(start, (long)sysInfo.minimumApplicationAddress.ToUInt64());
            end = Math.Min(end, (long)sysInfo.maximumApplicationAddress.ToUInt64());

            UIntPtr currentAddress = new UIntPtr((ulong)start);

            while (currentAddress.ToUInt64() < (ulong)end)
            {
                MEMORY_BASIC_INFORMATION mbi;
                UIntPtr result = VirtualQueryEx(_pHandle, currentAddress, out mbi);
                if (result == UIntPtr.Zero) break;

                if (IsValidRegion(mbi, readable, writable, executable))
                {
                    regions.Add(new MemoryRegionResult
                    {
                        CurrentBaseAddress = currentAddress,
                        RegionSize = mbi.RegionSize,
                        RegionBase = mbi.BaseAddress
                    });
                }

                ulong nextAddress = mbi.BaseAddress.ToUInt64() + (ulong)mbi.RegionSize;
                if (nextAddress <= currentAddress.ToUInt64()) break;
                currentAddress = new UIntPtr(nextAddress);
            }

            _regionCache.TryAdd(cacheKey, regions);
            return regions;
        }

        private UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer)
        {
            if (Is64Bit || IntPtr.Size == 8)
            {
                MEMORY_BASIC_INFORMATION64 mbi64;
                UIntPtr result = Native_VirtualQueryEx(hProcess, lpAddress, out mbi64,
                    new UIntPtr((uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION64>()));

                lpBuffer = new MEMORY_BASIC_INFORMATION
                {
                    BaseAddress = mbi64.BaseAddress,
                    AllocationBase = mbi64.AllocationBase,
                    AllocationProtect = mbi64.AllocationProtect,
                    RegionSize = (long)mbi64.RegionSize,
                    State = mbi64.State,
                    Protect = mbi64.Protect,
                    Type = mbi64.Type
                };
                return result;
            }
            else
            {
                MEMORY_BASIC_INFORMATION32 mbi32;
                UIntPtr result = Native_VirtualQueryEx(hProcess, lpAddress, out mbi32,
                    new UIntPtr((uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION32>()));

                lpBuffer = new MEMORY_BASIC_INFORMATION
                {
                    BaseAddress = mbi32.BaseAddress,
                    AllocationBase = mbi32.AllocationBase,
                    AllocationProtect = mbi32.AllocationProtect,
                    RegionSize = mbi32.RegionSize,
                    State = mbi32.State,
                    Protect = mbi32.Protect,
                    Type = mbi32.Type
                };
                return result;
            }
        }

        private bool IsValidRegion(MEMORY_BASIC_INFORMATION mbi, bool readable, bool writable, bool executable)
        {
            if (mbi.State != 0x1000) return false;
            if ((mbi.Protect & 0x100) != 0) return false;
            if ((mbi.Protect & 0x1) != 0) return false;
            if (mbi.Type != MEM_PRIVATE && mbi.Type != MEM_IMAGE) return false;

            bool isReadable = (mbi.Protect & 0x2) > 0;
            bool isWritable = (mbi.Protect & 0x4) > 0 ||
                            (mbi.Protect & 0x8) > 0 ||
                            (mbi.Protect & 0x40) > 0 ||
                            (mbi.Protect & 0x80) > 0;
            bool isExecutable = (mbi.Protect & 0x10) > 0 ||
                               (mbi.Protect & 0x20) > 0 ||
                               (mbi.Protect & 0x40) > 0 ||
                               (mbi.Protect & 0x80) > 0;

            return (isReadable && readable) || (isWritable && writable) || (isExecutable && executable);
        }
        #endregion

        #region Memory Operations
        public byte[] ReadMemory(string address, long length, string file = "")
        {
            byte[] buffer = new byte[length];
            UIntPtr addr = GetCode(address, file, 8);
            return ReadProcessMemory(_pHandle, addr, buffer, (UIntPtr)length, IntPtr.Zero) ? buffer : null;
        }

        public bool WriteMemory(string address, string type, string value, string file = "", Encoding encoding = null)
        {
            byte[] bytes = GetBytesForType(type, value, encoding);
            UIntPtr addr = GetCode(address, file, 8);
            return WriteProcessMemory(_pHandle, addr, bytes, (UIntPtr)bytes.Length, IntPtr.Zero);
        }

        private byte[] GetBytesForType(string type, string value, Encoding encoding)
        {
            switch (type.ToLower())
            {
                case "float": return BitConverter.GetBytes(Convert.ToSingle(value));
                case "int": return BitConverter.GetBytes(Convert.ToInt32(value));
                case "byte": return new byte[] { Convert.ToByte(value, 16) };
                case "2bytes": return new byte[] { (byte)(Convert.ToInt32(value) % 256), (byte)(Convert.ToInt32(value) / 256) };
                case "bytes": return ParseBytesString(value);
                case "double": return BitConverter.GetBytes(Convert.ToDouble(value));
                case "long": return BitConverter.GetBytes(Convert.ToInt64(value));
                case "string": return encoding?.GetBytes(value) ?? Encoding.UTF8.GetBytes(value);
                default: return new byte[0];
            }
        }

        private byte[] ParseBytesString(string value)
        {
            if (value.Contains(",") || value.Contains(" "))
            {
                string[] parts = value.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                byte[] bytes = new byte[parts.Length];
                for (int i = 0; i < parts.Length; i++)
                    bytes[i] = Convert.ToByte(parts[i], 16);
                return bytes;
            }
            return new byte[] { Convert.ToByte(value, 16) };
        }

        private string LoadCodeFromFile(string name, string file)
        {
            try
            {
                if (File.Exists(file))
                {
                    var lines = File.ReadAllLines(file);
                    foreach (var line in lines)
                    {
                        if (line.StartsWith(name + "="))
                        {
                            return line.Substring(name.Length + 1).Trim();
                        }
                    }
                }
                return name;
            }
            catch
            {
                return name;
            }
        }

        public UIntPtr GetCode(string name, string path = "", int size = 8)
        {
            return Is64Bit ? Get64BitCode(name, path, size) : Get32BitCode(name, path, size);
        }

        private UIntPtr Get64BitCode(string name, string path, int size)
        {
            string code = path != "" ? LoadCodeFromFile(name, path) : name;
            if (string.IsNullOrEmpty(code)) return UIntPtr.Zero;

            code = code.Replace(" ", "");

            if (!code.Contains("+") && !code.Contains(","))
                return new UIntPtr(Convert.ToUInt64(code, 16));

            string offsetStr = code.Contains("+") ? code.Substring(code.IndexOf('+') + 1) : code;

            if (offsetStr.Contains(','))
            {
                long[] offsets = ParseOffsets(offsetStr);
                byte[] buffer = new byte[size];

                if (code.Contains("base") || code.Contains("main"))
                {
                    ReadProcessMemory(_pHandle, (UIntPtr)((ulong)((long)_mainModule.BaseAddress + offsets[0])),
                                     buffer, (UIntPtr)size, IntPtr.Zero);
                }
                else if (!code.Contains("base") && !code.Contains("main") && code.Contains("+"))
                {
                    string[] parts = code.Split('+');
                    IntPtr baseAddr = GetBaseAddress(parts[0]);
                    ReadProcessMemory(_pHandle, (UIntPtr)((ulong)((long)baseAddr + offsets[0])),
                                     buffer, (UIntPtr)size, IntPtr.Zero);
                }
                else
                {
                    ReadProcessMemory(_pHandle, (UIntPtr)((ulong)offsets[0]), buffer, (UIntPtr)size, IntPtr.Zero);
                }

                long value = BitConverter.ToInt64(buffer, 0);
                UIntPtr result = UIntPtr.Zero;

                for (int i = 1; i < offsets.Length; i++)
                {
                    result = new UIntPtr(Convert.ToUInt64(value + offsets[i]));
                    ReadProcessMemory(_pHandle, result, buffer, (UIntPtr)size, IntPtr.Zero);
                    value = BitConverter.ToInt64(buffer, 0);
                }

                return result;
            }
            else
            {
                long offset = Convert.ToInt64(offsetStr, 16);
                IntPtr baseAddr = GetBaseAddress(code);
                return (UIntPtr)((ulong)((long)baseAddr + offset));
            }
        }

        private IntPtr GetBaseAddress(string codePart)
        {
            if (codePart.Contains("base") || codePart.Contains("main"))
                return _mainModule.BaseAddress;

            if (codePart.Contains("+"))
            {
                string moduleName = codePart.Split('+')[0];
                if (moduleName.Contains(".dll") || moduleName.Contains(".exe") || moduleName.Contains(".bin"))
                    return _modules.TryGetValue(moduleName, out var addr) ? addr : IntPtr.Zero;

                return (IntPtr)long.Parse(moduleName.Replace("0x", ""), NumberStyles.HexNumber);
            }

            return _modules[codePart.Split('+')[0]];
        }

        private long[] ParseOffsets(string offsetsStr)
        {
            string[] parts = offsetsStr.Split(',');
            long[] offsets = new long[parts.Length];

            for (int i = 0; i < parts.Length; i++)
            {
                string part = parts[i];
                bool isNegative = part.Contains("-");
                part = part.Replace("-", "").Replace("0x", "");

                long value = long.Parse(part, NumberStyles.HexNumber);
                offsets[i] = isNegative ? -value : value;
            }

            return offsets;
        }

        private UIntPtr Get32BitCode(string name, string path, int size)
        {
            string code = path != "" ? LoadCodeFromFile(name, path) : name;
            if (string.IsNullOrEmpty(code)) return UIntPtr.Zero;

            code = code.Replace(" ", "");

            if (!code.Contains("+") && !code.Contains(","))
                return new UIntPtr(Convert.ToUInt32(code, 16));

            string offsetStr = code.Contains("+") ? code.Substring(code.IndexOf('+') + 1) : code;

            if (offsetStr.Contains(','))
            {
                int[] offsets = Parse32BitOffsets(offsetStr);
                byte[] buffer = new byte[size];

                if (code.Contains("base") || code.Contains("main"))
                {
                    ReadProcessMemory(_pHandle, (UIntPtr)((ulong)((int)_mainModule.BaseAddress + offsets[0])),
                                     buffer, (UIntPtr)size, IntPtr.Zero);
                }
                else if (!code.Contains("base") && !code.Contains("main") && code.Contains("+"))
                {
                    string[] parts = code.Split('+');
                    IntPtr baseAddr = Get32BitBaseAddress(parts[0]);
                    ReadProcessMemory(_pHandle, (UIntPtr)((ulong)((int)baseAddr + offsets[0])),
                                     buffer, (UIntPtr)size, IntPtr.Zero);
                }
                else
                {
                    ReadProcessMemory(_pHandle, (UIntPtr)((ulong)offsets[0]), buffer, (UIntPtr)size, IntPtr.Zero);
                }

                uint value = BitConverter.ToUInt32(buffer, 0);
                UIntPtr result = UIntPtr.Zero;

                for (int i = 1; i < offsets.Length; i++)
                {
                    result = new UIntPtr(Convert.ToUInt32((long)value + offsets[i]));
                    ReadProcessMemory(_pHandle, result, buffer, (UIntPtr)size, IntPtr.Zero);
                    value = BitConverter.ToUInt32(buffer, 0);
                }

                return result;
            }
            else
            {
                int offset = Convert.ToInt32(offsetStr, 16);
                IntPtr baseAddr = Get32BitBaseAddress(code);
                return (UIntPtr)((ulong)((int)baseAddr + offset));
            }
        }

        private IntPtr Get32BitBaseAddress(string codePart)
        {
            if (codePart.ToLower().Contains("base") || codePart.ToLower().Contains("main"))
                return _mainModule.BaseAddress;

            if (codePart.Contains("+"))
            {
                string moduleName = codePart.Split('+')[0];
                if (!moduleName.ToLower().Contains(".dll") && !moduleName.ToLower().Contains(".exe") && !moduleName.ToLower().Contains(".bin"))
                {
                    string addrStr = moduleName.Replace("0x", "");
                    return (IntPtr)int.Parse(addrStr, NumberStyles.HexNumber);
                }
                return _modules[moduleName];
            }

            return _modules[codePart.Split('+')[0]];
        }

        private int[] Parse32BitOffsets(string offsetsStr)
        {
            string[] parts = offsetsStr.Split(',');
            int[] offsets = new int[parts.Length];

            for (int i = 0; i < parts.Length; i++)
            {
                string part = parts[i];
                bool isNegative = part.Contains("-");
                part = part.Replace("-", "").Replace("0x", "");

                int value = int.Parse(part, NumberStyles.HexNumber);
                offsets[i] = isNegative ? -value : value;
            }

            return offsets;
        }
        #endregion

        #region Process Management
        public bool OpenProcess(int pid)
        {
            if (pid <= 0) return false;

            try
            {
                _theProc = Process.GetProcessById(pid);
                if (_theProc == null || _theProc.HasExited) return false;

                _pHandle = OpenProcess(PROCESS_ALL_ACCESS, true, pid);
                if (_pHandle == IntPtr.Zero) return false;

                _mainModule = _theProc.MainModule;
                GetModules();

                bool isWow64;
                _is64Bit = Environment.Is64BitOperatingSystem &&
                          IsWow64Process(_pHandle, out isWow64) &&
                          !isWow64;

                return true;
            }
            catch
            {
                return false;
            }
        }

        private void GetModules()
        {
            _modules.Clear();
            if (_theProc == null) return;

            foreach (ProcessModule module in _theProc.Modules)
            {
                if (!string.IsNullOrEmpty(module.ModuleName))
                    _modules[module.ModuleName] = module.BaseAddress;
            }
        }

        public void CloseProcess()
        {
            if (_pHandle != IntPtr.Zero)
            {
                CloseHandle(_pHandle);
                _pHandle = IntPtr.Zero;
            }
            _theProc = null;
            _modules.Clear();
            _regionCache.Clear();
        }
        #endregion


        #region System Freeze Methods
        public void EnableDebugPrivileges(ref IntPtr hToken)
        {
            IntPtr processHandle = Process.GetCurrentProcess().Handle;
            if (!OpenProcessToken(processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
                return;

            LUID luid;
            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out luid))
                return;

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Luid = luid;
            tp.Attributes = SE_PRIVILEGE_ENABLED;

            AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }

        public void SuspendAllProcessesExceptSelf()
        {
            uint currentPid = (uint)Process.GetCurrentProcess().Id;
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == currentPid) continue;

                    foreach (ProcessThread thread in process.Threads)
                    {
                        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)thread.Id);
                        if (hThread != IntPtr.Zero)
                        {
                            SuspendThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                }
                catch { }
            }
        }

        public void ResumeAllProcesses()
        {
            uint currentPid = (uint)Process.GetCurrentProcess().Id;
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == currentPid) continue;

                    foreach (ProcessThread thread in process.Threads)
                    {
                        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)thread.Id);
                        if (hThread != IntPtr.Zero)
                        {
                            ResumeThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                }
                catch { }
            }
        }

        public void BeginExclusiveOperation()
        {
            // Set maximum priority
            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.RealTime;
            Thread.CurrentThread.Priority = ThreadPriority.Highest;

            // Freeze other processes
            uint currentPid = (uint)Process.GetCurrentProcess().Id;
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == currentPid) continue;

                    foreach (ProcessThread thread in process.Threads)
                    {
                        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)thread.Id);
                        if (hThread != IntPtr.Zero)
                        {
                            SuspendThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                }
                catch { }
            }
        }

        public void EndExclusiveOperation()
        {
            // Unfreeze other processes
            uint currentPid = (uint)Process.GetCurrentProcess().Id;
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == currentPid) continue;

                    foreach (ProcessThread thread in process.Threads)
                    {
                        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)thread.Id);
                        if (hThread != IntPtr.Zero)
                        {
                            ResumeThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                }
                catch { }
            }

            // Restore normal priority
            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.Normal;
            Thread.CurrentThread.Priority = ThreadPriority.Normal;
        }


        public bool CloseTokenHandle(IntPtr hToken)
        {
            return CloseHandle(hToken);
        }
        #endregion

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION32
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public uint RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION64
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public uint __alignment1;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
            public uint __alignment2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public uint AllocationProtect;
            public long RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            private ushort reserved;
            public uint pageSize;
            public UIntPtr minimumApplicationAddress;
            public UIntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        internal struct MemoryRegionResult
        {
            public UIntPtr CurrentBaseAddress { get; set; }
            public long RegionSize { get; set; }
            public UIntPtr RegionBase { get; set; }
        }
    }
}