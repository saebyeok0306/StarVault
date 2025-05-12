using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace StarVault
{
    public class MemoryScanner
    {
        #region Constants
        // private const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const int PROCESS_VM_READ = 0x0010;
        private const int PROCESS_VM_WRITE = 0x0020;
        private const int PROCESS_VM_OPERATION = 0x0008;
        private const int MEM_COMMIT = 0x1000;
        private const int PAGE_READWRITE = 0x04;
        private const int PAGE_EXECUTE_READWRITE = 0x40;
        #endregion

        #region Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        #endregion

        #region Native Methods
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll")]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);
        #endregion

        /// <summary>
        /// Lists processes matching the specified name
        /// </summary>
        /// <param name="name">Part of process name to match</param>
        /// <returns>Dictionary containing process info or null if not found</returns>
        public Dictionary<string, object> ListProcesses(string name)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.ProcessName.Contains(name))
                        {
                            Console.WriteLine($"PID: {proc.Id,6} | Name: {proc.ProcessName}");
                            return new Dictionary<string, object>
                            {
                                { "pid", proc.Id },
                                { "name", proc.ProcessName },
                                { "result", true }
                            };
                        }
                    }
                    catch
                    {
                        // Skip inaccessible processes
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error listing processes: {ex.Message}");
            }

            return new Dictionary<string, object>
            {
                { "pid", null },
                { "name", null },
                { "result", false }
            };
        }

        public IntPtr FindProcessAddr(int pid)
        {
            var res1 = ScanProcessMemory(pid, 111111111);
            if (res1.Count == 0)
            {
                Console.WriteLine("Please run the custom use map." + res1.ToArray());
                return IntPtr.Zero;
            }
            var res2 = ScanProcessMemory(pid, 222222222);
            if (res2.Count == 0)
            {
                Console.WriteLine("Please run the custom use map.");
                return IntPtr.Zero;
            }
            var res3 = ScanProcessMemory(pid, 333333333);
            if (res3.Count == 0)
            {
                Console.WriteLine("Please run the custom use map.");
                return IntPtr.Zero;
            }

            var addresses = new List<IntPtr>();
            foreach (var addr1 in res1)
            {
                foreach (var addr2 in res2)
                {
                    // When the address offset diff is 4 bytes
                    if (addr2 - addr1 == 4)
                    {
                        addresses.Add(addr1);
                    }
                }
            }

            foreach (var addr1 in addresses)
            {
                foreach (var addr3 in res3)
                {
                    // When the address offset diff is 8 bytes
                    if (addr3 - addr1 == 8)
                    {
                        Console.WriteLine($"Found target address: {addr1.ToInt64():X}");
                        return addr1;
                    }
                }
            }

            return IntPtr.Zero;
        }

        /// <summary>
        /// Scan optimized process memory using parallel processing
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="targetValue">Value to search for</param>
        /// <returns>List of memory addresses where the value was found</returns>
        public List<IntPtr> ScanProcessMemory(int pid, int targetValue)
        {
            Console.WriteLine($"scan_process_memory pid: {pid}, target_value: {targetValue}");
            List<IntPtr> foundAddresses = new List<IntPtr>();

            // Open process with all access rights
            var PROCESS_ACCESS = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
            IntPtr processHandle = OpenProcess(PROCESS_ACCESS, false, pid);
            if (processHandle == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine($"Failed to open process. Error code: {error}");
                return foundAddresses;
            }

            try
            {
                // Get system information
                SYSTEM_INFO systemInfo;
                GetSystemInfo(out systemInfo);

                // Set memory address range
                IntPtr minAddress = systemInfo.lpMinimumApplicationAddress;
                IntPtr maxAddress = systemInfo.lpMaximumApplicationAddress;

                // Convert target value to bytes (32-bit integer)
                byte[] targetBytes = BitConverter.GetBytes(targetValue);

                Console.WriteLine($"Searching for: {targetValue} (bytes: {BitConverter.ToString(targetBytes).Replace("-", "")})");
                Console.WriteLine($"Memory range: {minAddress} - {maxAddress}");

                // Start memory scan - Predefine memory regions
                List<(IntPtr BaseAddress, IntPtr RegionSize)> readableRegions = new List<(IntPtr, IntPtr)>();
                IntPtr currentAddress = minAddress;
                
                while (currentAddress.ToInt64() < maxAddress.ToInt64())
                {
                    MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                    int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

                    if (VirtualQueryEx(processHandle, currentAddress, out mbi, (uint)mbiSize) != mbiSize)
                    {
                        break;
                    }

                    // Filter for readable and committed memory regions only
                    if (mbi.State == MEM_COMMIT && mbi.Protect != 0 && (mbi.Protect & PAGE_READWRITE) != 0)
                    {
                        readableRegions.Add((mbi.BaseAddress, mbi.RegionSize));
                    }

                    // Move to the next memory region
                    long nextAddress = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                    if (nextAddress <= currentAddress.ToInt64())
                        break;  // Prevent infinite loop
                        
                    currentAddress = new IntPtr(nextAddress);
                }

                // Use parallel execution for memory scanning
                Parallel.ForEach(readableRegions, region => 
                {
                    try
                    {
                        // Calculate memory region size (cast to long to handle large regions)
                        long regionSizeLong = region.RegionSize.ToInt64();
                        int bufferSize = regionSizeLong > int.MaxValue ? int.MaxValue - 1 : (int)regionSizeLong;
                        
                        byte[] buffer = new byte[bufferSize];
                        IntPtr bytesRead;

                        // Read memory
                        if (ReadProcessMemory(processHandle, region.BaseAddress, buffer, bufferSize, out bytesRead))
                        {
                            int offset = 0;
                            int bytesReadInt = bytesRead.ToInt32();

                            // Search for target value in buffer
                            while (offset <= bytesReadInt - targetBytes.Length)
                            {
                                bool found = true;
                                for (int i = 0; i < targetBytes.Length; i++)
                                {
                                    if (buffer[offset + i] != targetBytes[i])
                                    {
                                        found = false;
                                        break;
                                    }
                                }

                                if (found)
                                {
                                    IntPtr foundAddress = new IntPtr(region.BaseAddress.ToInt64() + offset);
                                    foundAddresses.Add(foundAddress);
                                    Console.WriteLine($"Found at address: 0x{foundAddress.ToInt64():X}");
                                }
                                
                                offset++;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error reading memory region: {ex.Message}");
                    }
                });
            }
            finally
            {
                CloseHandle(processHandle);
            }

            return foundAddresses.ToList();
        }


        /// <summary>
        /// Reads a value from process memory
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="baseAddress">Memory address to read from</param>
        /// <param name="dataType">Type of data to read ("int", "string", "bytes")</param>
        /// <param name="size">Size of data to read (for string/bytes)</param>
        /// <returns>The read value</returns>
        public object ReadProcessMemory(int pid, IntPtr baseAddress, string dataType = "int", int size = 4)
        {
            var PROCESS_ACCESS = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
            IntPtr processHandle = OpenProcess(PROCESS_ACCESS, false, pid);
            if (processHandle == IntPtr.Zero)
            {
                throw new Exception($"Failed to open process. Error code: {Marshal.GetLastWin32Error()}");
            }

            try
            {
                byte[] buffer;
                IntPtr bytesRead;

                // Set buffer size based on data type
                if (dataType == "int")
                {
                    size = 4;  // 32-bit integer
                }

                buffer = new byte[size];

                // Read memory
                if (!ReadProcessMemory(processHandle, baseAddress, buffer, size, out bytesRead))
                {
                    throw new Exception($"Failed to read process memory. Error code: {Marshal.GetLastWin32Error()}");
                }

                // Convert based on data type
                switch (dataType)
                {
                    case "int":
                        return BitConverter.ToInt32(buffer, 0);
                    case "string":
                        // Find null terminator if present
                        int nullPos = Array.IndexOf(buffer, (byte)0);
                        if (nullPos != -1)
                        {
                            return Encoding.UTF8.GetString(buffer, 0, nullPos);
                        }
                        return Encoding.UTF8.GetString(buffer);
                    case "bytes":
                        return buffer;
                    default:
                        throw new ArgumentException($"Unsupported data type: {dataType}");
                }
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }

        /// <summary>
        /// Writes a value to process memory
        /// </summary>
        /// <param name="pid">Process ID</param>
        /// <param name="baseAddress">Memory address to write to</param>
        /// <param name="value">Value to write</param>
        /// <param name="dataType">Type of data to write ("int", "string", "bytes")</param>
        /// <returns>True if successful</returns>
        public bool WriteProcessMemory(int pid, IntPtr baseAddress, object value, string dataType = "int")
        {
            var PROCESS_ACCESS = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
            IntPtr processHandle = OpenProcess(PROCESS_ACCESS, false, pid);
            if (processHandle == IntPtr.Zero)
            {
                throw new Exception($"Failed to open process. Error code: {Marshal.GetLastWin32Error()}");
            }

            try
            {
                byte[] buffer;
                int size;

                // Convert value to bytes based on data type
                switch (dataType)
                {
                    case "int":
                        buffer = BitConverter.GetBytes((int)value);
                        size = 4;
                        break;
                    case "string":
                        string strValue = value.ToString();
                        buffer = Encoding.UTF8.GetBytes(strValue + '\0');  // Null-terminated string
                        size = buffer.Length;
                        break;
                    case "bytes":
                        if (value is byte[])
                        {
                            buffer = (byte[])value;
                        }
                        else if (value is string)
                        {
                            buffer = Encoding.UTF8.GetBytes((string)value);
                        }
                        else
                        {
                            throw new ArgumentException("Value must be byte[] or string for 'bytes' data type");
                        }
                        size = buffer.Length;
                        break;
                    default:
                        throw new ArgumentException($"Unsupported data type: {dataType}");
                }

                // Write to memory
                IntPtr bytesWritten;
                bool result = WriteProcessMemory(processHandle, baseAddress, buffer, size, out bytesWritten);

                if (!result)
                {
                    throw new Exception($"Failed to write process memory. Error code: {Marshal.GetLastWin32Error()}");
                }

                return bytesWritten.ToInt32() == size;
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }
    }

    class Program
    {
        private static void Main(string[] args)
        {
            MemoryScanner scanner = new MemoryScanner();

            var targetName = "StarCraft";
            var processInfo = scanner.ListProcesses(targetName);

            if (!(bool) processInfo["result"])
            {
                Console.WriteLine($"Process '{targetName}' not found.");
                return;
            }
            
            var pid = (int) processInfo["pid"];
            var name = (string) processInfo["name"];

            var targetAddr = scanner.FindProcessAddr(pid);
            if (targetAddr == IntPtr.Zero)
            {
                Console.WriteLine("Target address not found.");
                return;
            }
            
            // Example reading
            var res = scanner.ReadProcessMemory(pid, targetAddr + 4 * 4);
            Console.WriteLine($"Read value: {(int) res}");
            
            // Example writing
            var rand = new Random();
            var randValue = rand.Next(0, 16777215);
            scanner.WriteProcessMemory(pid, targetAddr + 3 * 4, randValue);
            Console.WriteLine($"Write Random value: {randValue}");
            
            
            Console.WriteLine("Press any key to exit...");
        }
    }
}