using StarVault;

enum Status
{
    FIND_STARCRAFT_PROCESS,
    WAIT_FOR_GAME,
    PLAYING_STAR_VAULT_MAP,
}

enum PlayingStatus
{
    WAITING,
    SAVE_DATA,
    LOAD_DATA,
    TEST_STEP
}

class Program
{
    private static void Main(string[] args)
    {
        var scanner = new MemoryScanner();
        var targetName = "StarCraft";
        var STATUS = Status.FIND_STARCRAFT_PROCESS;
        var PLAYING_STATUS = PlayingStatus.WAITING;
        var FAIL_COUNT = 0;
        var starcraftPid = -1;

        Thread worker = new Thread(() =>
        {
            var starVaultAddr = IntPtr.Zero;
            while (true)
            {
                if (STATUS == Status.FIND_STARCRAFT_PROCESS)
                {
                    Console.WriteLine($"{Status.FIND_STARCRAFT_PROCESS.ToString()}");
                    var processInfo = scanner.ListProcesses(targetName);

                    if (!(bool) processInfo["result"])
                    {
                        // Console.WriteLine($"Process '{targetName}' not found.");
                        Thread.Sleep(1000);
                        continue;
                    }

                    starcraftPid = (int)processInfo["pid"];
                    // (string) processInfo["name"];
                    STATUS = Status.WAIT_FOR_GAME;
                }
                else if (STATUS == Status.WAIT_FOR_GAME)
                {
                    Console.WriteLine($"{Status.WAIT_FOR_GAME.ToString()}");
                    starVaultAddr = scanner.FindProcessAddr(starcraftPid);
                    if (starVaultAddr == IntPtr.Zero)
                    {
                        // Console.WriteLine("Target address not found.");
                        Thread.Sleep(1000);
                        FAIL_COUNT += 1;
                        if (FAIL_COUNT >= 2)
                        {
                            FAIL_COUNT = 0;
                            var processInfo = scanner.ListProcesses(targetName);
                            if (!(bool)processInfo["result"])
                            {
                                STATUS = Status.FIND_STARCRAFT_PROCESS;
                            }
                        }
                        continue;
                    }
                    
                    Console.WriteLine($"Found starVaultAddr: {starVaultAddr}");
                    STATUS = Status.PLAYING_STAR_VAULT_MAP;
                    PLAYING_STATUS = PlayingStatus.TEST_STEP;
                }
                else if (STATUS == Status.PLAYING_STAR_VAULT_MAP)
                {
                    if (PLAYING_STATUS == PlayingStatus.WAITING)
                    {
                        Console.WriteLine("WAITING...");
                        if (!scanner.CheckingStarVaultMap(starcraftPid, starVaultAddr))
                        {
                            STATUS = Status.WAIT_FOR_GAME;
                            continue;
                        }
                        Thread.Sleep(1000);
                    }
                    else if (PLAYING_STATUS == PlayingStatus.TEST_STEP)
                    {
                        Console.WriteLine("TEST_STEP...");

                        // Example reading
                        var res = scanner.ReadProcessMemory(starcraftPid, starVaultAddr + 4 * 4);
                        Console.WriteLine($"Read value: {(int)res}");

                        // Example writing
                        var rand = new Random();
                        var randValue = rand.Next(0, 16777215);
                        scanner.WriteProcessMemory(starcraftPid, starVaultAddr + 3 * 4, randValue);
                        Console.WriteLine($"Write Random value: {randValue}");

                        PLAYING_STATUS = PlayingStatus.WAITING;
                    }
                }
            }
        });
        
        worker.IsBackground = true; // 메인 스레드가 끝나면 자동 종료
        worker.Start();

        Console.ReadLine();
    }
}
