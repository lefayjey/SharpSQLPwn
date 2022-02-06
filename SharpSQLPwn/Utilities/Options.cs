using System;
using System.Collections.Generic;

namespace SharpSQLPwn.Utilities
{
    class Options
    {
        //default values off all arguments
        public class Arguments
        {
            public string sqlServer = "LocalMachine";
            public string database = "master";
            public string modules = "R";
            public string impersonatedUser = "sa";
            public int cmdExecTechnique = 1;
            public string cmdExecCommand = null;
            public string attackerIP = null;
            public string linkedSQLServer = null;
            public bool interactive = false;
            public bool help = false;
        }
        public static Dictionary<string, string[]> ParseArgs(string[] args)
        {
            Dictionary<string, string[]> result = new Dictionary<string, string[]>();
            //these boolean variables aren't passed w/ values. If passed, they are "true"
            string[] booleans = new string[] { "/interactive", "/help" };
            var argList = new List<string>();
            foreach (string arg in args)
            {
                //delimit key/value of arguments by ":"
                string[] parts = arg.Split(":".ToCharArray(), 2);
                argList.Add(parts[0]);

                //boolean variables
                if (parts.Length == 1)
                {
                    result[parts[0]] = new string[] { "true" };
                }
                if (parts.Length == 2)
                {
                    result[parts[0]] = new string[] { parts[1] };
                }
            }
            return result;
        }
        public static Arguments ArgumentValues(Dictionary<string, string[]> parsedArgs)
        {
            Arguments arguments = new Arguments();
            if (parsedArgs.ContainsKey("/target"))
            {
                arguments.sqlServer = parsedArgs["/target"][0];
            }
            if (parsedArgs.ContainsKey("/db"))
            {
                arguments.database = parsedArgs["/db"][0];
            }
            if (parsedArgs.ContainsKey("/modules"))
            {
                arguments.modules = parsedArgs["/modules"][0];
            }
            if (parsedArgs.ContainsKey("/impuser"))
            {
                arguments.impersonatedUser = parsedArgs["/impuser"][0];
            }
            if (parsedArgs.ContainsKey("/cmdtech"))
            {
                arguments.cmdExecTechnique = Convert.ToInt32(parsedArgs["/cmdtech"][0]);
            }
            if (parsedArgs.ContainsKey("/cmd"))
            {
                arguments.cmdExecCommand = parsedArgs["/cmd"][0];
            }
            if (parsedArgs.ContainsKey("/localIP"))
            {
                arguments.attackerIP = parsedArgs["/localIP"][0];
            }
            if (parsedArgs.ContainsKey("/linkedsql"))
            {
                arguments.linkedSQLServer = parsedArgs["/linkedsql"][0];
            }
            if (parsedArgs.ContainsKey("/interactive"))
            {
                arguments.interactive = Convert.ToBoolean(parsedArgs["/interactive"][0]);
            }
            if (parsedArgs.ContainsKey("/help"))
            {
                ShowBanner();
                Usage();
                Environment.Exit(0);
            }
            return arguments;
        }

        public static void ShowBanner()
        {
            Console.WriteLine();
            Console.WriteLine(@"   _____ __                    _____ ____    __    ____     ");
            Console.WriteLine(@"  / ___// /_  ____ __________ / ___// __ \  / /   / __ \_      ______ ");
            Console.WriteLine(@"  \__ \/ __ \/ __ `/ ___/ __ \\__ \/ / / / / /   / /_/ / | /| / / __ \");
            Console.WriteLine(@" ___/ / / / / /_/ / /  / /_/ /__/ / /_/ / / /___/ ____/| |/ |/ / / / /");
            Console.WriteLine(@"/____/_/ /_/\__,_/_/  / .___/____/\___\_\/_____/_/     |__/|__/_/ /_/ ");
            Console.WriteLine(@"                     /_/                                              ");
            Console.WriteLine(@"   https://github.com/lefayjey/SharpSQLPwn");
            Console.WriteLine(@"   Version:  1.2.1");
            Console.WriteLine(@"   Author:  lefayjey");
            Console.WriteLine();
        }
        public static void Usage()
        {
            string usageString = @"
Usage:
    - Basic recon:
        SharpSQLPwn.exe /modules:R /target:SQLServer [/db:DatabaseName]
    - Impersonation:
        SharpSQLPwn.exe /modules:I /target:SQLServer [/db:DatabaseName] /impuser:ImpersonatedUser
    - Command Execution (Optional: add module I to impersonate user before command execution):
        SharpSQLPwn.exe /modules:C[I] /target:SQLServer [/db:DatabaseName] /cmdtech:CmdExecTechnique /cmd:Command [/impuser:ImpersonatedUser]
    - UNC Path Injection (Optional: add module I to impersonate user before path injection):
        SharpSQLPwn.exe /modules:U[I] /target:SQLServer [/db:DatabaseName] /localIP:AttackerIP [/impuser:ImpersonatedUser]
    - Linked Servers (Optional: add module C to execute command on linked SQL server, and module U to perform path injection:
        SharpSQLPwn.exe /modules:L /target:SQLServer [/db:DatabaseName] /linkedsql:LinkedSQLServer [/cmdtech:CmdExecTechnique] [/cmd:Command] [/localIP:AttackerIP]
    - All modules:
        SharpSQLPwn.exe /modules:RICUL /target:SQLServer [/db:DatabaseName] /impuser:ImpersonatedUser /cmdtech:CmdExecTechnique /cmd:Command /localIPAttackerIP /linkedsqlLinkedSQLServer
    - Interactive mode:
        SharpSQLPwn.exe /interactive


Arguments:
    /target      - Target SQL server hostname or IP (default: LocalMachine)
    /db          - Database name of target SQL server (default: master)
    /modules     - Specify modules to run (default: R). Choose multiple modules by concatening letters, example: /modules:RI
            R=Recon
            I=Impersonation
            C=CommandExecution
            U=UNCPathInjection
            L=LinkedSQL
    /impuser     - Name of user to impersonate (default: sa)
    /cmdtech     - Specify execution technique (default: 1)
            1=xp_cmdshell
            2=sp_OACreate
            3=dll_assembly
    /cmd         - Command to execute
    /localIP     - Local IP of the attacker (used for responder or ntlmrelay or Inveigh)
    /linkedsql   - Target linked SQL Server Hostname or IP
    /interactive - Run Interactive version
    /help        - Show this help message
";

            Console.WriteLine(usageString);
        }
    }
}
