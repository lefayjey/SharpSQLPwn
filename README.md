# SharpSQLPwn


C# tool to identify and exploit weaknesses with MSSQL instances in Active Directory environments

```
.\SharpSQLPwn.exe --help
   _____ __                    _____ ____    __    ____               
  / ___// /_  ____ __________ / ___// __ \  / /   / __ \_      ______ 
  \__ \/ __ \/ __ `/ ___/ __ \\__ \/ / / / / /   / /_/ / | /| / / __ \
 ___/ / / / / /_/ / /  / /_/ /__/ / /_/ / / /___/ ____/| |/ |/ / / / /
/____/_/ /_/\__,_/_/  / .___/____/\___\_\/_____/_/     |__/|__/_/ /_/ 
                     /_/                                              

SharpSQLPwn 1.0.0.0
Copyright ©  2022

  -t, --SQLServer           (Default: LocalMachine) Target SQL Server Hostname or IP.

  -d, --Database            (Default: master) Database Name of target SQL server.

  -M, --Modules             (Default: R) Available Modules: R=Recon, I=Impersonation, C=CommandExecution,
                            U=UNCPathInjection, L=LinkedSQL

  -U, --ImpersonatedUser    (Default: sa) Name of user to impersonate.

  -C, --CmdExecTechnique    (Default: 1) Available Command Execution Techniques: 1=xp_cmdshell, 2=sp_OACreate,
                            3=dll_assembly

  -x, --CmdExecCommand      (Default: ) Command to be executed.

  -I, --AttackerIP          (Default: ) Local IP of the attacker (used for responder or ntlmrelay or Inveigh).

  -L, --LinkedSQLServer     Target linked SQL Server Hostname or IP.

  -i, --Interactive         Run Interactive version.

  -E, --Example             Display example commands.

  --help                    Display this help screen.

  --version                 Display version information.
  ```