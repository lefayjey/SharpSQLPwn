using System;
using System.Data.SqlClient;

namespace SharpSQLPwn.Utilities
{
    public class Authentication
    {
        public static SqlConnection Authenticate(String conString)
        {
            SqlConnection con = new SqlConnection(conString); 
            try
            {
                con.Open();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[+] Authentication Success!");
                Console.ResetColor();
                return con;
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[-] Error: Connection or Authentication Failed");
                Console.ResetColor();
                Environment.Exit(0);
                return null;
            }
        }

        //Local authentication
        public static SqlConnection LocalAuthenticate(String sqlServer, String database, String user, String pass)
        {
            Console.ForegroundColor = ConsoleColor.Cyan; 
            Console.WriteLine("[*] Local Authentication Selected");
            Console.ResetColor(); 
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security=false; user id=" + user + "; password=" + pass + ";";

            return Authenticate(conString);
        } 

        //Windows authentication
        public static SqlConnection WindowsAuthenticate(String sqlServer, String database)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[*] Windows Authentication Selected");
            Console.ResetColor();
            string user = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";

            return Authenticate(conString);
        }

        //Domain authentication to Azure based MSSQL databases
        public static SqlConnection AzureAuthenticate(String sqlServer, String database, String domain, String user, String pass)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[*] Azure Authentication Selected");
            Console.ResetColor();
            user = user + "@" + domain;
            String conString = "Server = " + sqlServer + "; Database = " + database + ";  Authentication=Active Directory Password; TrustServerCertificate=True; user id=" + user + "; password=" + pass + ";";

            return Authenticate(conString);
        }
    }
}
