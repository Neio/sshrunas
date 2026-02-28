using Renci.SshNet;
using Renci.SshNet.Common;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.IO;
using System.Linq.Expressions;
using System.Collections;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Renci.SshNet.Security;

namespace SshRunas
{
    static class Program
    {

        static async Task Main(string[] args)
        {
            string commandLine = Environment.CommandLine;
            bool inQuotes = false;
            int i = 0;
            for (; i < commandLine.Length; i++)
            {
                if (commandLine[i] == '"') inQuotes = !inQuotes;
                if (commandLine[i] == ' ' && !inQuotes) break;
            }
            string requestedCommand = commandLine.Substring(i).Trim();

            if (string.IsNullOrEmpty(requestedCommand))
            {
                Console.WriteLine("Usage: sshrunas <command> <arguments>");
                return;
            }

            Console.WriteLine("Executing command: " + requestedCommand);

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Console.Error.WriteLine("This program is only supported on Windows.");
                System.Environment.ExitCode = 1;
                return;
            }

            var username = Environment.GetEnvironmentVariable("SSH_RUNNER_USER");
            var password = Environment.GetEnvironmentVariable("SSH_RUNNER_PWD");

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                Console.Error.WriteLine("User name or password is not specified in the environment SSH_RUNNER_USER and SSH_RUNNER_PWD.");
                System.Environment.ExitCode = 2;
                return;
            }

            if (!CreateUserIfNecessary(username, password))
            {
                System.Environment.ExitCode = 3;
                return;
            }

            await SshRun("localhost", username, password, requestedCommand);
        }

        private static bool CreateUserIfNecessary(string username, string password)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Console.WriteLine("Skipping user creation on non-Windows platform.");
                return true;
            }

            try
            {
                using (PrincipalContext context = new PrincipalContext(ContextType.Machine))
                {
                    UserPrincipal user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);
                    if (user == null)
                    {
                        user = new UserPrincipal(context);
                        user.SamAccountName = username;
                        user.SetPassword(password);
                        user.Enabled = true;
                        user.Save();
                        Console.WriteLine("User is created successfully.");

                        // Use SID for Administrators group (S-1-5-32-544) to support non-English Windows
                        GroupPrincipal adminGroup = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, "S-1-5-32-544");

                        if (adminGroup != null)
                        {
                            adminGroup.Members.Add(user);
                            adminGroup.Save();
                            Console.WriteLine("User is added to the Administrators group.");
                        }
                        else
                        {
                            Console.Error.WriteLine("Failed to find Administrators group (S-1-5-32-544).");
                            return false;
                        }
                    }
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to create or configure user: {ex.Message}");
                return false;
            }
        }

        private static async Task SshRun(string host, string user, string password, string command)
        {
            var lines = new List<string> { "@echo off" };

            var envVars = Environment.GetEnvironmentVariables(EnvironmentVariableTarget.Process);
            var builtInVars = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "ALLUSERSPROFILE", "APPDATA", "CommonProgramFiles", "CommonProgramFiles(x86)",
                "CommonProgramW6432", "COMPUTERNAME", "ComSpec", "HOMEDRIVE", "HOMEPATH",
                "LOCALAPPDATA", "NUMBER_OF_PROCESSORS", "OS", "PATHEXT",
                "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "ProgramData",
                "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "PROMPT",
                "PUBLIC", "SESSIONNAME", "SystemDrive", "SystemRoot", "TEMP", "TMP",
                "USERDOMAIN", "USERNAME", "USERPROFILE", "WINDIR", "LOGONSERVER",
                "USERDOMAIN_ROAMINGPROFILE", "USERDNSDOMAIN", "CLIENTNAME"
            };

            foreach (DictionaryEntry item in envVars)
            {
                string key = item.Key.ToString()!.Replace("%", "%%");
                if (builtInVars.Contains(key)) continue;

                string value = item.Value?.ToString() ?? string.Empty;
                // Only escape % for batch files. ^ & | < > are safe inside set "key=value"
                value = value.Replace("%", "%%");

                lines.Add($"set \"{key}={value}\"");
            }

            lines.Add($"CD /d \"{Environment.CurrentDirectory.Replace("%", "%%")}\"");
            lines.Add(command.Replace("%", "%%"));

            var tempPath = Path.GetTempPath();
            string tempBat = Path.Combine(tempPath, $"{Guid.NewGuid()}.bat");
            
            try
            {
                File.WriteAllLines(tempBat, lines.ToArray());
                var comSpec = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe";
                var actualCmd = $"\"{comSpec}\" /c \"{tempBat}\"";

                using (var client = new SshClient(host, user, password))
                {
                    client.Connect();
                    var cmd = client.CreateCommand(actualCmd);
                    
                    // Use a simple synchronous execution for stdout/stderr if possible, 
                    // or properly handle the async streams.
                    var result = cmd.BeginExecute();
                    
                    var stdoutTask = Task.Run(() => {
                        using var reader = new StreamReader(cmd.OutputStream);
                        while (!reader.EndOfStream) Console.WriteLine(reader.ReadLine());
                    });

                    var stderrTask = Task.Run(() => {
                        using var reader = new StreamReader(cmd.ExtendedOutputStream);
                        while (!reader.EndOfStream) Console.Error.WriteLine(reader.ReadLine());
                    });

                    await Task.WhenAll(stdoutTask, stderrTask, Task.Factory.FromAsync(result, cmd.EndExecute));
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"SSH execution failed: {ex.Message}");
            }
            finally
            {
                if (File.Exists(tempBat)) File.Delete(tempBat);
            }
        }


    }

}
