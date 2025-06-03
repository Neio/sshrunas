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

            string raw = Environment.CommandLine;
            string exePath = Environment.GetCommandLineArgs()[0];
            string requestedCommand = raw.Substring(exePath.Length).TrimStart();

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

            CreateUserIfNecessary(username, password);

            await SshRun("localhost", username, password, requestedCommand);



        }

        private static void CreateUserIfNecessary(string username, string password)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Console.WriteLine("Skipping user creation on non-Windows platform.");
                return;
            }
            using (PrincipalContext context = new PrincipalContext(ContextType.Machine))
            {
                // Search for the user in the local machine context
                UserPrincipal user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);
                if (user == null)
                {
                    user = new UserPrincipal(context);
                    user.SamAccountName = username;
                    user.SetPassword(password);
                    user.Enabled = true;

                    try
                    {
                        user.Save();
                        Console.WriteLine("User is created successfully.");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to create user: {ex}");
                    }

                    GroupPrincipal adminGroup = GroupPrincipal.FindByIdentity(context, "Administrators");

                    if (adminGroup != null)
                    {
                        adminGroup.Members.Add(user);
                        adminGroup.Save();

                        Console.WriteLine("User is added to the Administrators group.");
                    }
                    else
                    {
                        Console.WriteLine("Failed to add user to Administrators group.");
                    }

                }
            }
        }

        private static async Task SshRun(string host, string user, string password, string command)
        {
            var lines = new List<string>
            {
                "@echo off"
            };


            var envVars = Environment.GetEnvironmentVariables(EnvironmentVariableTarget.Process);
            var systemEnvVars = Environment.GetEnvironmentVariables(EnvironmentVariableTarget.Machine);
            var userEnvVars = Environment.GetEnvironmentVariables(EnvironmentVariableTarget.User);
            var finalList = new Dictionary<string, string>(); 
            var builtInVars = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                 "ALLUSERSPROFILE", "APPDATA", "CommonProgramFiles", "CommonProgramFiles(x86)",
                "CommonProgramW6432", "COMPUTERNAME", "ComSpec", "HOMEDRIVE", "HOMEPATH",
                "LOCALAPPDATA", "NUMBER_OF_PROCESSORS", "OS", "PATH", "PATHEXT",
                "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "ProgramData",
                "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "PROMPT",
                "PUBLIC", "SESSIONNAME", "SystemDrive", "SystemRoot", "TEMP", "TMP",
                "USERDOMAIN", "USERNAME", "USERPROFILE", "WINDIR", "LOGONSERVER",
                "USERDOMAIN_ROAMINGPROFILE", "USERDNSDOMAIN", "CLIENTNAME"
            };
            foreach (DictionaryEntry item in envVars)
            {
                if (builtInVars.Contains(item.Key) || systemEnvVars.Contains(item.Key) || userEnvVars.Contains(item.Key))
                {
                    // Skip if the variable is already set in system or user scope
                    continue;
                }
                Console.WriteLine("Found Process Environment Variable: {0}", item.Key);
                string value = item.Value?.ToString() ?? String.Empty;
                value = value.Replace("^", "^^")
                         .Replace("&", "^&")
                         .Replace("|", "^|")
                         .Replace("<", "^<")
                         .Replace(">", "^>")
                         .Replace("%", "%%")
                .Replace("\"", "\\\"");

                lines.Add($"set \"{item.Key}={value}\"");
            }
            lines.Add($"CD \"{Environment.CurrentDirectory}\"");
            lines.Add(command);

            var tempPath = Path.GetTempPath();
            string tempBat = Path.Combine(tempPath, $"{Guid.NewGuid()}.bat");
            Directory.CreateDirectory(tempPath);
            File.WriteAllLines(tempBat, lines.ToArray());

            try
            {
                var actualCmd = $"C:\\Windows\\System32\\cmd.exe /c \"{tempBat}\"";
                using (var client = new SshClient(host, user, password))
                {
                    client.Connect();
                    var cmd = client.CreateCommand(actualCmd);
                    var cmdExec = cmd.ExecuteAsync();
                    using (var stdout = new StreamReader(cmd.OutputStream))
                    {

                        Task stdoutTask = Task.Run(async () =>
                        {
                            while (!stdout.EndOfStream)
                            {
                                var line = await stdout.ReadLineAsync();
                                Console.WriteLine(line);
                            }
                        });

                        // Read stderr asynchronously
                        using (var stderr = new StreamReader(cmd.ExtendedOutputStream))
                        {
                            Task stderrTask = Task.Run(async () =>
                            {
                                while (!stderr.EndOfStream)
                                {
                                    var line = await stderr.ReadLineAsync();
                                    Console.Error.WriteLine(line);
                                }
                            });

                            await Task.WhenAll(stdoutTask, stderrTask, cmdExec);
                        }
                    }

                }
            }
            finally
            {
                File.Delete(tempBat);
            }
        }


    }

}
