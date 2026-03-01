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
            
            // Robust command-line parsing to skip the current executable.
            // Environment.GetCommandLineArgs() provides correctly parsed arguments.
            // The first argument is the path to the executable.
            string[] commandLineArgs = Environment.GetCommandLineArgs();
            string executablePath = commandLineArgs[0];
            
            int i = 0;
            bool inQuotes = false;
            // Find the end of the executable path in the raw command line
            for (; i < commandLine.Length; i++)
            {
                if (commandLine[i] == '"') inQuotes = !inQuotes;
                if (commandLine[i] == ' ' && !inQuotes)
                {
                    // Check if we matched the executable path
                    string candidate = commandLine.Substring(0, i).Trim('\"');
                    if (string.Equals(candidate, executablePath, StringComparison.OrdinalIgnoreCase))
                        break;
                }
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
                    }

                    // Always ensure user is in the Administrators group (S-1-5-32-544)
                    GroupPrincipal adminGroup = GroupPrincipal.FindByIdentity(context, IdentityType.Sid, "S-1-5-32-544");

                    if (adminGroup != null)
                    {
                        if (!adminGroup.Members.Contains(user))
                        {
                            adminGroup.Members.Add(user);
                            adminGroup.Save();
                            Console.WriteLine("User is added to the Administrators group.");
                        }
                    }
                    else
                    {
                        Console.Error.WriteLine("Failed to find Administrators group (S-1-5-32-544).");
                        return false;
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
                "LOCALAPPDATA", "NUMBER_OF_PROCESSORS", "OS", "PATH", "PATHEXT",
                "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "ProgramData",
                "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "PROMPT",
                "PUBLIC", "SESSIONNAME", "SystemDrive", "SystemRoot", "TEMP", "TMP",
                "USERDOMAIN", "USERNAME", "USERPROFILE", "WINDIR", "LOGONSERVER",
                "USERDOMAIN_ROAMINGPROFILE", "USERDNSDOMAIN", "CLIENTNAME",
                "SSH_RUNNER_USER", "SSH_RUNNER_PWD" // Exclude sensitive credentials
            };

            foreach (DictionaryEntry item in envVars)
            {
                string originalKey = item.Key.ToString()!;
                if (builtInVars.Contains(originalKey)) continue;

                string value = item.Value?.ToString() ?? string.Empty;

                // Use `set "key=value"` syntax for robustness, as it correctly handles spaces.
                // Inside quotes, only '%' needs to be escaped. Quotes in values/names are not
                // supported by `set` and can be removed to prevent issues.
                string escapedKey = originalKey.Replace("\"", "");
                string escapedValue = value.Replace("%", "%%").Replace("\"", "");

                lines.Add($"set \"{escapedKey}={escapedValue}\"");
            }

            lines.Add($"CD /d \"{Environment.CurrentDirectory.Replace("%", "%%").Replace("\"", "")}\"");
            lines.Add(command.Replace("%", "%%"));

            var tempPath = Path.GetTempPath();
            string tempBat = Path.Combine(tempPath, $"{Guid.NewGuid()}.bat");
            
            try
            {
                // Create the file with restrictive permissions from the start on Windows.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var fileSecurity = new FileSecurity();
                    fileSecurity.SetAccessRuleProtection(true, false);
                    fileSecurity.AddAccessRule(new FileSystemAccessRule(
                        WindowsIdentity.GetCurrent().User!,
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));
                    
                    var fileInfo = new FileInfo(tempBat);
                    using (fileInfo.Create()) { }
                    fileInfo.SetAccessControl(fileSecurity);
                }

                File.WriteAllLines(tempBat, lines.ToArray());
                
                // Use Environment.SystemDirectory to find cmd.exe reliably
                var comSpec = Path.Combine(Environment.SystemDirectory, "cmd.exe");
                var actualCmd = $"\"{comSpec}\" /c \"{tempBat.Replace("\"", "")}\"";

                using (var client = new SshClient(host, user, password))
                {
                    client.Connect();
                    using (var cmd = client.CreateCommand(actualCmd))
                    {
                        var result = cmd.BeginExecute();

                        // Use CopyToAsync for efficient, non-blocking stream handling
                        var stdoutTask = cmd.OutputStream.CopyToAsync(Console.OpenStandardOutput());
                        var stderrTask = cmd.ExtendedOutputStream.CopyToAsync(Console.OpenStandardError());

                        await Task.WhenAll(stdoutTask, stderrTask, Task.Factory.FromAsync(result, cmd.EndExecute));
                    }
                }
            }
            catch (IOException ex)
            {
                Console.Error.WriteLine($"File operation failed: {ex.Message}");
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
