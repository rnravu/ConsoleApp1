using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace ConsoleApp1
{
    /// <summary>
    /// Provides secure process execution with CWE-78 (OS Command Injection) mitigations.
    /// Security Controls:
    /// - Executable whitelist validation
    /// - Absolute path resolution
    /// - Argument sanitization against injection patterns
    /// - UseShellExecute disabled to prevent shell interpretation
    /// - Path traversal prevention
    /// </summary>
    public class SecureProcessRunner
    {
        // Security: Whitelist of allowed executables - prevents arbitrary code execution
        private static readonly HashSet<string> AllowedExecutables = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ConsoleApp2.exe",
            "python.exe"
        };

        private static readonly string BaseDirectory = AppDomain.CurrentDomain.BaseDirectory;

        // Security: Configurable Python path - avoids PATH environment variable risks
        private static string ConfiguredPythonPath = @"C:\Python39\python.exe";

        /// <summary>
        /// Executes a whitelisted executable with validated arguments.
        /// Security: CWE-78 Mitigation - Validates executable against whitelist and sanitizes all arguments.
        /// </summary>
        /// <param name="fileName">Name of the executable (must be in whitelist)</param>
        /// <param name="args">List of arguments (validated for injection patterns)</param>
        /// <exception cref="ArgumentNullException">Thrown when fileName is null or empty</exception>
        /// <exception cref="ProcessSecurityException">Thrown when security validation fails</exception>
        /// <exception cref="FileNotFoundException">Thrown when executable is not found</exception>
        [SuppressMessage("Security", "CA3076:Insecure XSLT script processing", Justification = "Not applicable - no XSLT processing")]
        public void ExecuteExe(string fileName, List<string> args)
        {
            if (string.IsNullOrWhiteSpace(fileName)) throw new ArgumentNullException(nameof(fileName));

            // Security: Validate fileName against whitelist
            string executableName = Path.GetFileName(fileName);
            if (!AllowedExecutables.Contains(executableName))
            {
                throw new ProcessSecurityException($"Executable '{executableName}' is not in the allowed list.");
            }

            // Security: Use absolute path to prevent path traversal
            string absolutePath = GetSecureExecutablePath(fileName);
            if (!File.Exists(absolutePath))
            {
                throw new FileNotFoundException($"Executable not found: {absolutePath}");
            }

            // Security: Validate all arguments
            if (args != null)
            {
                foreach (var arg in args)
                {
                    ValidateArgument(arg);
                }
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = absolutePath,
                UseShellExecute = false, // Essential to prevent Command Injection
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            // Handle Framework Differences
#if NET5_0_OR_GREATER
            if (args != null)
            {
                foreach (var arg in args)
                    startInfo.ArgumentList.Add(arg);
            }
#else
            // .NET 4.7: Must use the Arguments string. 
            // We wrap each arg in quotes and escape internal quotes.
            if (args != null && args.Count > 0)
            {
                var escapedArgs = args.Select(a => EscapeArgument(a));
                startInfo.Arguments = string.Join(" ", escapedArgs);
            }
#endif

            using (Process process = Process.Start(startInfo))
            {
                if (process == null) return;

                // Optional: Read output to prevent hanging
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                process.WaitForExit();
            }
        }

        /// <summary>
        /// Executes a Python script with validated parameters.
        /// Security: CWE-78 Mitigation - Validates script path, parameter names, and values.
        /// </summary>
        /// <param name="scriptPath">Relative path to Python script (must be within base directory)</param>
        /// <param name="parameters">Dictionary of parameter names and values (all validated)</param>
        /// <exception cref="ArgumentNullException">Thrown when scriptPath is null or empty</exception>
        /// <exception cref="ProcessSecurityException">Thrown when security validation fails</exception>
        [SuppressMessage("Security", "CA3076:Insecure XSLT script processing", Justification = "Not applicable - no XSLT processing")]
        public void ExecutePythonScript(string scriptPath, Dictionary<string, string> parameters)
        {
            // Security: Validate script path
            if (string.IsNullOrWhiteSpace(scriptPath))
                throw new ArgumentNullException(nameof(scriptPath));

            string validatedScriptPath = ValidateScriptPath(scriptPath);

            var args = new List<string> { validatedScriptPath };

            if (parameters != null)
            {
                foreach (var kvp in parameters)
                {
                    // Validate keys to ensure they look like --key or -k
                    if (!Regex.IsMatch(kvp.Key, @"^-{1,2}[a-zA-Z0-9_-]+$"))
                        throw new ArgumentException($"Invalid parameter name: {kvp.Key}");

                    // Security: Validate parameter values
                    ValidateArgument(kvp.Value);

                    args.Add(kvp.Key);   // e.g., "--user"
                    args.Add(kvp.Value); // e.g., "attacker; dir" (will be treated as literal text)
                }
            }

            ExecuteExe("python.exe", args);
        }

        /// <summary>
        /// Validates argument against dangerous characters and command injection patterns.
        /// Security: CWE-78 Mitigation - Blocks shell metacharacters and command invocations.
        /// </summary>
        /// <param name="argument">Argument to validate</param>
        /// <exception cref="ProcessSecurityException">Thrown when argument contains dangerous patterns</exception>
        private void ValidateArgument(string argument)
        {
            if (argument == null) return;

            // Security: Block shell metacharacters that could enable command injection
            var dangerousPatterns = new[]
            {
                "|", "&", ";", "`", "$", "(", ")", "<", ">", "\n", "\r", "^", "%"
            };

            foreach (var pattern in dangerousPatterns)
            {
                if (argument.Contains(pattern))
                {
                    throw new ProcessSecurityException($"Argument contains dangerous character: {pattern}");
                }
            }

            // Security: Prevent shell/command invocation attempts
            if (Regex.IsMatch(argument, @"\b(cmd|powershell|bash|sh|wscript|cscript)\b", RegexOptions.IgnoreCase))
            {
                throw new ProcessSecurityException("Argument contains potentially dangerous command references.");
            }
        }

        /// <summary>
        /// Validates script path to prevent path traversal attacks.
        /// Security: CWE-78 Mitigation - Ensures script is within base directory with allowed extension.
        /// </summary>
        /// <param name="scriptPath">Relative script path to validate</param>
        /// <returns>Validated absolute path to script</returns>
        /// <exception cref="ProcessSecurityException">Thrown when path validation fails</exception>
        /// <exception cref="FileNotFoundException">Thrown when script file is not found</exception>
        private string ValidateScriptPath(string scriptPath)
        {
            // Security: Prevent path traversal (e.g., ../../../windows/system32/malicious.py)
            string fullPath = Path.GetFullPath(Path.Combine(BaseDirectory, scriptPath));

            // Security: Ensure the resolved path is within the base directory
            if (!fullPath.StartsWith(BaseDirectory, StringComparison.OrdinalIgnoreCase))
            {
                throw new ProcessSecurityException("Script path attempts to access files outside the application directory.");
            }

            // Security: Whitelist file extension
            string extension = Path.GetExtension(fullPath);
            if (!string.Equals(extension, ".py", StringComparison.OrdinalIgnoreCase))
            {
                throw new ProcessSecurityException("Only .py script files are allowed.");
            }

            // Security: Verify file exists (prevents timing attacks on file system)
            if (!File.Exists(fullPath))
            {
                throw new FileNotFoundException($"Script file not found: {fullPath}");
            }

            return fullPath;
        }

        /// <summary>
        /// Returns secure absolute path for executable.
        /// Security: CWE-78 Mitigation - Uses absolute paths and avoids PATH environment variable.
        /// </summary>
        /// <param name="fileName">Executable file name</param>
        /// <returns>Validated absolute path to executable</returns>
        private string GetSecureExecutablePath(string fileName)
        {
            string executableName = Path.GetFileName(fileName);

            // Security: Special handling for python.exe - use configured path instead of PATH variable
            if (string.Equals(executableName, "python.exe", StringComparison.OrdinalIgnoreCase))
            {
                return FindPythonExecutable();
            }

            // Security: Default - Look in base directory only
            return Path.GetFullPath(Path.Combine(BaseDirectory, executableName));
        }

        /// <summary>
        /// Finds Python executable in predefined secure locations only.
        /// Security: CWE-78 Mitigation - Does NOT use PATH environment variable to prevent hijacking.
        /// </summary>
        /// <returns>Validated absolute path to Python executable</returns>
        /// <exception cref="FileNotFoundException">Thrown when Python is not found in secure locations</exception>
        private string FindPythonExecutable()
        {
            // Security: Use configured path first
            if (File.Exists(ConfiguredPythonPath))
            {
                return ConfiguredPythonPath;
            }

            // Security: Try only known safe Python installation paths (not PATH variable)
            var securePaths = new[]
            {
                @"C:\Python39\python.exe",
                @"C:\Python38\python.exe",
                @"C:\Python37\python.exe",
                @"C:\Program Files\Python39\python.exe",
                @"C:\Program Files\Python38\python.exe",
                @"C:\Program Files (x86)\Python39\python.exe",
                @"C:\Program Files (x86)\Python38\python.exe"
            };

            foreach (var path in securePaths)
            {
                if (File.Exists(path))
                    return path;
            }

            throw new FileNotFoundException("Python executable not found in secure locations. Configure the path using SetPythonPath method.");
        }

        /// <summary>
        /// Configures the Python executable path for secure execution.
        /// Security: Allows setting Python path without relying on PATH environment variable.
        /// </summary>
        /// <param name="pythonPath">Absolute path to python.exe</param>
        /// <exception cref="ArgumentException">Thrown when path is invalid</exception>
        /// <exception cref="FileNotFoundException">Thrown when file does not exist</exception>
        public static void SetPythonPath(string pythonPath)
        {
            if (string.IsNullOrWhiteSpace(pythonPath))
                throw new ArgumentException("Python path cannot be null or empty.", nameof(pythonPath));

            if (!File.Exists(pythonPath))
                throw new FileNotFoundException($"Python executable not found at: {pythonPath}");

            if (!pythonPath.EndsWith("python.exe", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Path must point to python.exe", nameof(pythonPath));

            ConfiguredPythonPath = Path.GetFullPath(pythonPath);
        }

        /// <summary>
        /// Properly escapes arguments for Windows command line.
        /// Security: CWE-78 Mitigation - Prevents argument injection through proper escaping.
        /// </summary>
        /// <param name="arg">Argument to escape</param>
        /// <returns>Escaped argument safe for command line</returns>
        private string EscapeArgument(string arg)
        {
            if (string.IsNullOrEmpty(arg))
                return "\"\"";

            // Security: Escape backslashes and quotes according to Windows command line rules
            // This prevents breakout from quoted strings
            string escaped = arg.Replace("\\", "\\\\").Replace("\"", "\\\"");
            return $"\"{escaped}\"";
        }
    }

    /// <summary>
    /// Exception thrown when process execution security validation fails.
    /// Used to distinguish security violations from other exceptions.
    /// </summary>
    public class ProcessSecurityException : Exception
    {
        public ProcessSecurityException(string message) : base(message) { }

        public ProcessSecurityException(string message, Exception innerException) : base(message, innerException) { }
    }
}
