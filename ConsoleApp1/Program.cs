using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Enter a message to send to ConsoleApp2:");
            string userInput = Console.ReadLine();

            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "ConsoleApp2.exe";
            startInfo.Arguments = userInput;
            startInfo.UseShellExecute = false;

            Process process = Process.Start(startInfo);
            process.WaitForExit();
        }
    }
}
