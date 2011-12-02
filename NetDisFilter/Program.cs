using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetDisFilter
{
    class Program
    {
        const string FILE = @"C:\Users\AustinWise\Documents\Visual Studio 2010\Projects\ConsoleApplication5\ConsoleApplication5\bin\Debug\ConsoleApplication5.exe";
        static void Main(string[] args)
        {
            var pe = new PeHeaderReader(FILE);
            var head = new CorReader(pe);
            Console.WriteLine(head);
        }
    }
}
