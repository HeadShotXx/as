using System;
using System.Linq;
using System.Text;

namespace BrowserExtractorCS
{
    public static class Tests
    {
        public static void Run()
        {
            Console.WriteLine("Running Logic Verification Tests...");
            TestFindSubsequence();
            Console.WriteLine("Tests completed successfully!");
        }

        static void TestFindSubsequence()
        {
            byte[] haystack = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            byte[] needle = { 3, 4, 5 };
            int pos = Utils.FindSubsequence(haystack, needle);
            if (pos != 3) throw new Exception($"FindSubsequence failed: expected 3, got {pos}");

            byte[] needle2 = { 8, 9, 10 };
            pos = Utils.FindSubsequence(haystack, needle2);
            if (pos != -1) throw new Exception($"FindSubsequence failed: expected -1, got {pos}");

            Console.WriteLine("TestFindSubsequence passed.");
        }
    }
}
