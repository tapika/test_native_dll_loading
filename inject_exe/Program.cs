using PeNet;
using PeNet.Header.Pe;
using System;
using System.Linq;
using System.IO;

namespace inject_exe
{
    class Program
    {
        static void Main(string[] args)
        {
            var exeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location);
            var dir = Path.GetFullPath(Path.Combine(exeDir, @"..\..\..\bin"));

            string exePath = Path.Combine(dir, "test_dll_load.exe");
            string dll2Inject = Path.Combine(dir, "ext", "mydll.dll");
            byte[] dll = File.ReadAllBytes(dll2Inject);
            //byte[] exe = File.ReadAllBytes(exePath);
            //int filler = 65536 - (exe.Length % 65536);
            //byte[] newExe = new byte[exe.Length + filler + dll.Length];
            //Array.Copy(exe, newExe, exe.Length);
            //int dllOffet = exe.Length + filler;
            //Array.Copy(dll, 0, newExe, dllOffet, dll.Length);

            //Console.WriteLine($"Injecting mydll.dll into test_dll_load.exe at offset 0x{dllOffet.ToString("X")}");       
            //File.WriteAllBytes(Path.Combine(dir, "test_dll_load.exe"), newExe);

            var peFile = new PeFile(exePath);

            string sectionName = ".mydll";  //max 8 bytes

            peFile.AddSection(sectionName, dll.Length, (ScnCharacteristicsType)0x40000040);
            //peFile.AddSection(sectionName, dll.Length, (ScnCharacteristicsType)0x60000020);
            ImageSectionHeader ish = peFile.ImageSectionHeaders.First(x => x.Name == sectionName);
            peFile.RawFile.WriteBytes(ish.PointerToRawData, dll);

            Console.WriteLine($"Injecting mydll.dll into test_dll_load.exe at offset 0x{ish.VirtualAddress.ToString("X")}" +
                $" (File offset: 0x{ish.PointerToRawData.ToString("X")})");

            // Save the changed binary to disk
            File.WriteAllBytes(exePath, peFile.RawFile.ToArray());
        }
    }
}
