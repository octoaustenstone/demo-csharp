using System;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace VulnerableApp
{
    public class Program
    {
        // Hardcoded credentials (CWE-798)
        private static string dbUser = "admin";
        private static string dbPass = "password123";

        public static void Main(string[] args)
        {
            // SQL Injection (CWE-89)
            Console.WriteLine("Enter username:");
            string username = Console.ReadLine();
            string query = "SELECT * FROM Users WHERE Username = '" + username + "';";
            SqlConnection connection = new SqlConnection("Data Source=localhost;Initial Catalog=MyDB;User ID=" + dbUser + ";Password=" + dbPass);
            SqlCommand command = new SqlCommand(query, connection);
            connection.Open();
            SqlDataReader reader = command.ExecuteReader();

            // XSS vulnerability (CWE-79)
            Console.WriteLine("Enter your name for display:");
            string displayName = Console.ReadLine();
            Console.WriteLine("Hello, " + displayName); // Displaying unsanitized user input

            // Insecure file handling (CWE-22)
            Console.WriteLine("Enter file path:");
            string filePath = Console.ReadLine();
            using (StreamReader sr = new StreamReader(filePath))
            {
                Console.WriteLine(sr.ReadToEnd());
            }

            // Weak encryption (CWE-327)
            Console.WriteLine("Enter a message to encrypt:");
            string message = Console.ReadLine();
            byte[] encryptedMessage = WeakEncrypt(message);
            Console.WriteLine("Encrypted message: " + Convert.ToBase64String(encryptedMessage));

            // Insufficient input validation (CWE-20)
            Console.WriteLine("Enter your age:");
            int age = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine("You are " + age + " years old.");
        }

        // Weak encryption using DES (CWE-327)
        public static byte[] WeakEncrypt(string plainText)
        {
            byte[] key = Encoding.UTF8.GetBytes("12345678"); // DES uses an 8-byte key (weak)
            using (DES des = DES.Create())
            {
                des.Key = key;
                des.IV = key;
                byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(inputBytes, 0, inputBytes.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }
    }
}


