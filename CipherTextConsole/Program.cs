using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
class TripleDESSample
{
    public static void Main()
    {
        
        string Test;

        //Test = EncryptData("5D6EE6948C387ACEE56E02CBC8433194", "1F85A94176F1D46873C605BDC5D8F5F04D9C5C9C7A067B75");

        //Test = DecryptData("/DyLObsnTgbQxsMgldp9FB3MCFXnQqxBn9pdc1bWuijF+2EbFZY9Mv5zTnDqSw8P9p4XcabfsHw=", "5D6EE6948C387ACEE56E02CBC8433194");

        Console.WriteLine("Enter text that needs to be encrypted..");

        string data = Console.ReadLine();
        Apply3DES(data);
        Console.ReadLine();
    }
    static string EncryptData(string encryptionKey, string data)
    {
        TripleDES des = TripleDES.Create();
        des.Mode = CipherMode.ECB;
        des.Padding = PaddingMode.PKCS7;
        byte[] bytesInUni = HexToBytes(encryptionKey);
        //des.Key = Encoding.UTF8.GetBytes(bytesInUni);
        des.Key = bytesInUni;

        ICryptoTransform cryptoTransform = des.CreateEncryptor();
        byte[] dataBytes = Encoding.UTF8.GetBytes(data);
        byte[] encryptedDataBytes = cryptoTransform.TransformFinalBlock(dataBytes, 0, dataBytes.Length);

        des.Dispose();

        return Convert.ToBase64String(encryptedDataBytes);
    }

    static string DecryptData(string encryptedData, string encryptionKey)
    {
        TripleDES des = TripleDES.Create();
        byte[] bytesInUni = HexToBytes(encryptionKey);
        des.Key = bytesInUni;
        des.Mode = CipherMode.ECB;
        
        des.Padding = PaddingMode.PKCS7;

        ICryptoTransform cryptoTransform = des.CreateDecryptor();
        byte[] EncryptDataBytes = Convert.FromBase64String(encryptedData);
        byte[] plainDataBytes = cryptoTransform.TransformFinalBlock(EncryptDataBytes, 0, EncryptDataBytes.Length);

        des.Dispose();

        return Encoding.UTF8.GetString(plainDataBytes);
    }

    static void Apply3DES(string raw)
    {
        try
        {
            // Create 3DES that generates a new key and initialization vector (IV).  
            // Same key must be used in encryption and decryption  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                //tdes.GenerateIV();
                //tdes.GenerateKey();

                //Console.WriteLine($"TDES Key: {System.Text.Encoding.UTF8.GetString(tdes.Key)}");
                //Console.WriteLine($"TDES IV: {System.Text.Encoding.UTF8.GetString(tdes.IV)}");

                //string key = "9999_KBPK_01";
                string key = "6279018A32B6F2F29431FEB9E351EAB6";
                //string key =   "5D6EE6948C387ACEE56E02CBC8433194";

                //byte[] bytesInUni = Encoding.Unicode.GetBytes(Key);

                byte[] bytesInUni = HexToBytes(key);

                // Encrypt string  
                //byte[] encrypted = Encrypt(raw, tdes.Key, tdes.IV);
                byte[] encrypted = Encrypt(raw, bytesInUni, tdes.IV);
                // Print encrypted string  
                Console.WriteLine("Encrypted data:" + System.Text.Encoding.UTF8.GetString(encrypted));
                // Decrypt the bytes to a string.  
                //string decrypted = Decrypt(encrypted, tdes.Key, tdes.IV);
                
                string decrypted = Decrypt(encrypted, bytesInUni, tdes.IV);
                // Print decrypted string. It should be same as raw data  
                Console.WriteLine("Decrypted data:" + decrypted);
            }
        }
        catch (Exception exp)
        {
            Console.WriteLine(exp.Message);
        }
        Console.ReadKey();
    }
    static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
    {
        byte[] encrypted;
        // Create a new TripleDESCryptoServiceProvider.  
        using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
        {
            // Create encryptor  
            ICryptoTransform encryptor = tdes.CreateEncryptor(Key, IV);
            // Create MemoryStream  
            using (MemoryStream ms = new MemoryStream())
            {
                // Create crypto stream using the CryptoStream class. This class is the key to encryption  
                // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream  
                // to encrypt  
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    // Create StreamWriter and write data to a stream  
                    using (StreamWriter sw = new StreamWriter(cs))
                        sw.Write(plainText);
                    encrypted = ms.ToArray();
                }
            }
        }
        // Return encrypted data  
        return encrypted;
    }
    static string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
    {
        string plaintext = null;
        // Create TripleDESCryptoServiceProvider  
        using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
        {
            // Create a decryptor  
            ICryptoTransform decryptor = tdes.CreateDecryptor(Key, IV);
            // Create the streams used for decryption.  
            using (MemoryStream ms = new MemoryStream(cipherText))
            {
                // Create crypto stream  
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    // Read crypto stream  
                    using (StreamReader reader = new StreamReader(cs))
                        plaintext = reader.ReadToEnd();
                }
            }
        }
        return plaintext;
    }

    static byte[] HexToBytes(string keyvalue)
        {
        int KeyLength;
        KeyLength = keyvalue.Length / 2;
        byte[] MyResult = new byte[KeyLength];
        for (int i = 0; i < KeyLength - 1; i++)
        {
            MyResult[i] = Convert.ToByte(keyvalue.Substring(i*2,2),16);
        }
        return MyResult;
        
    }

}