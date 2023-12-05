using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;

namespace CreateEncryptionDat
{
    [Serializable]
    public class EncryptionInfo
    {
        private string _name;
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }

        private string _password;
        public string Password
        {
            get { return _password; }
            set { _password = value; }
        }
    }
    internal class Program
    {
        public static string FilePath = AppDomain.CurrentDomain.BaseDirectory + "Config\\Recipes.dat";
        public static string GetENcrytPassword(string name, string password)
        {
            var md5 = new MD5CryptoServiceProvider();
            return BitConverter.ToString(md5.ComputeHash(Encoding.Default.GetBytes(name + password))).Replace("-", "");
        }
        public static bool CreateRecipePassword(string recipeName = "", string passward = "")
        {
            FileStream fs = null;
            List<EncryptionInfo> enCryptList = new List<EncryptionInfo>();
            string resultStr = "写入密码信息成功!";
            bool result = true;
            try
            {
                string pass = GetENcrytPassword(recipeName, passward);
                enCryptList.Add(new EncryptionInfo() { Name = recipeName, Password = pass });

                DirectoryInfo info = Directory.GetParent(FilePath);
                if (!Directory.Exists(FilePath))
                {
                    Directory.CreateDirectory(info.ToString());
                }
                fs = new FileStream(FilePath, FileMode.Create);
                BinaryFormatter bf = new BinaryFormatter();
                bf.Serialize(fs, enCryptList);
            }
            catch (Exception e)
            {
                resultStr = "写入密码信息异常:" + e.Message;
                result = false;
            }
            finally
            {
                if (fs != null)
                {
                    fs.Close();
                }
            }
            Console.WriteLine(resultStr);
            return result;
        }

        /// <summary>
        /// 对称加密之TripleDes加密
        /// </summary>
        /// <param name="plainTextArray">明文字节数组</param>
        /// <param name="Key">Key</param>
        /// <param name="IV">IV</param>
        /// <returns>返回字节数组</returns>
        public static byte[] TripleDesEncrypt(string plainText, byte[] Key, byte[] IV)
        {
            //将明文字符串转成明文字节数组
            Encoding encoding = Encoding.GetEncoding("utf-8");
            byte[] plainTextArray = encoding.GetBytes(plainText);

            //新建一个MemoryStream对象存放加密后的数据流
            MemoryStream memoryStream = new MemoryStream();

            //新建一个CryptoStream对象
            CryptoStream cryptoStream = new CryptoStream
                (
                    memoryStream,
                    new TripleDESCryptoServiceProvider().CreateEncryptor(Key, IV),
                    CryptoStreamMode.Write
                );

            //将加密后的字节流写入到memoryStream
            cryptoStream.Write(plainTextArray, 0, plainTextArray.Length);

            //把缓冲区中的最后状态更新到memoryStream，并清除cryptoStream的缓存区。
            cryptoStream.FlushFinalBlock();

            //保存为文件
            SaveFile(FilePath, memoryStream);

            //把加密后的数据流转成字节流
            byte[] result = memoryStream.ToArray();

            //关闭两个Stream
            cryptoStream.Close();
            memoryStream.Close();

            //返回结果
            return result;
        }

        /// <summary>
        /// 对称加密之TripleDes解密
        /// </summary>
        /// <param name="encryptTextArray">加密字节数组</param>
        /// <param name="Key">Key</param>
        /// <param name="IV">IV</param>
        /// <returns>返回字符串</returns>
        public static string TripleDesDecrypt(byte[] encryptTextArray, byte[] Key, byte[] IV)
        {
            //将加密字符串转成加密字节数组
            Encoding encoding = Encoding.GetEncoding("utf-8");

            //新建一个MemoryStream对象存放解密后的数据流
            MemoryStream memoryStream = new MemoryStream(encryptTextArray);

            //新建一个CryptoStream对象
            CryptoStream cryptoStream = new CryptoStream
                (
                    memoryStream,
                    new TripleDESCryptoServiceProvider().CreateDecryptor(Key, IV),
                    CryptoStreamMode.Read
                );

            //新建一个存放解密后的明文字节数组（可能比加密前的明文长）
            byte[] decryptTextArray = new byte[encryptTextArray.Length];

            //把解密后的数据流读到
            cryptoStream.Read(decryptTextArray, 0, decryptTextArray.Length);

            //关闭两个Stream
            memoryStream.Close();
            cryptoStream.Close();

            return encoding.GetString(decryptTextArray);
        }
        public static void SaveFile(string filePath, MemoryStream memoryStream)
        {
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
            using (FileStream fileStream = File.OpenWrite(filePath))
            {
                memoryStream.WriteTo(fileStream);
            }
        }
        public static byte[] ReadFileAsBytes(string filePath)
        {
            FileStream fileStream = File.OpenRead(filePath);
            using (BinaryReader binaryReader = new BinaryReader(fileStream))
            {
                byte[] inputByteArray = new byte[fileStream.Length];
                binaryReader.Read(inputByteArray, 0, inputByteArray.Length);
                return inputByteArray;
            }
        }
        static void Main(string[] args)
        {
            try
            {


                string recipeName = "";
                string passward = "ptp123";
                //CreateRecipePassword(recipeName, passward);

                byte[] keyArray, ivArray;
                //生成Key和IV
                TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider();
                keyArray = tripleDES.Key;
                ivArray = tripleDES.IV;



                // write to txt
                string str = Convert.ToBase64String(keyArray);
                StreamWriter sw = new StreamWriter(FilePath.Remove(FilePath.LastIndexOf("\\")) + "\\key.txt");
                sw.WriteLine(str);
                str = Convert.ToBase64String(ivArray);
                sw.WriteLine(str);
                sw.Close();

                // read from txt
                StreamReader sr = new StreamReader(FilePath.Remove(FilePath.LastIndexOf("\\")) + "\\key.txt");
                str = sr.ReadLine();
                keyArray = Convert.FromBase64String(str);
                str = sr.ReadLine();
                ivArray = Convert.FromBase64String(str);
                sr.Close();

                //加密
                byte[] encryptTextArray = TripleDesEncrypt(passward, keyArray, ivArray);

                byte[] encryptTextArray2 = ReadFileAsBytes(FilePath);

                //解密
                string decryptText = TripleDesDecrypt(encryptTextArray2, keyArray, ivArray);

                //输出
                Console.WriteLine($"明文数据：{passward}");
                Console.WriteLine($"加密数据：{Encoding.UTF8.GetString(encryptTextArray)}");
                Console.WriteLine($"解密后数据：{decryptText}");
                Console.WriteLine(string.Compare(passward, decryptText) == 0 ? "验证正确！" : "验证错误！");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            Console.ReadLine();
        }
    }
}
