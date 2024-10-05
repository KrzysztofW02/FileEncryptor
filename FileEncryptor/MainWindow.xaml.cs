using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Path = System.IO.Path;

namespace FileEncryptor
{
    public partial class MainWindow : Window
    {
        private string selectedFilePath;
        public MainWindow()
        {
            InitializeComponent();
        }

        private void ChooseFileButton_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                selectedFilePath = openFileDialog.FileName;
            }
        }

        private void GenerateRSAKeys()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                string publicKey = Convert.ToBase64String(rsa.ExportCspBlob(false));
                string privateKey = Convert.ToBase64String(rsa.ExportCspBlob(true));
                string keyDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Keys");
                if (!Directory.Exists(keyDirectory))
                {
                    Directory.CreateDirectory(keyDirectory);
                }

                File.WriteAllText(Path.Combine(keyDirectory, "publicKey.pem"), publicKey);
                File.WriteAllText(Path.Combine(keyDirectory, "privateKey.pem"), privateKey);
            }
        }


        private void EncryptRSA(string filePath)
        {
            string keyDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Keys");
            string publicKeyPath = Path.Combine(keyDirectory, "publicKey.pem");

            if (!File.Exists(publicKeyPath))
            {
                MessageBox.Show("Public key not found. Please generate RSA keys first.");
                return;
            }

            byte[] data = File.ReadAllBytes(filePath); 
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(Convert.FromBase64String(File.ReadAllText(publicKeyPath)));

                byte[] encryptedData = rsa.Encrypt(data, false);

                string encryptedFilePath = Path.Combine(
                    Path.GetDirectoryName(filePath),
                    Path.GetFileNameWithoutExtension(filePath) + "(encrypted)" + Path.GetExtension(filePath));

                File.WriteAllBytes(encryptedFilePath, encryptedData);
            }
        }

        private void DecryptRSA(string filePath)
        {
            string keyDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Keys");
            string privateKeyPath = Path.Combine(keyDirectory, "privateKey.pem");

            if (!File.Exists(privateKeyPath))
            {
                MessageBox.Show("Private key not found. Please generate RSA keys first.");
                return;
            }

            byte[] encryptedData = File.ReadAllBytes(filePath); 
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(Convert.FromBase64String(File.ReadAllText(privateKeyPath)));

                byte[] decryptedData = rsa.Decrypt(encryptedData, false);

                string decryptedFilePath = Path.Combine(
                    Path.GetDirectoryName(filePath),
                    Path.GetFileNameWithoutExtension(filePath).Replace("(encrypted)", "(decrypted)") + Path.GetExtension(filePath));

                File.WriteAllBytes(decryptedFilePath, decryptedData);
            }
        }



        private void EncryptAES(string filePath, string password)
        {
            byte[] key;
            byte[] iv;

            using (var sha256 = SHA256.Create())
            {
                key = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                iv = key.Take(16).ToArray();
            }

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (var fs = new FileStream(filePath, FileMode.Open))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            fs.CopyTo(csEncrypt);
                        }

                        string encryptedFilePath = Path.Combine(
                            Path.GetDirectoryName(filePath),
                            Path.GetFileNameWithoutExtension(filePath) + "(encrypted)" + Path.GetExtension(filePath));
                        File.WriteAllBytes(encryptedFilePath, msEncrypt.ToArray());
                    }
                }
            }
        }

        private void DecryptAES(string filePath, string password)
        {
            byte[] key;
            byte[] iv;

            using (var sha256 = SHA256.Create())
            {
                key = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                iv = key.Take(16).ToArray();
            }

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var fs = new FileStream(filePath, FileMode.Open))
                {
                    using (var msDecrypt = new MemoryStream())
                    {
                        using (var csDecrypt = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                        {
                            csDecrypt.CopyTo(msDecrypt);
                        }

                        string decryptedFilePath = Path.Combine(
                            Path.GetDirectoryName(filePath),
                            Path.GetFileNameWithoutExtension(filePath).Replace("(encrypted)", "(decrypted)") + Path.GetExtension(filePath));
                        File.WriteAllBytes(decryptedFilePath, msDecrypt.ToArray());
                    }
                }
            }
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(selectedFilePath))
            {
                MessageBox.Show("Please select a file to encrypt.");
                return;
            }

            var selectedAlgorithm = ((ComboBoxItem)AlgorithmComboBox.SelectedItem)?.Content.ToString();

            if (selectedAlgorithm == "AES")
            {
                if (string.IsNullOrEmpty(PasswordBoxAES.Password))
                {
                    MessageBox.Show("Please enter a password for AES encryption.");
                    return;
                }
                EncryptAES(selectedFilePath, PasswordBoxAES.Password);
                MessageBox.Show("File encrypted successfully using AES.");
            }
            else if (selectedAlgorithm == "RSA")
            {
                string keyDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Keys");
                if (!File.Exists(Path.Combine(keyDirectory, "publicKey.pem")) || !File.Exists(Path.Combine(keyDirectory, "privateKey.pem")))
                {
                    MessageBox.Show("Generating RSA keys");
                    GenerateRSAKeys();
                }

                EncryptRSA(selectedFilePath);
                MessageBox.Show("File encrypted successfully using RSA.");
            }
            else
            {
                MessageBox.Show("Please select an encryption algorithm.");
            }
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(selectedFilePath))
            {
                MessageBox.Show("Please select a file to decrypt.");
                return;
            }

            var selectedAlgorithm = ((ComboBoxItem)AlgorithmComboBox.SelectedItem)?.Content.ToString();

            if (selectedAlgorithm == "AES")
            {
                if (string.IsNullOrEmpty(PasswordBoxAES.Password))
                {
                    MessageBox.Show("Please enter a password for AES decryption.");
                    return;
                }
                DecryptAES(selectedFilePath, PasswordBoxAES.Password);
                MessageBox.Show("File decrypted successfully using AES.");
            }
            else if (selectedAlgorithm == "RSA")
            {
                DecryptRSA(selectedFilePath);
                MessageBox.Show("File decrypted successfully using RSA.");
            }
            else
            {
                MessageBox.Show("Please select a decryption algorithm.");
            }
        }
    }
}
