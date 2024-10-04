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

                File.WriteAllText("publicKey.pem", publicKey);
                File.WriteAllText("privateKey.pem", privateKey);
            }
        }

        private void EncryptRSA(string filePath, string publicKeyPath)
        {
            byte[] data = File.ReadAllBytes(filePath);
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(Convert.FromBase64String(File.ReadAllText(publicKeyPath)));
                byte[] encryptedData = rsa.Encrypt(data, false);
                File.WriteAllBytes(filePath + ".enc", encryptedData);
            }
        }

        private void DecryptRSA(string filePath, string privateKeyPath)
        {
            byte[] encryptedData = File.ReadAllBytes(filePath);
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(Convert.FromBase64String(File.ReadAllText(privateKeyPath)));
                byte[] decryptedData = rsa.Decrypt(encryptedData, false);
                File.WriteAllBytes(filePath.Replace(".enc", ".dec"), decryptedData);
            }
        }


    }
}
