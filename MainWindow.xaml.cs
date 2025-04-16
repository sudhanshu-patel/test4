// MainWindow.xaml.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using System.Text.Json;

namespace APKInspector
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            // Initialize the database when the main window is loaded.
            DatabaseHelper.InitializeDatabase();
        }

        private async void UploadAPK_Click(object sender, RoutedEventArgs e)
        {
            // Declare variables at the top for proper scope
            string apkPath = "";

            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "APK Files (*.apk)|*.apk",
                Title = "Select an APK File"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                apkPath = openFileDialog.FileName;
                FilePathTextBlock.Text = $"Selected APK: {apkPath}";

                FilePathTextBlock.Text += "\nExtracting APK details...";
                string extractionResult = await ExtractApkDetailsAsync(apkPath);

                if (extractionResult.StartsWith("Error:"))
                {
                    FilePathTextBlock.Text += "\n" + extractionResult;
                }
                else
                {
                    FilePathTextBlock.Text += "\nExtraction complete.";
                    // Define tempOutput in a variable for use in parsing
                    string tempOutput = Path.Combine(Path.GetTempPath(), "APKInspector", Path.GetFileNameWithoutExtension(apkPath));
                    try
                    {
                        // Parse the manifest to get the SDK version and components
                        var parseResult = ParseAndroidManifest(tempOutput);
                        string sdkVersion = parseResult.SdkVersion;
                        var components = parseResult.Components;

                        FilePathTextBlock.Text += $"\nSDK Version: {sdkVersion}";
                        foreach (var comp in components)
                        {
                            FilePathTextBlock.Text += $"\n- [{comp.ComponentType.ToUpper()}] {comp.Name}, Exported: {comp.Exported}, TaskAffinity: {comp.TaskAffinity}";
                        }

                        // Convert components list to JSON
                        string componentsJson = JsonSerializer.Serialize(components);
                        var record = new ApkRecord
                        {
                            ApkName = Path.GetFileName(apkPath),
                            SdkVersion = sdkVersion,
                            ComponentsJson = componentsJson,
                            DateScanned = DateTime.Now
                        };

                        DatabaseHelper.InsertApkRecord(record);
                        FilePathTextBlock.Text += "\nAPK record saved to database.";
                    }
                    catch (Exception ex)
                    {
                        FilePathTextBlock.Text += "\nError parsing AndroidManifest.xml: " + ex.Message;
                    }
                }
            }
        }

        // Example of calling apktool; update FileName if using the full path
        private async Task<string> ExtractApkDetailsAsync(string apkPath)
        {
            string tempOutput = Path.Combine(Path.GetTempPath(), "APKInspector", Path.GetFileNameWithoutExtension(apkPath));
            if (Directory.Exists(tempOutput))
            {
                Directory.Delete(tempOutput, true);
            }
            Directory.CreateDirectory(tempOutput);

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "java", // Call java directly
                    Arguments = $"-jar \"C:\\apktool\\apktool.jar\" d \"{apkPath}\" -o \"{tempOutput}\" -f",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            string output = await process.StandardOutput.ReadToEndAsync();
            string error = await process.StandardError.ReadToEndAsync();
            process.WaitForExit();

            if (!string.IsNullOrWhiteSpace(error))
                return "Error: " + error;
            else
                return output;
        }


        // Updated ParseAndroidManifest that returns a tuple with sdkVersion and a List of components
        private (string SdkVersion, System.Collections.Generic.List<ComponentInfo> Components) ParseAndroidManifest(string extractedFolder)
        {
            string manifestPath = Path.Combine(extractedFolder, "AndroidManifest.xml");
            if (!File.Exists(manifestPath))
                throw new FileNotFoundException("AndroidManifest.xml not found", manifestPath);

            var doc = new System.Xml.XmlDocument();
            doc.Load(manifestPath);

            var ns = new System.Xml.XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("android", "http://schemas.android.com/apk/res/android");

            string sdkVersion = "Unknown";
            var components = new System.Collections.Generic.List<ComponentInfo>();

            var usesSdk = doc.SelectSingleNode("//uses-sdk", ns);
            if (usesSdk != null)
            {
                var minSdkAttr = usesSdk.Attributes.GetNamedItem("minSdkVersion", "http://schemas.android.com/apk/res/android");
                if (minSdkAttr != null)
                {
                    sdkVersion = minSdkAttr.Value;
                }
                else
                {
                    var targetSdkAttr = usesSdk.Attributes.GetNamedItem("targetSdkVersion", "http://schemas.android.com/apk/res/android");
                    if (targetSdkAttr != null)
                    {
                        sdkVersion = targetSdkAttr.Value;
                    }
                }
            }

            // Define the component types to record
            string[] componentTypes = { "activity", "service", "receiver", "provider" };
            foreach (var type in componentTypes)
            {
                var nodes = doc.SelectNodes($"//{type}", ns);
                if (nodes != null)
                {
                    foreach (System.Xml.XmlNode node in nodes)
                    {
                        var comp = new ComponentInfo
                        {
                            ComponentType = type,
                            Name = node.Attributes.GetNamedItem("name", "http://schemas.android.com/apk/res/android")?.Value ?? "Unknown",
                            Exported = node.Attributes.GetNamedItem("exported", "http://schemas.android.com/apk/res/android")?.Value ?? "Not Defined",
                            TaskAffinity = node.Attributes.GetNamedItem("taskAffinity", "http://schemas.android.com/apk/res/android")?.Value ?? "Not Defined"
                        };
                        components.Add(comp);
                    }
                }
            }
            return (sdkVersion, components);
        }

        // Button click event to view the saved records
        private void ViewRecords_Click(object sender, RoutedEventArgs e)
        {
            FilterWindow filterWindow = new FilterWindow();
            filterWindow.ShowDialog();
        }
    }

    // ComponentInfo class used for storing APK component details
    public class ComponentInfo
    {
        public string ComponentType { get; set; }
        public string Name { get; set; }
        public string Exported { get; set; }
        public string TaskAffinity { get; set; }
    }
}
