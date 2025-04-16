// FilterWindow.xaml.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;

namespace APKInspector
{
    public partial class FilterWindow : Window
    {
        public FilterWindow()
        {
            InitializeComponent();
            LoadRecords();
        }

        private void LoadRecords(string generalFilter = "")
        {
            // Load all records from the database (using the general filter on APK name/SDK version)
            List<ApkRecord> records = DatabaseHelper.GetApkRecords(generalFilter);

            // Get the verbose filter criteria from the UI
            string selectedComponentType = (ComponentTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString().ToLower();
            bool exportedOnly = ExportedCheckBox.IsChecked ?? false;
            string taskAffinityFilter = TaskAffinityTextBox.Text?.Trim().ToLower();

            // Filter records based on verbose criteria:
            var filteredRecords = records.Where(record =>
            {
                // Parse the JSON of components stored in the record
                List<ComponentInfo> comps = null;
                try
                {
                    comps = JsonSerializer.Deserialize<List<ComponentInfo>>(record.ComponentsJson);
                }
                catch
                {
                    // If deserialization fails, skip this record.
                    return false;
                }
                if (comps == null || comps.Count == 0)
                    return false;

                // Determine if any component in this record matches all the specified filters:
                return comps.Any(comp =>
                {
                    bool typeMatch = selectedComponentType == "all" ||
                                     comp.ComponentType.Equals(selectedComponentType, StringComparison.OrdinalIgnoreCase);
                    bool exportedMatch = !exportedOnly || (comp.Exported.Equals("true", StringComparison.OrdinalIgnoreCase));
                    bool taskAffinityMatch = string.IsNullOrEmpty(taskAffinityFilter) ||
                                               (comp.TaskAffinity != null && comp.TaskAffinity.ToLower().Contains(taskAffinityFilter));
                    return typeMatch && exportedMatch && taskAffinityMatch;
                });
            }).ToList();

            RecordsDataGrid.ItemsSource = filteredRecords;
        }

        private void SearchButton_Click(object sender, RoutedEventArgs e)
        {
            string generalFilter = GeneralFilterTextBox.Text;
            LoadRecords(generalFilter);
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            GeneralFilterTextBox.Text = "";
            ComponentTypeComboBox.SelectedIndex = 0;
            ExportedCheckBox.IsChecked = false;
            TaskAffinityTextBox.Text = "";
            LoadRecords();
        }
    }
}
