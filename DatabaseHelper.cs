// DatabaseHelper.cs
using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;

public class ApkRecord
{
    public int Id { get; set; }
    public string ApkName { get; set; }
    public string SdkVersion { get; set; }
    public string ComponentsJson { get; set; } // Stores component info as JSON
    public DateTime DateScanned { get; set; }
}

public static class DatabaseHelper
{
    // Database file will be created in the application's base directory
    private static string DbPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ApkInspector.db");

    public static void InitializeDatabase()
    {
        using (var connection = new SqliteConnection($"Data Source={DbPath}"))
        {
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = @"
                CREATE TABLE IF NOT EXISTS ApkRecords (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ApkName TEXT NOT NULL,
                    SdkVersion TEXT,
                    ComponentsJson TEXT,
                    DateScanned TEXT
                );
            ";
            command.ExecuteNonQuery();
        }
    }

    public static void InsertApkRecord(ApkRecord record)
    {
        using (var connection = new SqliteConnection($"Data Source={DbPath}"))
        {
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO ApkRecords (ApkName, SdkVersion, ComponentsJson, DateScanned)
                VALUES ($apkName, $sdkVersion, $componentsJson, $dateScanned);
            ";
            command.Parameters.AddWithValue("$apkName", record.ApkName);
            command.Parameters.AddWithValue("$sdkVersion", record.SdkVersion);
            command.Parameters.AddWithValue("$componentsJson", record.ComponentsJson);
            command.Parameters.AddWithValue("$dateScanned", record.DateScanned.ToString("o")); // ISO format
            command.ExecuteNonQuery();
        }
    }

    public static List<ApkRecord> GetApkRecords(string filter = "")
    {
        var records = new List<ApkRecord>();
        using (var connection = new SqliteConnection($"Data Source={DbPath}"))
        {
            connection.Open();
            var command = connection.CreateCommand();
            if (string.IsNullOrEmpty(filter))
            {
                command.CommandText = "SELECT * FROM ApkRecords ORDER BY DateScanned DESC";
            }
            else
            {
                command.CommandText = "SELECT * FROM ApkRecords WHERE ApkName LIKE $filter OR SdkVersion LIKE $filter ORDER BY DateScanned DESC";
                command.Parameters.AddWithValue("$filter", "%" + filter + "%");
            }

            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    records.Add(new ApkRecord
                    {
                        Id = reader.GetInt32(0),
                        ApkName = reader.GetString(1),
                        SdkVersion = reader.GetString(2),
                        ComponentsJson = reader.GetString(3),
                        DateScanned = DateTime.Parse(reader.GetString(4))
                    });
                }
            }
        }
        return records;
    }
}
