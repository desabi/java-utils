package com.desabisc.zip;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) {
        String zipFilePath = "C:\\data\\comprimido.zip";  // Path to your ZIP file
        String txtFileName = "fruits.txt";  // Name of the TXT file inside the ZIP

        try (ZipFile zipFile = new ZipFile(zipFilePath)) {
            // Locate the specific txt file inside the zip
            ZipEntry entry = zipFile.getEntry(txtFileName);

            if (entry != null) {
                // Read the content of the txt file-
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(zipFile.getInputStream(entry)))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println(line);
                    }
                }
            } else {
                System.out.println("The file " + txtFileName + " was not found inside the ZIP.");
            }
        } catch (IOException e) {
            System.out.println("e.getMessage() = " + e.getMessage());
        }
    }
}