/*
 * memprocfs_packager
 * 
 * Copyright (C) 2024  Sleuth Kit Labs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.sleuthkitlabs.memprocfspackager;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class Main {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);
    
    public static void main(String[] args) throws FileNotFoundException, IOException {
        
        Options allOptions = new Options();
        Options visibleOptions = new Options(); // These are displayed in help meny

        Option input = new Option("i", "input", true, "input file path");
        input.setRequired(true);
        allOptions.addOption(input);
        visibleOptions.addOption(input);

        Option output = new Option("o", "output", true, "output file");
        output.setRequired(true);
        allOptions.addOption(output);
        visibleOptions.addOption(output);

        Option forceOverwrite = new Option("f", "force", false, "force overwrite of output file");
        allOptions.addOption(forceOverwrite);
        visibleOptions.addOption(forceOverwrite);

        Option noClobber = new Option("n", "no-clobber", false, "do not overwrite existing output file");
        allOptions.addOption(noClobber);
        visibleOptions.addOption(noClobber);

        Option yaraRules = new Option("y", "yara-rules", true, "yara rules file");
        allOptions.addOption(yaraRules);
        visibleOptions.addOption(yaraRules);

        Option acceptElasticLicense = Option.builder()
            .longOpt("license-accept-elastic-license-2-0")
            .desc("Passes the -license-accept-elastic-license-2-0 option to MemProcFS")
            .hasArg(false)
            .build();
        allOptions.addOption(acceptElasticLicense); // This option is hidden, not shown in help.

        Option memProcFSOpt = new Option("m", "memprocfs", true, "path to MemProcFS");
        allOptions.addOption(memProcFSOpt); // This option is hidden, not shown in help.

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;
        
        try {
             cmd = parser.parse(allOptions, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("memprocfs_packager", visibleOptions);

            System.exit(1);
        }
        
        String inputFilePath = cmd.getOptionValue("input");
        String outputFilePath = cmd.getOptionValue("output");

        String strPathToNativeBinaries = "memprocfs";
        if (cmd.hasOption("memprocfs")) {
            strPathToNativeBinaries = cmd.getOptionValue("memprocfs");
        }

        // check that path exists
        Path memprocfsPath = Paths.get(strPathToNativeBinaries);
        Path dllPath = memprocfsPath.resolve("vmm.dll");
        if (!Files.isDirectory(memprocfsPath) || !Files.exists(dllPath)) {
            System.err.println("Error: MemProcFS not found at " + memprocfsPath.toAbsolutePath().toString());
            System.exit(1);
        }

        // check that input file exists
        Path inputPath = Paths.get(inputFilePath);
        if (!Files.exists(inputPath)) {
            System.err.println("Error: File not found: " + inputFilePath);
            System.exit(1);
        }

        // check if output file exists and handle overwrite logic
        Path outputPath = Paths.get(outputFilePath);
        if (Files.exists(outputPath)) {
            // If no-clobber (-n) is set, do not overwrite and exit
            if (cmd.hasOption("n")) {
                System.out.println("Output file exists and --no-clobber is set. Operation aborted.");
                System.exit(1);
            }

            // If the file exists and force flag is not set, ask for confirmation
            if (!cmd.hasOption("f")) {
                try (Scanner scanner = new Scanner(System.in)) {
                    System.out.println("File " + outputFilePath + " already exists. Overwrite? (y/n)");
                    String response = scanner.nextLine().trim().toLowerCase();
                    if (!response.equals("y") && !response.equals("yes")) {
                        System.out.println("Operation cancelled.");
                        System.exit(0);
                    }
                }
            }
        }

        String yaraRulesPath = "";
        if (cmd.hasOption("yara-rules")) {
            String _yaraRulesPath = cmd.getOptionValue("yara-rules");
            if (Files.exists(Path.of(_yaraRulesPath))) {
                yaraRulesPath = _yaraRulesPath;
            } else {
                System.err.println("Yara rules file not found: " + _yaraRulesPath);
                LOGGER.warn("Yara rules file not found: " + _yaraRulesPath);
            }
        }

        List<String> additionalOptions = new ArrayList<>();
        if (cmd.hasOption("license-accept-elastic-license-2-0")) {
            additionalOptions.add("-license-accept-elastic-license-2-0");
        }
        
        LOGGER.debug("Starting processing image:" + inputFilePath);

        try (FileOutputStream outputStream = new FileOutputStream(outputFilePath)) {
            MemProcFSPackager packager = new MemProcFSPackager(inputFilePath, outputStream, strPathToNativeBinaries, yaraRulesPath, additionalOptions);
            packager.run();
        } catch (IOException ex) {
            System.err.println("Error: " + ex.getMessage());
            LOGGER.error("Error writing to file", ex);

            System.exit(1);
        }

        LOGGER.debug("Processing completed. Output written to: " + outputFilePath);
        System.out.println("Processing completed. Output written to: " + outputFilePath);
    }
}
