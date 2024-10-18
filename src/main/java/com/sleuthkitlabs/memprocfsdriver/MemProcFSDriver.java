package com.sleuthkitlabs.memprocfsdriver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import vmm.IVmm;
import vmm.VmmException;
import vmm.entry.Vmm_VfsListEntry;

/**
 *
 */
public class MemProcFSDriver {

    private static final Logger LOGGER = LoggerFactory.getLogger(MemProcFSDriver.class);

    private final String imagePath;
        
    private final OutputStream outputstream;

    private final String yaraRulesPath;

    // Maintain a set of file paths that have already been added to the zip
    private final Set<String> addedEntries = new HashSet<>();
                
    private final String strPathToNativeBinaries;
    private IVmm vmm;
    
    public MemProcFSDriver(String imagePath, OutputStream outputStream, String strPathToNativeBinaries, String yaraRulesPath) {
        
        this.imagePath = imagePath;
        this.strPathToNativeBinaries = strPathToNativeBinaries;
        this.yaraRulesPath = yaraRulesPath;
        
        if (Objects.nonNull(outputStream)) {
            this.outputstream = outputStream;
        } else {
            this.outputstream = null;
        }
    }

    public void run() {

        try {
            List<String> argvMemProcFS = new ArrayList<>();
            argvMemProcFS.addAll(List.of(
                "-device", imagePath, 
                "-forensic", "1",
                "-disable-python",
                "-disable-symbolserver"));

            if (yaraRulesPath != null && !yaraRulesPath.isBlank()) {
                argvMemProcFS.addAll(List.of("-forensic-yara-rules", yaraRulesPath));
            }

            vmm = IVmm.initializeVmm(strPathToNativeBinaries, argvMemProcFS.toArray(new String[0]));
    
            // wait for the forensic processing to complete
            CountDownLatch latch = new CountDownLatch(1);

            final AtomicReference<String> atomicProgress = new AtomicReference<>("");

            ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(1);
            ScheduledFuture scheduledFuture = scheduledExecutorService.scheduleWithFixedDelay(() -> {
                try {
                    List<Vmm_VfsListEntry> directoryListing = vfsList("\\forensic\\");

                    Map<String, Vmm_VfsListEntry> directoryListingByName = directoryListing.stream().collect(Collectors.toMap(item -> item.name, item -> item, (o, n) -> o));
                
                    Vmm_VfsListEntry fileListEntry = directoryListingByName.get("progress_percent.txt");
                    if (fileListEntry == null) {
                        LOGGER.error("File not found: \\forensic\\progress_percent.txt");
                        System.err.println("File not found: \\forensic\\progress_percent.txt");
                        System.exit(1);
                    }

                    try (InputStream inputStream = new VFSInputStream("\\forensic\\progress_percent.txt", (int) fileListEntry.size, vmm);
                            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                        String progress = reader.lines().collect(Collectors.joining("\n"));
                        if ("100".equals(progress)) {
                            latch.countDown();
                            System.out.println("MemProcFS forensic processing complete: " + progress + "%");
                            return;
                        }

                        // Output percent complete if has changed since last reported
                        String previousProgress = atomicProgress.get();
                        if (!previousProgress.equals(progress)) {
                            atomicProgress.set(progress);
                            System.out.println("Waiting for MemProcFS forensic processing to complete: " + progress + "%");
                        }

                    }
                } catch (Throwable ex) {
                    LOGGER.error("Error checking progress", ex);
                    System.err.println("Error checking progress: " + ex.getMessage());
                    System.exit(1);
                }
            }, 0, 1, TimeUnit.SECONDS);

            try {
                latch.await();
            } catch (InterruptedException ex) {
                LOGGER.error("Interrupted waiting for forensics to complete");
                System.err.println("Interrupted waiting for forensics to complete");
                System.exit(1);
            }

            scheduledExecutorService.shutdown();

            List<FileToCollect> filesToCollect = getFilesToCollect();
            Map<String, List<FileToCollect>> groupedByParentPath = filesToCollect.stream().collect(Collectors.groupingBy(FileToCollect::parentPath));
    
            try (ZipOutputStream zipOutputStream = new ZipOutputStream(outputstream)) {
    
                for (Map.Entry<String, List<FileToCollect>> entry : groupedByParentPath.entrySet()) {
                    String parentPath = entry.getKey();
                    List<FileToCollect> files = entry.getValue();
    
                    // Check if the parent path contains wildcards
                    if (containsWildcard(parentPath)) {
                        // Get all matching parent directories
                        List<String> matchedDirectories = matchDirectoriesWithWildcards(parentPath);
    
                        // Process each matched directory
                        for (String matchedDirectory : matchedDirectories) {
                            processFilesInDirectory(matchedDirectory, files, zipOutputStream);
                        }
                    } else {
                        // No wildcard in the parent path, process as usual
                        processFilesInDirectory(parentPath, files, zipOutputStream);
                    }
                }
            } catch (IOException ex) {
                LOGGER.error("IO Exception ", ex);
            }
    
        } finally {
            if (vmm != null) {
                vmm.close();
            }
        }
    }
    
    // This method processes the files in a specific directory
    private void processFilesInDirectory(String parentPath, List<FileToCollect> files, ZipOutputStream zipOutputStream) throws IOException {
        List<Vmm_VfsListEntry> directoryListing = vfsList(parentPath);
        Map<String, Vmm_VfsListEntry> directoryListingByName = directoryListing.stream().collect(Collectors.toMap(item -> item.name, item -> item, (o, n) -> o));
    
        for (FileToCollect file : files) {
            // Check if the file name contains wildcards
            if (containsWildcard(file.name())) {
                List<Vmm_VfsListEntry> matchedFiles = matchWildcards(file.name(), directoryListing);
                for (Vmm_VfsListEntry matchedFile : matchedFiles) {
                    addToZip(zipOutputStream, parentPath, matchedFile);
                }
            } else {
                // No wildcard in the file name, process as usual
                if (!directoryListingByName.containsKey(file.name())) {
                    LOGGER.warn("File not found: " + parentPath + file.name());
                    continue;
                }
                Vmm_VfsListEntry fileListEntry = directoryListingByName.get(file.name());
                addToZip(zipOutputStream, parentPath, fileListEntry);
            }
        }
    }
    
    private boolean containsWildcard(String path) {
        return path.contains("*") || path.contains("?");
    }
    
    // This method matches directories that contain wildcards in the path
    private List<String> matchDirectoriesWithWildcards(String parentPath) {
        List<String> matchedDirectories = new ArrayList<>();
    
        // Split the parentPath by directory separators and traverse each part
        String _tempParentPath = parentPath;
        if (_tempParentPath.startsWith("\\")) {
            _tempParentPath = _tempParentPath.substring(1);
        }
        String[] pathSegments = _tempParentPath.split("\\\\");

        // Start the traversal at the last path segment before the first wildcard
        List<String> segmentsToTraverse = new ArrayList<>();
        StringBuilder pathBuilder = new StringBuilder();
        boolean wildCardFound = false;
        pathBuilder.append("\\");

        for (String segment : pathSegments) {
            if (wildCardFound || containsWildcard(segment)) {
                wildCardFound = true;
                segmentsToTraverse.add(segment);
            } else {
                pathBuilder.append(segment).append("\\");
            }
        }

        traverseAndMatch(pathBuilder.toString(), segmentsToTraverse.toArray(new String[0]), 0, matchedDirectories);
    
        return matchedDirectories;
    }
    
    // This method recursively traverses the directories and matches wildcards
    private void traverseAndMatch(String currentPath, String[] pathSegments, int index, List<String> matchedDirectories) {

        if (index == pathSegments.length) {
            matchedDirectories.add(currentPath);
            return;
        }
    
        String currentSegment = pathSegments[index];
    
        // List directories at the current path
        List<Vmm_VfsListEntry> directoryListing = vfsList(currentPath);

        // Handle the double wildcard '**' for recursive directory matching
        if (currentSegment.equals("**")) {
            // Match the current directory and all subdirectories recursively
            traverseAndMatch(currentPath, pathSegments, index + 1, matchedDirectories);

            // Recursively traverse through all subdirectories
            for (Vmm_VfsListEntry entry : directoryListing) {
                if (!entry.isFile) {
                    String nextPath = currentPath + entry.name + "\\";
                    traverseAndMatch(nextPath, pathSegments, index, matchedDirectories); // Continue traversing with the same '**'
                }
            }
        } else if (containsWildcard(currentSegment)) {
            // Handle other wildcards (*, ?)
            String regex = wildcardToRegex(currentSegment);
            Pattern compiledPattern = Pattern.compile(regex);
    
            for (Vmm_VfsListEntry entry : directoryListing) {
                if (!entry.isFile && compiledPattern.matcher(entry.name).matches()) {
                    String nextPath = currentPath + entry.name + "\\";
                    traverseAndMatch(nextPath, pathSegments, index + 1, matchedDirectories);
                }
            }
        } else {
            // No wildcard, traverse the exact directory
            for (Vmm_VfsListEntry entry : directoryListing) {
                if (!entry.isFile && entry.name.equals(currentSegment)) {
                    String nextPath = currentPath + entry.name + "\\";
                    traverseAndMatch(nextPath, pathSegments, index + 1, matchedDirectories);
                }
            }
        }
    }
    
    // This method is reused to handle wildcards in filenames
    private List<Vmm_VfsListEntry> matchWildcards(String pattern, List<Vmm_VfsListEntry> directoryListing) {
        String regex = wildcardToRegex(pattern);
        Pattern compiledPattern = Pattern.compile(regex);
    
        return directoryListing.stream()
                .filter(entry -> compiledPattern.matcher(entry.name).matches())
                .collect(Collectors.toList());
    }
    
    // This method converts a wildcard pattern into a regular expression
    private String wildcardToRegex(String wildcard) {
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < wildcard.length(); i++) {
            char c = wildcard.charAt(i);
            if (c == '*' && i + 1 < wildcard.length() && wildcard.charAt(i + 1) == '*') {
                // Handle '**' for recursive directory matching
                regex.append(".*");
                i++; // Skip the next '*'
            } else {
                switch (c) {
                    case '*':
                        regex.append("[^\\\\]*"); // Match any characters except directory separators
                        break;
                    case '?':
                        regex.append("[^\\\\]"); // Match exactly one character, except directory separators
                        break;
                    default:
                        regex.append(Pattern.quote(String.valueOf(c)));
                        break;
                }
            }
        }
        regex.append("$");
        return regex.toString();
    }
    
    private void addToZip(ZipOutputStream zipOutputStream, String parentPath, Vmm_VfsListEntry fileListEntry) throws IOException {

        String path = parentPath + fileListEntry.name;
        String zipPath = getZipPath(path);

        // Add a trailing slash for directories
        if (!fileListEntry.isFile) {
            zipPath = zipPath + "/";
        }

        // Check if the entry has already been added
        if (addedEntries.contains(zipPath)) {
            LOGGER.warn("Duplicate entry skipped: " + zipPath);
            return; // Skip adding the duplicate entry
        }
    
        ZipEntry zipEntry = new ZipEntry(zipPath);
        zipOutputStream.putNextEntry(zipEntry);
        if (fileListEntry.isFile) {
            try (InputStream inputStream = new VFSInputStream(path, (int) fileListEntry.size, vmm)) {
                inputStream.transferTo(zipOutputStream);
            }
        } 
        zipOutputStream.closeEntry();

        addedEntries.add(zipPath);
    }

    private String getZipPath(String path) {
        String zipPath = path.replace("\\", "/");

        if (zipPath.startsWith("/")) {
            zipPath = zipPath.substring(1);
        }

        return zipPath;
    }

    private List<Vmm_VfsListEntry> vfsList(String path) {
        try {

            if (path.startsWith("\\registry\\") && path.endsWith("\\")) {
                // workaround for issue: https://github.com/ufrisk/MemProcFS/issues/321
                path = path.substring(0, path.length() - 1);
            }

            List<Vmm_VfsListEntry> directoryListing = vmm.vfsList(path);
            return directoryListing;
        } catch (VmmException ex) {
            LOGGER.error("Error listing files for path: " + path, ex);
        }

        return List.of();
    }

    private List<FileToCollect> getFilesToCollect() {
        List<FileToCollect> filesToCollect = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(getClass().getResourceAsStream("/files_to_collect.txt")))) {

            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()
                        || (line.startsWith("##") && line.endsWith("##"))) {
                    continue;
                }

                int lastSeparatorIndex = line.lastIndexOf('\\');
                if (lastSeparatorIndex == -1) {
                    filesToCollect.add(new FileToCollect("", line));
                } else {
                    String parentPath = line.substring(0, lastSeparatorIndex + 1);
                    String fileName = line.substring(lastSeparatorIndex + 1);

                    if ("**".equals(fileName)) {
                        filesToCollect.add(new FileToCollect(line, "*"));
                    } else {
                        filesToCollect.add(new FileToCollect(parentPath, fileName));
                    }
                }
            }

        } catch (IOException ex) {
            LOGGER.error("IO Exception ", ex);
        }

        return filesToCollect;
    }

    private record FileToCollect(String parentPath, String name) {

    }
}
