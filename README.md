# MemProcFS Packager

This program uses the [MemProcFS](https://github.com/ufrisk/MemProcFS) library to:
* Load a memory image
* Extract key files from the virtual file system
* Save the files to a ZIP file

The files that will be included in the ZIP are defined in `files_to_collect.txt`

## Install the vmm.jar File into Local Maven Repository

Run the following command to install the vmm.jar file to your local repository. Ensure the file path is correct based on your system setup.

```
mvn install:install-file -Dfile="%MEMPROCFS_HOME%\vmm.jar" -DgroupId=vmm -DartifactId=vmmjava -Dversion=5.17.6 -Dpackaging=jar
```

## Environment Variables Required to Build

    MEMPROCFS_HOME = Path to memprocfs. This is copied to the target directory as part of the build process.

## Build

### Native image build (GraalVM)

The native image profile compiles the application into a self-contained Windows executable that requires no JRE on the target machine.

> **Note:** The native executable still requires `vmm.dll` and the other MemProcFS native DLLs at runtime.

#### Prerequisites

* **GraalVM JDK 25** — install to a local path, e.g. `C:\Program Files\Java\graalvm-jdk-25.0.2+10.1`
* On Windows, Native Image requires Visual Studio and Microsoft Visual C++ (MSVC).
* `MEMPROCFS_HOME` environment variable set to the MemProcFS installation directory.

#### Building native image

Make sure GraalVM is configured as your current Java version and use the native profile.

```cmd
SET JAVA_HOME=C:\Program Files\Java\graalvm-jdk-25.0.2+10.1
SET PATH=%JAVA_HOME%\bin;%PATH%

mvn clean package -Pnative -DskipTests
```

This produces `target\bin\memprocfs_packager.exe` — a standalone native executable with no JRE dependency.

### Standard build (launch4j wrapper)

```
mvn clean package
```

### Running the example locally

The example can be run locally using the following Maven goal:

```
mvn exec:java
```

```
mvn exec:java -Dexec.args="-i E:\test_data\memory_images\stuxnet.img -o stuxnet.zip -m %MEMPROCFS_HOME%"
```

or from the `target\bin` directory:

```
memprocfs_packager.exe -i E:\test_data\memory_images\stuxnet.img -o stuxnet.zip
```
