# MemProcFS Packager

This program uses the [MemProcFS](https://github.com/ufrisk/MemProcFS) library to:
* Load a memory image
* Extract key files from the virtual file system
* Save the files to a ZIP file

The files that will be included in the ZIP are defined in `files_to_collect.txt`

## Install the vmm.jar File into Local Maven Repository

Run the following command to install the vmm.jar file to your local repository. Ensure the file path is correct based on your system setup.

```
mvn install:install-file -Dfile="%MEMPROCFS_HOME%\vmm.jar" -DgroupId=vmm -DartifactId=vmmjava -Dversion=5.12.5 -Dpackaging=jar
```

## Environment Variables Required to Build

    MEMPROCFS_HOME = Path to memprocfs. This is copied to the target directory as part of the build process.

## To build

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
