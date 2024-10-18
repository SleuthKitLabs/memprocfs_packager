# MemProcFS Driver

Wrapper driver program to zip up the interesting artifacts from a MemProcFS execution.

The files that will be included in the output are defined in `files_to_collect.txt`

## Install the vmm.jar File into Local Maven Repository

Run the following command to install the vmm.jar file to your local repository. Ensure the file path is correct based on your system setup.

```
mvn install:install-file -Dfile="%MEMPROCFS_HOME%\vmm.jar" -DgroupId=vmm -DartifactId=vmmjava -Dversion=5.12.0 -Dpackaging=jar
```

## Environment Variables Required to Build

    MEMPROCFS_HOME = Path to memprocfs. This is copied to the target directory as part of the build process.

    LAUNCH4J_JRE_PATH = Relative path to the JRE that will be bundled with the executable. If left blank then Launch4J will search for an installed JRE on the user's system at runtime.

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
memprocfs_driver.exe -i E:\test_data\memory_images\stuxnet.img -o stuxnet.zip
```