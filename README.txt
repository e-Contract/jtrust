README for FedICT jTrust Project
================================

=== 1. Introduction

This project contains the source core tree of the FedICT jTrust library.
The source code is hosted at: http://code.google.com/p/jtrust/


=== 2. Requirements

The following is required for compiling the eID Applet software:
* Sun Java 1.6.0_12
* Apache Maven 2.0.9


=== 3. Build

The project can be build via:
	mvn clean install


=== 4. Eclipse IDE

The Eclipse project files can be created via:
	mvn eclipse:eclipse

Afterwards simply import the projects in Eclipse via:
	File -> Import... -> General:Existing Projects into Workspace

First time you use an Eclipse workspace you might need to add the maven 
repository location. Do this via:
    mvn eclipse:add-maven-repo -Declipse.workspace=<location of your workspace>


=== 5. License

The license conditions can be found in the file: LICENSE.txt

