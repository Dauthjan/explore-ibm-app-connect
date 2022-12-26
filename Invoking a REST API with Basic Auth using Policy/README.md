# How to invoke a Basic Auth secured HTTP Service in IBM ACE

This document demonstrates the capability of invoking Basic Auth secured HTTP(s) service by injecting Auth Headers inruntime. Although Basic Auth is not generally used in production environments (securing the APIs is majorly handled by APManagement Tools like IBM API Connect), it is worth learning.

### Step 1:
MyApplication is a Basic Auth protected REST service. Created a new MySecondApplication which will invoke MyApplication. Note:
HTTP Request would require the Basic Auth in headers. 
<img src="https://imgpile.com/images/byOKTR.png" alt="Untitled" border="0"></br>
First, we invoke the service without introducing Auth. This should result into error. </br>
<img src="https://imgpile.com/images/byOOGw.png" alt="Untitled" border="0"></br>

### Step 2:
Writing BasicAuth in ESQL to add in the HTTPRequestHeader *[NOT RECOMMENDED]*. Writing password in plain text is not the recommended way (although it works).
<img src="https://imgpile.com/images/byOkXF.png" alt="Untitled" border="0"></br>
Re-deply the application, this time the application should work fine!</br>
<img src="https://imgpile.com/images/byO0pi.png" alt="Untitled" border="0"></br>
Now, since writing passwords in plain-text is not the recommended way, we’ll comment the piece of code and try to inject the same the Auth using Policy!

### Step 3:
Comment the code in ESQL that injects the username and password
<img src="https://imgpile.com/images/byOSGX.png" alt="Untitled" border="0"></br>

### Step 4:
Create a policy for the consumer. Note the Identified to propagate is now set to STATIC ID, Propagation is set to true and Transport propagation configuration is the Security Identifier (last time we saved the credentials in server.conf.yaml, this time we replaced it using mqsisetdbparms). We cannot use credentials stored in server.conf.yaml as it will throw an expection: BIP2769E which says The transportPropagationConfig property of the security profile must be set to the name of of a security identity that has been defined using the mqsisetdbparms or mqsicredentials command. </br>
<img src="https://imgpile.com/images/bykbmo.png" alt="Untitled" border="0"></br>

### Step 5:
In the Application, select the HTTP Request Node, go to Security tab and configure the Security profile as shown. The name must be configured as {PolicyProject}:PolicyName. Once the Security profile is configured, re-deploy the application (make sure the Policy is still deployed).
<img src="https://imgpile.com/images/bykfi4.png" alt="Untitled" border="0"></br>

### Step 6:
Redeploying the application and testing. It should be successful.
<img src="https://imgpile.com/images/bykVZh.png" alt="Untitled" border="0"></br>
