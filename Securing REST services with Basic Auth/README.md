# How to secure an HTTP Service in IBM ACE and using Basic Auth

This document demonstrates the capability of securing an HTTP(s) service using Basic Auth. Although Basic Auth is not generally used in production environments (securing the APIs is majorly handled by API Management Tools like IBM API Connect), it is worth learning.

### Step 1: 
Creating a simple HTTP Service
<img src="https://imgpile.com/images/byk0nW.png" alt="Untitled" border="0"></br>
The service transforms an XML to JSON. As shown, the service works without Authorization. </br>
<img src="https://imgpile.com/images/bykFZL.png" alt="Untitled" border="0"></br>

### Step 2: 
Creating a Policy Project which contains the Policy. Notice the Authentication configuration is configured with thevalue of MyAppBasicAuth. We must set the security credential with the same name. We can use mqsisetdbparmscommand, IBM ACE’s vault or configure credentials in the server.conf.yaml.
<img src="https://imgpile.com/images/byk3vo.png" alt="Untitled" border="0"></br>
Below snapshot shows the configuration of MyAppBasicAuth in server.conf.yaml. Once configured, restart the Integration Server.</br>
<img src="https://imgpile.com/images/bykex3.png" alt="Untitled" border="0"></br>

### Step 3: 
Validate the credential is available or not – I have used WebUI to validate. Once the Credential is available, we can configure the Policy to our Service.
<img src="https://imgpile.com/images/by0nhF.png" alt="Untitled" border="0"></br>

### Step 4: 
In the Application, select the HTTP Input Node, go to Security tab and configure the Security profile as shown. The name must be configured as {PolicyProject}:PolicyName. Once the Security profile is configured, re-deploy the application (make sure the Policy is still deployed). 
<img src="https://imgpile.com/images/by0UW4.png" alt="Untitled" border="0"></br>

### Step 5: 
Testing the service – we get HTTP 401 Unauthorized. This means that the service now needs an Authorization.  
<img src="https://imgpile.com/images/by0C3r.png" alt="Untitled" border="0"></br>

### Step 6: 
Added the Basic Authorization HTTP Header to invoke the service, the service works as expected. 
<img src="https://imgpile.com/images/by0G5R.png" alt="Untitled" border="0"></br>