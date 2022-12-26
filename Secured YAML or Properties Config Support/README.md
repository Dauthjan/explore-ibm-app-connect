# Using (Secured) YAML or Properties Config file as a DataStore in IBM App Connect Enterprise

This document demonstrates and implements a concept of using YAML or Properties file to use as a DataStore for lookup. Changing the config will *not* require the application to be redeployed or restarted. This can minimize maintenance time for an application as well as develop re-usable codes that can be dynamically configured. 
Features Implemented:
- Support for YAML or Properties config file
- Supports AES/CBC/PKCS5PADDING decryption [both – key level (similar to this) and file level (similar to this) decryption support]
- Local caching for better performance
- Auto-detect changes in config file. This reloads the config without redeploying/restarting application.
- YAML files can be bundled within BAR and hence no separate deployment/placing of files required. Properties file can be placed in the server running the ACE application.

### Understanding the flow-chart for implementation (simple version - not showing decryption capabilities)
<p align="center">
<a href="https://ibb.co/BySyHpc"><img src="https://i.ibb.co/sKMKpfb/Untitled.png" alt="Untitled" border="0"></a>
</p>

### How to use stored Key-Value pairs
<p align="center">
<a href="https://ibb.co/1QhWbWb"><img src="https://i.ibb.co/028bQbQ/Untitled.png" alt="Untitled" border="0"></a>
</p>

### Implementation:
Created a Subflow with 5 User Defined Properties as shown in the picture.
<p align="center">
<a href="https://ibb.co/wY5GcRm"><img src="https://i.ibb.co/QXySDfw/Untitled.png" alt="Untitled" border="0"></a>
</p>

### Testing with a Message Flow
Created a message flow which will read app-dev.conf.yaml. The YAML contains 2 backend details (postman and httpbin). Depending on the flag enabled, we will dynamically invoke the backends. The backends are Basic-Auth protected and hence require a username and password to invoke successfully. *Stored the password after encrypting. Key (and Vector) used for encryption – AESEncryptionKey*
Supported Operations in the Test message Flow:</br>
`POST` http://localhost:7800/mylookupflow - invoke backends based on enabled flag. Backend error (in case of Auth failure will generate an exception)</br>
`GET` http://localhost:7800/mylookupflow ?key=*{key_to_extract}* - this is to test if the key-values are extracted correctly (decrypted in case values are encrypted)</br>
<p align="center">
    <a href="https://imgbb.com/"><img height="200" src="https://i.ibb.co/Lg0vWyB/Untitled.png" alt="Untitled" border="0"></a>
    <a href="https://imgbb.com/"><img height="300" src="https://i.ibb.co/vQr1LVB/Untitled.png" alt="Untitled" border="0"></a>
</p>

### Test 1:
Retrieving a key-value using `GET` method</br>
<a href="https://ibb.co/2j3b23X"><img height="250" src="https://i.ibb.co/P5GSpGB/Untitled.png" alt="Untitled" border="0"></a>

### Test 2:
Retrieving a secured key-value using `GET` method (`password` is the decrypted value of `FZ87o1JZchI2kjQ/lzX2hg==`)</br>
<a href="https://ibb.co/SX4w5Tq"><img height="250" src="https://i.ibb.co/pvBjbDC/Untitled.png" alt="Untitled" border="0"></a>

### Test 3:
Invoking Message Flow with `POST` method. `postman.enabled` is `true` and `httpbin.enabled` is `false`. *Expected result*: only Postman backend will be invoked and final `response` will be `1 backend(s) invoked`.
<a href="https://ibb.co/HKWzVVm"><img height="290" src="https://i.ibb.co/VL7SttX/Untitled.png" alt="Untitled" border="0"></a></br>
<a href="https://ibb.co/jvWNKwf"><img height="250" src="https://i.ibb.co/d0LT9pM/Untitled.png" alt="Untitled" border="0"></a></br>

### Test 4:
Invoking Message Flow with `POST` method. `postman.enabled` is true and `httpbin.enabled` is `true`. *Expected result*: Postman and HTTPBin backends will be invoked and final `response` will be `2 backend(s) invoked`. Application was *not* redeployed or restarted, only config was edited.</br>
<a href="https://ibb.co/HKWzVVm"><img height="290" src="https://i.ibb.co/VL7SttX/Untitled.png" alt="Untitled" border="0"></a></br>
<a href="https://ibb.co/7C9tzSk"><img height="283" src="https://i.ibb.co/vqt4BcX/Untitled.png" alt="Untitled" border="0"></a></br>
<a href="https://ibb.co/8X0yg9b"><img height="250" src="https://i.ibb.co/st2T9qC/Untitled.png" alt="Untitled" border="0"></a></br>

### Test 5:
Testing with full encrypted file. Changing the User Defined Variable values as shown. Since the app-dev.conf-secured.yaml consists of encrypted values, for reference, app-dev.conf-unsecured.yaml contains the same data in unencrypted format. Using this to retrieve key-value pairs to check if decryption works as expected.</br>
<a href="https://ibb.co/MCGyNwZ"><img height="390" src="https://i.ibb.co/G5tfPYn/Untitled.png" alt="Untitled" border="0"></a></br>

Invoked the service refering the keys from app-dev.conf-unsecured.yaml and matching with the expected results. The response received and response expected matched. Hence, the encrypted file (entire file and not just the values of the Key) was decrypted successfully.</br>
<a href="https://ibb.co/YkhD6ns"><img height="450" src="https://i.ibb.co/6PFv29C/Untitled.png" alt="Untitled" border="0"></a>
