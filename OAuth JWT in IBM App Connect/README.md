# JWT Implementation for IBM App Connect Enterprise

This document demonstrates and implements a concept of JWT protected API without depending on any API Manager. The implementation is inspired from the [JWT Validation Policy in MuleSoft](https://docs.mulesoft.com/gateway/1.4/policies-included-jwt-validation) and utilized IBM ACE's own User Defined policy to replicate the behaviour. Creating the User Defined Policy is tricky hence use the [Web GUI utility](http://ibmacejwt.rf.gd/) specialy designed for generating the JWT Policy.

Features Implemented:
- Support of various popular JWT Signing Method (RSA, PS, ES, ED, HMAC) and unsigned method (although rarely used).
- Supports JWKS from URL, File System or in-lined. Supports Certificate and Public Key (File System and in-lined).
- Local caching of URL fetched JWKS for better performance (retry implemented for rotating signing key).
- Signature verification using locally file system stored Public Key or Certificate.

### Understanding the flow-chart of JWT (generation and verification)
<p align="center">
<a href="https://ibb.co/GJ1F5Sc"><img src="https://i.ibb.co/6ZpNWCg/krakend-signer-flow.png" alt="krakend-signer-flow" border="0"></a>
</p>

### Implementation:
Created a Message flow for testing the JWT verification. The actual verification is done by the `JWTValidation subflow` which needs a JWT Validation policy.
<p align="center">
<a href="https://ibb.co/YkT5719"><img src="https://i.ibb.co/2tYz7C2/verifier-flow.png" alt="verifier-flow" border="0"></a>
</p>

### Testing with a Message Flow
Two test cases are shown here, 97 test cases executed using various tokens and signing algorithm. For detailed test case report, refer the [README PDF](https://github.com/Dauthjan/explore-ibm-app-connect/tree/main/OAuth%20JWT%20in%20IBM%20App%20Connect/README%20-%20OAuth%20JWT%20for%20IBM%20App%20Connect%20Enterprise.pdf)</br>
```shell
curl --location 'http://localhost:7800/myjwtvalidator' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{token}}' \
--data '{
    "firstName": "Dipanjan",
    "lastName": "Das"
}'
```
</br>
<p align="center">
    <a href="https://ibb.co/TgQj48G"><img src="https://i.ibb.co/LZTjxty/testing.png" alt="testing" border="0"></a>
</p>
