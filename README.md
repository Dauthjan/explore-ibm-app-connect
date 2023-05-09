<p align="center">
  <img height="90" src="http://rhc4tp-cms-prod-vpc-76857813.s3.amazonaws.com/s3fs-public/icon_256x256.png" />
</p>

# Exploring IBM App Connect Enterprise

## Disclaimer
The intent of these samples is to demonstrate some of the features of IBM App Connect Enterprise. The implementations are provided 'as is' and without warranty of any kind. If you find issues with the implementations, please add a comment to the post that describes use of the feature. Feel free to contribute.

## Explored List

* [Securing REST services with Basic Auth](https://github.com/Dauthjan/explore-ibm-app-connect/tree/main/Securing%20REST%20services%20with%20Basic%20Auth)
> Example to demonstrate how to host an HTTP service that is Basic Auth protected using Policy. For invoking a REST API with Basic Auth using Policy, check [this](https://github.com/Dauthjan/explore-ibm-app-connect/tree/main/Invoking%20a%20REST%20API%20with%20Basic%20Auth%20using%20Policy). Used IBM App Connect Enterprise 12.0.6.0 on Windows 11. 

* [Invoking a REST API with Basic Auth using Policy](https://github.com/Dauthjan/explore-ibm-app-connect/tree/main/Invoking%20a%20REST%20API%20with%20Basic%20Auth%20using%20Policy)
> Example to demonstrate how to consume an HTTP service that is Basic Auth protected using Policy. This is a continuation of (and demonstration is dependent on) [Securing REST services with Basic Auth](https://github.com/Dauthjan/explore-ibm-app-connect/tree/main/Securing%20REST%20services%20with%20Basic%20Auth). Used IBM App Connect Enterprise 12.0.6.0 on Windows 11.

* [Secured YAML or Properties Config Support](https://github.com/Dauthjan/explore-ibm-app-connect/tree/main/Secured%20YAML%20or%20Properties%20Config%20Support)
> Implementation of configuring applications using config YAML or Properties which can change the behavior of application dynamically without redeploying. </br>
> This implementation supports (AES) sercured properties similar to [Secure Configuration in MuleSoft](https://docs.mulesoft.com/mule-runtime/4.4/secure-configuration-properties#define-secure-configuration-properties-in-the-file). The implementation also supports [Encrypt All the Content of a File](https://docs.mulesoft.com/mule-runtime/4.4/secure-configuration-properties#encrypt-all-the-content-of-a-file) similar to MuleSoft. Used IBM App Connect Enterprise 12.0.6.0 on Windows 11.

* [OAuth JWT in IBM App Connect](https://github.com/Dauthjan/explore-ibm-app-connect/tree/main/OAuth%20JWT%20in%20IBM%20App%20Connect)
> Experimental implementation of JWT validation on IBM App Connect Enterprise using User Defined Policy. </br>
> This implementation is an attempt to create a JWT Policy similar to  [JWT Validation Policy in MuleSoft](https://docs.mulesoft.com/gateway/1.4/policies-included-jwt-validation). The implementation only brings support of JWS (Signed JWT) and not JWE (Encrypted JWT). Used IBM App Connect Enterprise 12.0.8.0 on Windows 11.