# APKSignReader Java old

This tool is to read sign and generate hash, purposely used for signature killers. It is based on [fourbrother/kstools](https://github.com/fourbrother/kstools)，在其基础上进行了部分改进，并用纯 

**This tool does not support signature scheme v2 and above, please use new [APKSignReader-Java](https://github.com/AndnixSH/APKSignReader-Java)**

# Usage

`java -jar APKSignReader-Old.jar (APK file)`

### How to fix cannot access class sun.security.pkcs.PKCS7.txt

If you use Java 9 and above and you got "cannot access class" error, simply use this command

`java -jar --add-exports=java.base/sun.security.x509=ALL-UNNAMED --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/sun.security.util=ALL-UNNAMED --add-exports=java.base/sun.security.pkcs=ALL-UNNAMED APKSignReader-Old.jar (APK file)`