# APKSignReader Java old

This tool is to read sign and generate hash, purposely used for signature killers. It is based on [fourbrother/kstools](https://github.com/fourbrother/kstools)，在其基础上进行了部分改进，并用纯 

**This tool does not support signature scheme v2 and above, please use new [APKSignReader-Java](https://github.com/AndnixSH/APKSignReader-Java)**

# How to fix cannot access class sun.security.pkcs.PKCS7.txt

Simply use this command

`java -jar --add-exports=java.base/sun.security.x509=ALL-UNNAMED --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-exports=java.base/sun.security.util=ALL-UNNAMED --add-exports=java.base/sun.security.pkcs=ALL-UNNAMED APKSignReader-Old.jar (APK file)`