package cc.binmt.signature;

import bin.util.StreamUtil;
import bin.zip.ZipEntry;
import bin.zip.ZipFile;
import sun.security.pkcs.PKCS7;
import java.io.*;
import java.security.cert.Certificate;
import java.util.*;

public class NKillSignatureTool {

    private static byte[] signatures;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Please input APK file");
            return;
        }
        signatures = getApkSignatureData(new File(args[0]));
        System.out.println(Base64.getEncoder().encodeToString(signatures));
    }

    private static byte[] getApkSignatureData(File apkFile) throws Exception {
        ZipFile zipFile = new ZipFile(apkFile);
        Enumeration<ZipEntry> entries = zipFile.getEntries();
        while (entries.hasMoreElements()) {
            ZipEntry ze = entries.nextElement();
            String name = ze.getName().toUpperCase();
            if (name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA"))) {
                PKCS7 pkcs7 = new PKCS7(StreamUtil.readBytes(zipFile.getInputStream(ze)));
                Certificate[] certs = pkcs7.getCertificates();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(baos);
                dos.write(certs.length);
                //System.out.printf("  --cert length[%d]\n", certs.length);

                for (int i = 0; i < certs.length; i++) {
                    byte[] data = certs[i].getEncoded();
                    //System.out.printf("  --SignatureHash[%d]: %08x\n", i, Arrays.hashCode(data));
                    //System.out.printf("  --data length[%d]\n", data.length);

                    dos.writeInt(data.length);
                    dos.write(data);
                }
                return baos.toByteArray();
            }
        }
        throw new Exception("META-INF/XXX.RSA (DSA) file not found.");
    }
}
