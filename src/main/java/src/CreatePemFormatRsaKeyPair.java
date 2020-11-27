package src;

import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CreatePemFormatRsaKeyPair {

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        PPKeys keys = createKeys(2048);

        try {
            saveKeyToFile("MyPub.pem", keys.getPublicKey().getBytes());
            saveKeyToFile("MyPrv.pem", keys.getPrivatekey().getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PPKeys createKeys(int keySize) throws Exception {
        PPKeys keys = new PPKeys();

        // Create keyPair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();


        // Convert PrivateKey to PEM format
        StringWriter privateWrite = new StringWriter();
        PEMWriter privatePemWriter = new PEMWriter(privateWrite);

        privatePemWriter.writeObject(keyPair.getPrivate());
        privatePemWriter.close();

        keys.setPrivatekey(privateWrite.toString());
        privatePemWriter.close();
        privateWrite.close();


        // Convert PublicKey to PEM format
        StringWriter publicWrite = new StringWriter();
        PEMWriter publicPemWriter = new PEMWriter(publicWrite);

        publicPemWriter.writeObject(keyPair.getPublic());
        publicPemWriter.close();

        keys.setPublicKey(publicWrite.toString());
        publicPemWriter.close();
        publicWrite.close();


        return keys;
    }


    public static String encrypt(String publicKeyPem, String plainText) throws Exception {

        // Read PEM Format
        PemReader pemReader = new PemReader(new StringReader(publicKeyPem));
        byte[] content = pemReader.readPemObject().getContent();
        // Get X509EncodedKeySpec format
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(content);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKeySecret = kf.generatePublic(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeySecret);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        return new String(Base64.encode(encryptedBytes));
    }

    public static String decrypt(String privateKeyPem, String encryptedString) throws Exception {
        // Read PEM Format
        PemReader pemReader = new PemReader(new StringReader(privateKeyPem));
        PemObject pemObject = pemReader.readPemObject();
        pemReader.close();

        // Get PKCS8EncodedKeySpec for decrypt
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKeySecret = kf.generatePrivate(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKeySecret);
        return new String(cipher.doFinal(Base64.decode(encryptedString)), "UTF-8");

    }

    private static void saveKeyToFile(String fileName, byte[] key) throws IOException {
        File file = new File(fileName);
        FileOutputStream out = new FileOutputStream(file);
        out.write(key);
        out.flush();
        out.close();
    }

}