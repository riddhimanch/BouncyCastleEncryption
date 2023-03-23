import java.io.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import javax.crypto.spec.*;

public class FileEncryption {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        /* Generate a key and initialization vector (IV)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
         */

        /*read key from a file */
        String fileName = "secretkey.txt";
        byte[] keyBytes = readSecretKeyFromFile(fileName);
        Key secretKey = new SecretKeySpec(keyBytes, "AES");
        
        // Create cipher object for encryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        //cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        // Read input file
        File inputFile = new File("input.txt");
        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int) inputFile.length()];
        inputStream.read(inputBytes);
        inputStream.close();
        
        // Encrypt input file and write output file
        byte[] encryptedBytes = cipher.doFinal(inputBytes);
        FileOutputStream outputStream = new FileOutputStream("output.enc");
        outputStream.write(encryptedBytes);
        outputStream.close();
        
        /*Decryption
        // Create cipher object for decryption
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        
        // Read encrypted input file
        File encryptedFile = new File("output.enc");
        inputStream = new FileInputStream(encryptedFile);
        byte[] encryptedInputBytes = new byte[(int) encryptedFile.length()];
        inputStream.read(encryptedInputBytes);
        inputStream.close();
        
        // Decrypt input file and write output file
        byte[] decryptedBytes = cipher.doFinal(encryptedInputBytes);
        outputStream = new FileOutputStream("output.txt");
        outputStream.write(decryptedBytes);
        outputStream.close();
         */
    }

    public static byte[] readSecretKeyFromFile(String fileName) {
        try (FileInputStream fis = new FileInputStream(fileName)) {
            byte[] keyBytes = new byte[fis.available()];
            fis.read(keyBytes);
            return keyBytes;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
