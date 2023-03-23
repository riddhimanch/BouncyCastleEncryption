import java.io.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import javax.crypto.spec.*;

public class App {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        /*read key from a file */
        String fileName = "secretkey.txt";
        byte[] keyBytes = readSecretKeyFromFile(fileName);
        Key secretKey = new SecretKeySpec(keyBytes, "AES");
        
        // Create cipher object for decryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        //cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        
        
        
        
        // Read encrypted input file
        File encryptedFile = new File("output.enc");
        FileInputStream inputStream = new FileInputStream(encryptedFile);
        byte[] encryptedInputBytes = new byte[(int) encryptedFile.length()];
        inputStream.read(encryptedInputBytes);
        inputStream.close();
        
        // Decrypt input file and write output file
        byte[] decryptedBytes = cipher.doFinal(encryptedInputBytes);
        FileOutputStream outputStream = new FileOutputStream("output.txt");
        outputStream.write(decryptedBytes);
        outputStream.close();
        
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
