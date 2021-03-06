package RSA;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.util.Base64;

public class RSAKeyPairGenerator {

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private int KeySize = 515; 

    public RSAKeyPairGenerator(int KeySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KeySize);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void writeToFile(String path, Object key) throws IOException {
        File chave = new File(path);
        chave.getParentFile().mkdirs();
        chave.createNewFile();
        
        ObjectOutputStream chaveOS = new ObjectOutputStream(new FileOutputStream(chave));
        chaveOS.writeObject(key);
        chaveOS.close();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public void setKeySize(String KeySize) {
        this.KeySize = Integer.parseInt(KeySize);
    }
    
//    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
//        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
//        keyPairGenerator.writeToFile("RSA/publicKey", keyPairGenerator.getPublicKey().getEncoded());
//        keyPairGenerator.writeToFile("RSA/privateKey", keyPairGenerator.getPrivateKey().getEncoded());
//        System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded()));
//        System.out.println(Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));
//    };;
}