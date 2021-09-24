package RSA;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;


public class EncriptaDecriptaRSA {

  public static String ALGORITHM = "RSA";
  
  public static String cipherInstance = "";
  
  public static PublicKey chavePub = null;
  public static PrivateKey chavePri = null;

  public static String getPublicKey(String path) {
      String chave = "";
      try {
        ObjectInputStream inputStream = null;

        inputStream = new ObjectInputStream(new FileInputStream(path));
        chavePub = (PublicKey) inputStream.readObject();
        chave = Base64.getEncoder().encodeToString(chavePub.getEncoded());
      } catch (Exception e) {
          
      }
      
      return chave;
  }
  
  public static String getPrivateKey(String path) {
      String chave = "";
      try {
        ObjectInputStream inputStream = null;
        
        inputStream = new ObjectInputStream(new FileInputStream(path));
        chavePri = (PrivateKey) inputStream.readObject();
        chave = Base64.getEncoder().encodeToString(chavePri.getEncoded());
      } catch (Exception e) {
          
      }
      
      return chave;
  }
  
  public static void setPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            chavePub = publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        chavePub = publicKey;
    }

    public static void setPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        chavePri = privateKey;
    }
  
  public static String criptografa(String texto) {
    byte[] cipherText = null;

    try {
      
      final Cipher cipher = Cipher.getInstance(cipherInstance);
      // Criptografa o texto puro usando a chave P�lica
      cipher.init(Cipher.ENCRYPT_MODE, chavePub);
      cipherText = cipher.doFinal(texto.getBytes());
    } catch (Exception e) {
      e.printStackTrace();
    }

    return Base64.getEncoder().encodeToString(cipherText);
  }

  public static String decriptografa(byte[] texto) throws UnsupportedEncodingException {
    byte[] dectyptedText = null;

    try {   
      final Cipher cipher = Cipher.getInstance(cipherInstance);
      cipher.init(Cipher.DECRYPT_MODE, chavePri);
      dectyptedText = cipher.doFinal(texto);

    } catch (Exception ex) {
      ex.printStackTrace();
    }
    
    return new String (dectyptedText, "ISO-8859-1");
    
  }
}