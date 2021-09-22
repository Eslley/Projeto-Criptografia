package RSA;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;


public class EncriptaDecriptaRSA {

  public static String ALGORITHM = "RSA";
  
  public static String cipherInstance = "";
  
  public static PublicKey chavePub;
  public static PrivateKey chavePri;

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

  /**
   * Decriptografa o texto puro usando chave privada.
   */
  public static String decriptografa(byte[] texto) {
    byte[] dectyptedText = null;

    try {   
      final Cipher cipher = Cipher.getInstance(cipherInstance);
      // Decriptografa o texto puro usando a chave Privada
      cipher.init(Cipher.DECRYPT_MODE, chavePri);
      dectyptedText = cipher.doFinal(texto);

    } catch (Exception ex) {
      ex.printStackTrace();
    }

    //return Base64.getDecoder().decode(dectyptedText);
    return Base64.getEncoder().encodeToString(dectyptedText);
    
  }
}