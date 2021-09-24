/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package AES;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author jhois
 */
public class AESUtil {

    /**
     *
     */
    public static String key = null;
    public static String mode = "ECB";
    private static final String initVector = "encryptionIntVec";

   public static void setPrivateKey(String privateKey){
        key = privateKey;
   }
   
    public static String encrypt(String value) {
            try {
                    IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
                    SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
                    byte[] encrypted = null;
                    
                    if(mode=="CBC"){
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
                        encrypted = cipher.doFinal(value.getBytes());
                    }else if(mode == "ECB"){
                        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
                        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
                        encrypted = cipher.doFinal(value.getBytes());
                    }
                    return Base64.getEncoder().encodeToString(encrypted);
            } catch (Exception ex) {
                    ex.printStackTrace();
            }
            return null;
    }
    
    public static String decrypt(String encrypted) throws Exception {
	
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        byte[] original = null;

        if(mode=="CBC"){
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
         }else if(mode == "ECB"){
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
         }
        return new String(original);
    }
}