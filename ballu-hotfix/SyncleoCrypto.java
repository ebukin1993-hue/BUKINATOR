package com.ballucontrol.local;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Syncleo protocol v2 X25519 / SHA-256 / AES-128-CBC implementation.
 * Compatible with Android 13+ Conscrypt and standard JDK XDH.
 *
 * Android Conscrypt's XDH key generator does not accept NamedParameterSpec.
 * Its X25519 public key does not implement XECPublicKey, and its KeyFactory
 * accepts X509EncodedKeySpec. Use RFC 8410 SubjectPublicKeyInfo throughout.
 */
public final class SyncleoCrypto {
    private SyncleoCrypto() {}

    private static final byte[] X25519_SPKI_PREFIX = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
        0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
    };

    public static final class Keys {
        public final byte[] appPublicWire;
        public final byte[] h0;
        public final byte[] h1;
        Keys(byte[] pub,byte[] a,byte[] b){appPublicWire=pub;h0=a;h1=b;}
    }

    public static final class CryptoStageException extends Exception {
        public final String stage;
        CryptoStageException(String stage,Exception cause){super(stage,cause);this.stage=stage;}
    }

    public static Keys newSessionKeys(byte[] devicePublicWire) throws Exception {
        if(devicePublicWire==null||devicePublicWire.length!=32)
            throw new IllegalArgumentException("X25519 public key must be 32 bytes");
        final KeyPair pair;
        try {
            // Android Conscrypt automatically picks X25519 for XDH.
            // Do NOT initialize with NamedParameterSpec(X25519).
            pair=KeyPairGenerator.getInstance("XDH").generateKeyPair();
        } catch(Exception ex){throw new CryptoStageException("XDH_KEYPAIR",ex);}

        final byte[] appWire;
        try {
            byte[] publicLe=rawPublicFromSpki(pair.getPublic().getEncoded());
            // Syncleo expects the application's public coordinate in BE order.
            appWire=reverse(publicLe);
        } catch(Exception ex){throw new CryptoStageException("XDH_PUBLIC_EXPORT",ex);}

        final PublicKey peer;
        try {
            // Syncleo device advertises its coordinate in BE; standard XDH
            // X.509 SPKI stores the 32-byte u-coordinate little-endian.
            byte[] peerSpki=spkiForRawPublic(reverse(devicePublicWire));
            peer=KeyFactory.getInstance("XDH").generatePublic(
                new X509EncodedKeySpec(peerSpki));
        } catch(Exception ex){throw new CryptoStageException("XDH_PEER_IMPORT",ex);}

        final byte[] sharedLe;
        try {
            KeyAgreement agreement=KeyAgreement.getInstance("XDH");
            agreement.init(pair.getPrivate());
            agreement.doPhase(peer,true);
            sharedLe=agreement.generateSecret();
            if(sharedLe.length!=32)
                throw new IllegalStateException("Unexpected X25519 secret length");
        } catch(Exception ex){throw new CryptoStageException("XDH_EXCHANGE",ex);}

        try {
            byte[] digest=MessageDigest.getInstance("SHA-256").digest(reverse(sharedLe));
            return new Keys(appWire,Arrays.copyOfRange(digest,0,16),
                Arrays.copyOfRange(digest,16,32));
        } catch(Exception ex){throw new CryptoStageException("SHA256_DERIVE",ex);}
        finally {Arrays.fill(sharedLe,(byte)0);}
    }

    static byte[] spkiForRawPublic(byte[] rawLe){
        if(rawLe==null||rawLe.length!=32)
            throw new IllegalArgumentException("Expected 32-byte X25519 coordinate");
        byte[] result=Arrays.copyOf(X25519_SPKI_PREFIX,44);
        System.arraycopy(rawLe,0,result,12,32);
        return result;
    }

    static byte[] rawPublicFromSpki(byte[] encoded){
        if(encoded==null||encoded.length!=44)
            throw new IllegalArgumentException("Unexpected X25519 SPKI length");
        for(int i=0;i<12;i++)if(encoded[i]!=X25519_SPKI_PREFIX[i])
            throw new IllegalArgumentException("Unexpected X25519 SPKI prefix");
        return Arrays.copyOfRange(encoded,12,44);
    }

    static byte[] reverse(byte[] input){
        byte[] out=input.clone();
        for(int i=0,j=out.length-1;i<j;i++,j--){
            byte tmp=out[i];out[i]=out[j];out[j]=tmp;
        }
        return out;
    }

    static byte[] rotl(byte[] src,int count){
        byte[] out=new byte[src.length];
        int n=count&15;
        for(int i=0;i<src.length;i++)out[i]=src[(i+n)%src.length];
        return out;
    }

    static byte[] aes(boolean encrypt,byte[] key,byte[] iv,byte[] data) throws Exception {
        if(data.length%16!=0)throw new IllegalArgumentException("AES-CBC must be block aligned");
        Cipher cipher=Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,
            new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    static byte[] pad(byte[] raw){
        int n=16-raw.length%16;
        byte[] out=Arrays.copyOf(raw,raw.length+n);
        Arrays.fill(out,raw.length,out.length,(byte)n);
        return out;
    }

    static byte[] unpad(byte[] raw) throws Exception {
        if(raw.length==0)throw new Exception("Empty padded frame");
        int n=raw[raw.length-1]&255;
        if(n<1||n>16||n>raw.length)throw new Exception("Invalid AES PKCS7 padding");
        for(int i=raw.length-n;i<raw.length;i++)
            if((raw[i]&255)!=n)throw new Exception("Invalid AES PKCS7 block");
        return Arrays.copyOf(raw,raw.length-n);
    }

    public static byte[] fromHex(String value){
        String s=value.replaceAll("[\\s:-]","");
        if((s.length()&1)!=0)throw new IllegalArgumentException("Нечётная длина ключа");
        byte[] out=new byte[s.length()/2];
        for(int i=0;i<out.length;i++){
            int a=Character.digit(s.charAt(2*i),16),b=Character.digit(s.charAt(2*i+1),16);
            if(a<0||b<0)throw new IllegalArgumentException("Неверный hex-ключ");
            out[i]=(byte)((a<<4)|b);
        }
        return out;
    }

    public static String hex(byte[] raw){
        char[] chars="0123456789abcdef".toCharArray();
        char[] out=new char[raw.length*2];
        for(int i=0;i<raw.length;i++){
            int b=raw[i]&255;
            out[i*2]=chars[b>>>4];out[i*2+1]=chars[b&15];
        }
        return new String(out);
    }
}
