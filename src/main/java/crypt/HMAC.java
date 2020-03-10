package crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HMAC {

    private static final byte iPad = 0x36;
    private static final byte oPad = 0x5c;
    private static final byte blocksize = 64; // The block size of the underlying hash function
    private static final byte zero = 0x00;
    private static String hashFunc = "SHA-256"; // The hash function to use

    static byte[] HMACSHA256(byte[] message, byte[] key) throws NoSuchAlgorithmException { // Array of bytes

        MessageDigest messageDigest = MessageDigest.getInstance(hashFunc);

        if (key.length > blocksize) {  // Keys longer than blockSize are shortened by hashing them
            key = messageDigest.digest(key);
            messageDigest.reset();
        }

        byte[] IKeyPad = new byte[blocksize];
        for (int i = 0; i < blocksize; i++) {
            if (i < key.length)
                IKeyPad[i] = (byte) (key[i] ^ iPad); // Inner padded key
            else
                IKeyPad[i] = (byte) (zero ^ iPad); // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
        }

        byte[] IKeyPadConcatenationMessage = concatenationArrayOfBytes(IKeyPad, message);
        messageDigest.update(IKeyPadConcatenationMessage);

        byte[] hashIkeyPadConcatenationMessage = messageDigest.digest();
        messageDigest.reset();

        byte[] OKeyPad = new byte[blocksize];
        for (int i = 0; i < blocksize; i++) {
            if (i < key.length)
                OKeyPad[i] = (byte) (key[i] ^ oPad); // Outer padded key
            else
                OKeyPad[i] = (byte) (zero ^ oPad); // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
        }

        byte[] OKeyPadConcatenationMessage = concatenationArrayOfBytes(hashIkeyPadConcatenationMessage, OKeyPad); //function realized on 55
        messageDigest.update(OKeyPadConcatenationMessage);

        byte[] hashOKeyPadConcatenationMessage = messageDigest.digest();
        messageDigest.reset();

        return hashOKeyPadConcatenationMessage; // this is hmac
    }

    static byte[] concatenationArrayOfBytes(final byte[] ArrayOfBytes, final byte[] ArrayOfBytesOther) {

        byte[] concatenationOfBytes = new byte[ArrayOfBytes.length + ArrayOfBytesOther.length];

        System.arraycopy(ArrayOfBytes, 0, concatenationOfBytes, 0, ArrayOfBytes.length);
        System.arraycopy(ArrayOfBytesOther, 0, concatenationOfBytes, ArrayOfBytes.length, ArrayOfBytesOther.length);

        return concatenationOfBytes;
    }

    static byte[] byteAppendToArrayOfBytes(final byte[] bytesArray, final byte iByte) { // used in HKDF

        byte[] concatenationOfBytes = new byte[bytesArray.length + 1];

        System.arraycopy(bytesArray, 0, concatenationOfBytes, 0, bytesArray.length);
        concatenationOfBytes[bytesArray.length] = iByte;

        return concatenationOfBytes;
    }
}
