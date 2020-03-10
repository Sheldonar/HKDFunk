package crypt;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class PBKDF2 {

    private static HMAC hmac;

    private static byte[] block = null;
    private static byte[] pbkdf2Key = null;
    private static List<byte[]> listXorU = new ArrayList<>();
    private static int iterations = 10000;
    private static final double hmacLength = 32.0;
    private static int expectedPBKDF2BytesSize = 64;
    private static int saltBytesSize = 16;
    private static String secureRandomAlgorithm = "NativePRNG"; // is better than SHA1PRNG?

    public static byte[] getPBKDF2Key(byte[] password) throws IOException, NoSuchAlgorithmException {

        byte[] salt = getSalt();
        double quantityBlocks = expectedPBKDF2BytesSize / hmacLength;
        quantityBlocks = Math.ceil(quantityBlocks);

        for (int k = 0; k < quantityBlocks; k++) {
            byte kBytes = (byte) k;

            byte[] concatSalt_i = HMAC.byteAppendToArrayOfBytes(salt, kBytes);
            listXorU.add(0, HMAC.HMACSHA256(password, concatSalt_i));
            block = listXorU.get(0);

            for (int i = 1; i < iterations; i++) {
                listXorU.add(i, HMAC.HMACSHA256(password, listXorU.get(i - 1)));
                for (int j = 0; j < listXorU.get(i).length; j++)
                    block[j] = (byte) (block[j] ^ listXorU.get(i)[j]);
            }

            if (k == 0) pbkdf2Key = block;
            else pbkdf2Key = HMAC.concatenationArrayOfBytes(pbkdf2Key, block);
            listXorU.clear();
        }

        if (pbkdf2Key.length != expectedPBKDF2BytesSize) {
            throw new IOException("PBKDF2 Key Size is unavailable!!");
        }
        return pbkdf2Key;
    }

    private static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance(secureRandomAlgorithm);
        byte[] salt = new byte[saltBytesSize];
        secureRandom.nextBytes(salt);

        return salt;
    }
}
