package crypt;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class HKDF {

    private static HMAC hmac;
    private static byte[] lastKey = null;
    private static byte[] iSymmetricKey = null;
    private static byte[] hkdfKey = null;
    private static List<byte[]> hkdfKeyListOfBytes = new ArrayList<>();
    private static int expectedHKDFBytesSize = 32;

    public static List<byte[]> getHkdfKeyListOfBytes(byte[] xts, byte[] skm, byte[] ctx, int iterations) throws IOException, NoSuchAlgorithmException {
        byte[] prk = HKDFExtract(xts, skm);

        for (int i = 0; i <= iterations; i ++) {
            hkdfKey = HKDFExpand(prk, lastKey, ctx, i);

            if (hkdfKey.length != expectedHKDFBytesSize) {
                throw new IOException("HKDF Key Size is unavailable!!");
            } else {
                hkdfKeyListOfBytes.add(i, HKDFExpand(prk, lastKey, ctx, i));
                lastKey = hkdfKeyListOfBytes.get(i);
            }
        }
        return hkdfKeyListOfBytes;
    }

    private static byte[] HKDFExtract(byte[] xts, byte[] skm) throws NoSuchAlgorithmException { //xts is salt, skm - key material
        return HMAC.HMACSHA256(xts,skm); //gets prk key
    }

    private static byte[] HKDFExpand(byte[] prk, byte[] lastKey, byte[] ctx, int i) throws NoSuchAlgorithmException { //main logic is here
        byte iByte = (byte)(i);

        if (i == 0) {
            byte[] concatenationCTXi = HMAC.byteAppendToArrayOfBytes(ctx, iByte);
            iSymmetricKey = HMAC.HMACSHA256(prk,concatenationCTXi);
        }
        else {
            byte[] concatenationKCTX = HMAC.concatenationArrayOfBytes(lastKey, ctx);
            byte[] concatenationKCTXi = HMAC.byteAppendToArrayOfBytes(concatenationKCTX, iByte);
            iSymmetricKey = HMAC.HMACSHA256(prk,concatenationKCTXi);
        }
        return iSymmetricKey; //symmetric key
    }
}
