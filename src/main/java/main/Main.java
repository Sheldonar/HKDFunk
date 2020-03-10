package main;

import crypt.HKDF;
import crypt.HMAC;
import crypt.PBKDF2;
import filemanager.Parser;
import org.json.simple.parser.ParseException;
import org.scalastuff.json.JsonParser;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.PseudoColumnUsage;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Main {

    private static String ctx = "FedorMFGerasimov"; //context is my name
    private static int iterations = 1000; //number of keys
    private static int saltBytesSize = 16; //salt size
    private static String secureRandomAlgorithm = "NativePRNG";
    private static int bitsCount = 5;

    public static  void main(String[] args) throws IOException, NoSuchAlgorithmException, ParseException {

        byte[] salt = getSalt();
        byte[] ctxBytes = ctx.getBytes();

        String weatherContent = Parser.getWeather();
        byte[] skm = weatherContent.getBytes(); // material - the whole json

        List<byte[]> weatherGist = Collections.singletonList(weatherContent.getBytes()); // for gistagramm purposes
        Parser.getXXBits(weatherGist, bitsCount);

        List<byte[]> HKDFKeys = HKDF.getHkdfKeyListOfBytes(salt, skm, ctxBytes, iterations); // HKDF is done

        //System.out.println(HKDFKeys); // bytes to console
        //HKDFKeys.forEach(b->Stream.of(b).map(String::valueOf).map(s -> s.charAt(3)).forEach(System.out::println));
        //List<String> strings = HKDFKeys.stream().flatMap(Stream::of).map(String::valueOf).map(s -> s.substring(3,7)).collect(Collectors.toList());
        //System.out.println(String.join(" ", strings));

        Parser.getXXBits(HKDFKeys, bitsCount); // This goes to GIST keys hkdf

        List<String> listPasswords = Parser.getPasswords();
        List<byte[]> PBKDF2Keys = new ArrayList<>();
        for (String listPassword : listPasswords) {
            byte[] password = listPassword.getBytes();
            byte[] pbkdf2Key = PBKDF2.getPBKDF2Key(password);
            PBKDF2Keys.add(pbkdf2Key);
            Parser.getXXBits(password, bitsCount); // passwords to gist
        }
        //System.out.println(PBKDF2Keys); //console
        //System.out.println(PBKDF2Keys.toString());

        Parser.getXXBits(PBKDF2Keys, bitsCount); // this also goes to gist keys pbkdf2


    }

    private static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance(secureRandomAlgorithm);
        byte[] salt = new byte[saltBytesSize];
        sr.nextBytes(salt);

        return salt;
    }

}
