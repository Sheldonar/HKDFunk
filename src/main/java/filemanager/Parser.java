package filemanager;

import org.apache.commons.io.FileUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;


public class Parser {
    private static String pathToWeather = "/Users/fedorg/IdeaProjects/HKDFunk/src/main/resources/weather.json";
    private static String pathToPasswords = "/Users/fedorg/IdeaProjects/HKDFunk/src/main/resources/passwords.json";

    public static List<String> getPasswords() throws IOException, ParseException {

        FileReader fileReader = new FileReader(pathToPasswords);
        JSONParser jsonParser = new JSONParser();
        JSONObject jsonObject = (JSONObject) jsonParser.parse(fileReader);
        JSONArray passwords = (JSONArray) jsonObject.get("passwords");
        List<String> list = new ArrayList<String>();

        for (Object password : passwords) {
            list.add(password.toString());
        }
        return list;
    }

    public static String getWeather() throws IOException {
        File file = new File(pathToWeather);
        return FileUtils.readFileToString(file, "utf-8");

    }

    public static void getXXBits(byte[] key, int bitsCount) {
        BitSet hashBits = BitSet.valueOf(key);
        BitSet XXBits = hashBits.get(0, bitsCount);

        for (int i = 0; i < bitsCount; i++)
            if (XXBits.get((i)))
                System.out.print("1");
            else
                System.out.print("0");
        System.out.print("\n");
    }

    public static void getXXBits(List<byte[]> key, int bitsCount) { // this one gets first 5 bits

        for (int j = 0; j < key.size(); j++){
            BitSet hashBits = BitSet.valueOf(key.get(j));
            BitSet XXBits = hashBits.get(0, bitsCount);

            for (int i = 0; i < bitsCount; i++)
                if (XXBits.get((i)))
                    System.out.print("1");
                else
                    System.out.print("0");
            System.out.print("\n");
        }
    }
}
