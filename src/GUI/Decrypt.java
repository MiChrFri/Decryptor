package GUI;

import org.json.*;
import org.xml.sax.SAXException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static java.lang.Thread.sleep;


/**
 * Created by michael on 15/06/16.
 */
public class Decrypt {
    private JPanel myPanel;
    private JButton decryptButton;
    private JLabel outLabel;
    private JTextField filePath;
    static String IV = "AAAAAAAAAAAAAAAA";
    private String fileOutPath = "";
    JSONArray jsonarray = null;

    public Decrypt() {
        filePath.setText("/Users/michael/Desktop/");

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                if(decryptButton.getText().equals("read")) {
                    jsonarray = readJsonFile(filePath.getText());
                    outLabel.setText(String.valueOf(jsonarray).substring(0, 20) + "...");
                }
                else {
                    decrypt(jsonarray);
                }
            }
        });
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("Decrypt");
        frame.setContentPane(new Decrypt().myPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    public String rsaDecrypt(String cipherText) {
        String decrypted = "";

        String privateString = "";

        try {
            /**** create the key from the Strings ****/
            byte[] privateBytes = Base64.getMimeDecoder().decode(privateString.getBytes("utf-8"));
            PrivateKey privateKey = privateKeyFromBytes(privateBytes);

            /***** Decrypt *****/
            byte[] cipherBytes = Base64.getMimeDecoder().decode(cipherText.getBytes("utf-8"));

            Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            cipher1.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decryptedBytes = cipher1.doFinal(cipherBytes);
            decrypted = new String(decryptedBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return decrypted;
    }

    private static PrivateKey privateKeyFromBytes(byte[] privateBytes) {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /*****
     * AES
     ******/
    public static String decrypt(String cipherText, String encryptionKey) throws Exception {
        byte[] cipherBytes = Base64.getMimeDecoder().decode(cipherText.getBytes("utf-8"));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        return new String(cipher.doFinal(cipherBytes), "UTF-8");
    }


    public JSONArray readJsonFile(String inPath) {
        String filerDir = inPath.substring(0, inPath.lastIndexOf('.'));
        fileOutPath = filerDir + ".txt";

        String jsonString = readFile(inPath);
        JSONArray jsonarray = new JSONArray(jsonString);

        decryptButton.setText("decrypt data");

        return jsonarray;
    }

    private void decrypt(JSONArray jsonarray) {

        String outString = "";


        for (int i = 0; i < jsonarray.length(); i++) {

            JSONObject jsonobject = jsonarray.getJSONObject(i);

            String userId = jsonobject.getString("user_id");
            String timeStamp = jsonobject.getString("timestamp");
            String light = jsonobject.getString("light");
            String steps = jsonobject.getString("steps");
            String volume = jsonobject.getString("volume");
            String accX = jsonobject.getString("accX");
            String accY = jsonobject.getString("accY");
            String accZ = jsonobject.getString("accZ");
            String latitude = jsonobject.getString("latitude");
            String longitude = jsonobject.getString("longitude");

            String secret = jsonobject.getString("secret");
            String symmetricKey = rsaDecrypt(secret);

            try {
                light = decrypt(light, symmetricKey);
                steps = decrypt(steps, symmetricKey);
                volume = decrypt(volume, symmetricKey);
                accX = decrypt(accX, symmetricKey);
                accY = decrypt(accY, symmetricKey);
                accZ = decrypt(accZ, symmetricKey);
                latitude = decrypt(latitude, symmetricKey);
                longitude = decrypt(longitude, symmetricKey);
            } catch (Exception ev) {
                ev.printStackTrace();
            }

            outString += userId + " | " + timeStamp + "\n";
            outString += "l: " + light + "\n";
            outString += "s: " + steps + "\n";
            outString += "v: " + volume + "\n";
            outString += "x: " + accX + "\n";
            outString += "y: " + accY + "\n";
            outString += "z: " + accZ + "\n";
            outString += "la: " + latitude + "\n";
            outString += "lo: " + longitude + "\n";
            outString += "\n";

            try (PrintWriter out = new PrintWriter(fileOutPath)) {
                outLabel.setText(outString);

                out.println(outString);
                outLabel.setText(fileOutPath);

            } catch (FileNotFoundException e) {
                outLabel.setText("PROBLEM! DIDN'T DO IT : " + e);
            }
        }
    }



    public String readFile(String filename) {
        String result = "";
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null) {
                sb.append(line);
                line = br.readLine();
            }
            result = sb.toString();
        } catch(Exception e) {
            e.printStackTrace();

            outLabel.setText("NO READ");
        }
        return result;
    }
}