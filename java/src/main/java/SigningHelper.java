import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SigningHelper {

    public static RSAKey getRSAKey(File file) throws IOException, JOSEException {

        // Approach 1. Generate a random RSA key pair every time
//        RSAKey rsaJWK = new RSAKeyGenerator(2048)
//                .generate();

        // Approach 2. Generate PrivateKey by providing Modulus and Exponent
//        Base64URL pubModulus = Base64URL.encode(Hex.decodeHex("01D58729C5FFE1785360D7A2B532EAA6329C9B8BD95AF105422B40368630F636E1CB0B847D74798BD95249B42A47971BB5903FC87A97B7D541AC599961B8B0EB6CF24F7DFC798434EAE2E3D4E741D4FEC9C696208015205A50258B688A5475751B361C57CAEBE26DB3CF92AA4F4A69DD936E14A7A58072CFF461035ED9D448D1161E2C0DFFDF2A36B42CABC6B2D8FDACB7BC4C113890E69124E4FBD488AF9FBC5550C7586C5412E01A6DE9F2A8966E7C183C5A4CADD93E85FE6B1286211DEE62F29274358F569E20F169F1A2D01259710503AC6AD1DA8FC2C6C4C6933C78D1AE37DE30A0A84676FD11D95D43B5B93C032F52CEC2B1E636FC94E9FEA2F321A668FF".toCharArray()));
//        Base64URL pubExponent = Base64URL.encode(BigInteger.valueOf(65537));
//        Base64URL pkExponent = Base64URL.encode(Hex.decodeHex("2D426781C68B4810AC227274B50119742CD471994A1836EC37446BFD1375D30F2B860E0769D582E837F3BD8235D46DBF5AB5A09AF09FAFD6DCC8E642C7E2DB4EC282172037367498BA60EBD7943E4BDBCCB611514762B9A74577380F32DA54FCD7D7C8E9594397AA358AC0655444502F889F9A696C5AFA3611AE997E0B3B2F0185C60257E90D1955546F0190DF57F1674F0AD912BD8FFEAEAE65A79E0D9783E980E3C5CCC1B18D524296B806BDA4EC28DF028CCDA91FD94A89228EFA1B82A6B0B4C0A142EE7C890BE97C30F58232BEC26E897E25FC61B432CC651F82622132F3BE34E764623E4DD75DD469703C0081DCCE7F58C8A3DC72D46FB2BE548E5AF641".toCharArray()));
//        Base64URL pkPrime1 = Base64URL.encode(Hex.decodeHex("010CA88D97C90A5544D1CA63A5916B20CA2FC92C5CE2EB43409D953009630B322723D15581610A6CFE7686710A0086776C8929106646A4118CDC937E1B443F32D8B8255F4AB631D11C818D4D3411CF72D41780FC6354E6198BD6BE6D9790C12F6CB596B1C9BAC4F53B34C833375B60E1EC5EF71407FBA5229BDECEE38C8841432B".toCharArray()));
//        Base64URL pkPrime2 = Base64URL.encode(Hex.decodeHex("01BF67B98C4202D2BF8510B0F84752C26BF6C1E3C464B6678E612904F471A2D9E3A251B39416701F19290EC9957EA1EBB08ADABD3088018E7F81A57F3E287C3387EFDDC6ABBA7CDD446F089930071EDD3D06EB0D69AA334F23C7C7E8648AFC4C3C781BEBE6428949A2841E555B754685C2AAF2BA1E6F7F1A049CABFDC7FD5F577D".toCharArray()));
//        Base64URL dpPrime = Base64URL.encode(Hex.decodeHex("685B5CCCD5F1E69759EA84F47E5D1F9A8A1F59D526EBFDEEAE8791E6438BC8CA7D56462180815D3F26E928259B78A0110FE25C956DE13354052661B8D3B4BCDA84053853BC1BF3BF5FEF744AC2945365614FE039F17383FED6C697A965383564C3D0AA74D2D0C8F55B965C96A72F25F2FC1C7BB272247E220FD54B7C7E3CE38B".toCharArray()));
//        Base64URL dqPrime = Base64URL.encode(Hex.decodeHex("4572D7658335A6FB1DAFAA98CF91742688262EB1E4A43FCCE51E15EBCFDBE490A638A274814B2438A69BEA04AFA478CE6DAF68A0A8EBFCEFA3F3499E1F70B01B10CBCF3406FDACE71B892D263C64B918E9030190FE5F7A9066498CB456B2B52EC9C223CB1956F03C2EDFFA85F8DD5A940E2F215EEA15C3B7258EB9151B2A7A8D".toCharArray()));
//        Base64URL qiPrime = Base64URL.encode(Hex.decodeHex("89A217111B58DD54CCFB00C4873DB4EF6716283AEA77D2B46D85F1D8D47F2C0EC21AA37EBB26781C19EC43EB9583FB47205D83692D7CDCA9528B69C19EEFC100624A31907B33AFB9008C4685EB8AB709B890D7C6A6BD50BD41EE5A373FD31701F516FDB30C694243FBCB0851E237EA31703A2BC2A945EE5B9F12DCD574F3FBCB".toCharArray()));

//        // Create JWS Object
//        // RSA signatures require a public and private RSA key pair,
//        // the public key must be made known to the JWS recipient to
//        // allow the signatures to be verified
//        RSAKey rsaJWK = new RSAKey(pubModulus, pubExponent,
//                pkExponent,
//                pkPrime1,
//                pkPrime2,
//                dpPrime,
//                dqPrime,
//                qiPrime,
//                null,
//                null,
//                null, null, null, "uam2-opa-poc",
//                null, null, null, null,
//                null);


        // Approach 3. Read key from file
        StringBuilder strKeyPEM = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM.append(line).append("\n");
        }
        br.close();

        // Parse PEM-encoded key to RSA public / private JWK
        JWK jwk = JWK.parseFromPEMEncodedObjects(strKeyPEM.toString());
        return jwk.toRSAKey();
    }

    public static String getHMACKey() {
        // SecretKey hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
        // String secret = hmacKey.toString();
        return "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ";
    }

    public static String getJSONContent(Path payload) throws IOException {
        byte[] fileBytes = new byte[0];
        if (Files.exists(payload, LinkOption.NOFOLLOW_LINKS)) {
            fileBytes = Files.readAllBytes(payload);
        }
        if (fileBytes.length == 0) {
            throw new IOException("No content found in the file: " + payload);
        } else {
            return new String(fileBytes);
        }
    }

    public static String getPayloadFromDir(String dirPath) throws JsonProcessingException, IOException, NoSuchAlgorithmException {
        // Get the list of files from the directory
        List<FilesPOJO> files = getFilesFromDir(dirPath);

        ObjectMapper mapper = new ObjectMapper();
        // Java objects to JSON string - compact-print
        String jsonString = mapper.writeValueAsString(files);
        System.out.println("[FILES] Payload generated for signing: \n" + jsonString);
        return jsonString;
    }

    public static boolean verifyPayloadFiles(String payloadJSON, String targetDir) throws Exception, JsonProcessingException, IOException, NoSuchAlgorithmException {
        // Get the source files
        ObjectMapper mapper = new ObjectMapper();
        CollectionType javaType = mapper.getTypeFactory()
                .constructCollectionType(List.class, FilesPOJO.class);
        List<FilesPOJO> sourceFiles = mapper.readValue(payloadJSON, javaType);

        // Get the list of files from the directory
        List<FilesPOJO> targetFiles = getFilesFromDir(targetDir);

        // Check if there are any additional files in target directory
        for (FilesPOJO tf : targetFiles) {
            boolean extra = true;
            for (FilesPOJO sf : sourceFiles) {
                if (sf.getName().equals(tf.getName())) {
                    extra = false;
                }
            }
            if (extra) {
                throw new Exception("Additional file " + tf.getName() + " found in the target directory");
            }
        }

        // Validate source against the target directory
        for (FilesPOJO sf : sourceFiles) {
            boolean exists = false;
            for (FilesPOJO tf : targetFiles) {
                if (sf.getName().equals(tf.getName())) {
                    exists = true;
                    // Verify the SHA hash of the file
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] buffer = new byte[8192];
                    int count;
                    BufferedInputStream bis = new BufferedInputStream(new FileInputStream(tf.getName()));
                    while ((count = bis.read(buffer)) > 0) {
                        digest.update(buffer, 0, count);
                    }
                    bis.close();

                    byte[] hash = digest.digest();

                    if (!sf.getHash().equals(SigningHelper.encodeHexString(hash))) {
                        System.out.println("File " + sf.getName() + " has different SHA256. \nExpected=" + sf.getHash() + "\nGot=" + SigningHelper.encodeHexString(hash));
                        throw new Exception("SHA hash of the file " + sf.getName() + " could not be verified");
                    }
                }
            }
            if (!exists) {
                throw new Exception("File " + sf.getName() + " in the payload could not be found in target directory");
            }
        }

        return true;
    }

    public static List<FilesPOJO> getFilesFromDir(String targetDir) throws IOException, NoSuchAlgorithmException {
        List<FilesPOJO> files = new ArrayList<>();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        Stream<Path> walk = Files.walk(Paths.get(targetDir));
        List<String> results = walk.filter(Files::isRegularFile)
                .map(Path::toString).collect(Collectors.toList());

        for (String fileName : results) {
            if (!fileName.endsWith(".DS_Store")) {
                FilesPOJO file = new FilesPOJO();
                file.setName(fileName);

                byte[] buffer = new byte[8192];
                int count;
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));
                while ((count = bis.read(buffer)) > 0) {
                    digest.update(buffer, 0, count);
                }
                bis.close();

                byte[] hash = digest.digest();

//                    file.setSha256(Base64.getEncoder().encodeToString(hash));
                file.setHash(encodeHexString(hash));
                file.setAlgorithm("sha-256");
                files.add(file);
            }
        }
        return files;
    }

    public static String encodeHexString(byte[] byteArray) {
        StringBuilder hexStringBuilder = new StringBuilder();
        for (byte b : byteArray) {
            hexStringBuilder.append(byteToHex(b));
        }
        return hexStringBuilder.toString();
    }

    public static String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }
}
