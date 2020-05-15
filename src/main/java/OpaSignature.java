import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.DecoderException;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This example uses the NIMBUS_JOSE_JWT library (https://bitbucket.org/connect2id/nimbus-jose-jwt/wiki/Home).
 * Currently only compact serialisation is supported, not the non-compact i.e. JSON serialisation (https://connect2id.com/products/nimbus-jose-jwt/roadmap)
 * <p>
 * Another most popular library JJWT (https://github.com/jwtk/jjwt) also doesnt support non-compact i.e. JSON serialisation yet
 * Another popular library JOSE4j (https://bitbucket.org/b_c/jose4j/wiki/Home) also doesnt support non-compact i.e. JSON serialisation yet
 */
public class OpaSignature {

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public OpaSignature() {
    }

    public static void main(String[] args) throws JOSEException, ParseException, NoSuchAlgorithmException, DecoderException, IOException {
        System.out.println("OPA SIGNATURE EXAMPLE with JWS.....");

        // Generate a random RSA key pair every time
//        RSAKey rsaJWK = new RSAKeyGenerator(2048)
//                .generate();

        // Generate PrivateKey by providing Modulus and Exponent
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

        // Parse PEM-encoded key to RSA public / private JWK
        JWK jwk = JWK.parseFromPEMEncodedObjects(getKey("db/privateKey.pem"));
        RSAKey rsaJWK = jwk.toRSAKey();

        // Retrieve public key as RSA JWK
        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

        // Determine the Secret for Symmetric Key example
//        SecretKey hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
//        String secret = hmacKey.toString();
        String secretForHMAC = "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ";

        System.out.println("============================ Verify existing tokens of signature files ========================");
        verifyJWSWithRSA(rsaPublicJWK, "db/uam2/.signature-compact-RSA");
        verifyJWSWithHMAC(secretForHMAC, "db/uam2/.signature-compact-HMAC");

        System.out.println("\n============================ Generate new tokens using Java implementation ========================");
        String jsonString = scanDir("db/uam2");
        System.out.println("Files JSON Payload:\n" + jsonString);
        System.out.println("\n============================ Using COMPACT Serialisation==========================");
        String JWSString = createJWSWithRSA(rsaJWK, jsonString);
        System.out.println("JWS Token Serialised:\n" + JWSString);
        // Verify JWS Object
        verifyJWSWithRSA(rsaPublicJWK, "db/uam2/.signature-compact-RSA");

        System.out.println("\n============================ Using Secret/Symmetric Key==========================");
        String JWSStringHMAC = createJWSWithHMAC(secretForHMAC, jsonString);
        System.out.println("JWS Token Serialised:\n" + JWSStringHMAC);
        // Verify JWS Object
        verifyJWSWithHMAC(secretForHMAC, "db/uam2/.signature-compact-HMAC");
    }

    public static String createJWSWithRSA(RSAKey rsaJWK, String filesJson) throws JOSEException, ParseException, IOException {
        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
//                .subject("alice")
                .issuer("JWTService")
                .issueTime(new Date())
//                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .claim("files", filesJson)
                .claim("scope", "AU.GLOBAL.OPA.WRITE")
                .claim("jwks-url", "https://github.com/csp/opa-sourcedata-bundles")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("uam2-opa-poc").build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);


        // Prepare JWS object with simple string as payload
//        JWSObject jwsObject = new JWSObject(
//                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
//                new Payload(filesJson));
//
//        // Compute the RSA signature
//        jwsObject.sign(signer);

        // Output in URL-safe format
        String jsonString = signedJWT.serialize();

        // Set the signature object for signature and file list
        SignaturePOJO signatures = new SignaturePOJO();
        signatures.setSignature(jsonString);
        ObjectMapper mapper = new ObjectMapper();
        CollectionType javaType = mapper.getTypeFactory()
                .constructCollectionType(List.class, FilesPOJO.class);
        signatures.setFiles(mapper.readValue(filesJson, javaType));

        String signatureString = mapper.writeValueAsString(signatures);

        Files.write(Paths.get("db/uam2/.signature-compact-RSA"), signatureString.getBytes());
        return jsonString;
    }

    public static void verifyJWSWithRSA(RSAKey rsaPublicJWK, String fileName) throws JOSEException, ParseException, IOException {

        byte[] fileBytes = new byte[0];
        if (Files.exists(Paths.get(fileName), LinkOption.NOFOLLOW_LINKS)) {
            fileBytes = Files.readAllBytes(Paths.get(fileName));
        }
        if (fileBytes.length == 0) {
            System.out.println("No content found in the file -> \n" + fileName);
            return;
        }
        ObjectMapper mapper = new ObjectMapper();
        SignaturePOJO signatures = mapper.readValue(fileBytes, SignaturePOJO.class);

//        String content = new String(fileBytes);
        System.out.println("Token Found Out " + fileName + " ->\n" + signatures.getSignature());
        // To parse the JWS and verify it, e.g. on client-side
//        JWSObject jwsObject = JWSObject.parse(content);
        // On the consumer side, parse the JWS and verify its RSA signature
        SignedJWT signedJWT = SignedJWT.parse(signatures.getSignature());

        JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);
//        boolean isValid = jwsObject.verify(verifier);
        boolean isValid = signedJWT.verify(verifier);
        System.out.println("JWS Object isValid -> " + isValid);

        String payload = (String) signedJWT.getJWTClaimsSet().getClaim("files");
        System.out.println("JWS Object Payload ->\n" + payload);

        List<FilesPOJO> files = null;
        try {
            CollectionType javaType = mapper.getTypeFactory()
                    .constructCollectionType(List.class, FilesPOJO.class);
            files = mapper.readValue(payload, javaType);
//            files = mapper.readValue(payload, new TypeReference<List<FilesPOJO>>() {
//            });
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (FilesPOJO file : files) {
                // Verify the SHA of decoded payload files
                byte[] buffer = new byte[8192];
                int count;
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file.getName()));
                while ((count = bis.read(buffer)) > 0) {
                    digest.update(buffer, 0, count);
                }
                bis.close();

                byte[] hash = digest.digest();

                if (!file.getSha256().equals(encodeHexString(hash))) {
                    System.out.println("File has different SHA256. \nExpected=" + file.getSha256() + "\nGot=" + encodeHexString(hash));
                }
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    public static String createJWSWithHMAC(String sharedSecret, String filesJson) throws JOSEException, ParseException, IOException {
        // Create HMAC signer
        JWSSigner signer = new MACSigner(sharedSecret);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
//                .subject("alice")
                .issuer("JWTService")
                .issueTime(new Date())
//                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .claim("files", filesJson)
                .claim("scope", "AU.GLOBAL.OPA.WRITE")
                .claim("jwks-url", "https://github.com/csp/opa-sourcedata-bundles")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("uam2-opa-poc").build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);

        // Prepare JWS object with "Hello, world!" payload
//        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(filesJson));
        // Apply the HMAC
//        jwsObject.sign(signer);

        // To serialize to compact form, produces something like
        // eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
        String jsonString = signedJWT.serialize();

        // Set the signature object
        SignaturePOJO signatures = new SignaturePOJO();
        signatures.setSignature(jsonString);
        ObjectMapper mapper = new ObjectMapper();
        CollectionType javaType = mapper.getTypeFactory()
                .constructCollectionType(List.class, FilesPOJO.class);
        signatures.setFiles(mapper.readValue(filesJson, javaType));

        String signatureString = mapper.writeValueAsString(signatures);

        Files.write(Paths.get("db/uam2/.signature-compact-HMAC"), signatureString.getBytes());

        return jsonString;
    }

    public static void verifyJWSWithHMAC(String sharedSecret, String fileName) throws JOSEException, ParseException, IOException {
        byte[] fileBytes = new byte[0];
        if (Files.exists(Paths.get(fileName), LinkOption.NOFOLLOW_LINKS)) {
            fileBytes = Files.readAllBytes(Paths.get(fileName));
        }
        if (fileBytes.length == 0) {
            System.out.println("No content found in the file -> \n" + fileName);
            return;
        }
        ObjectMapper mapper = new ObjectMapper();
        SignaturePOJO signatures = mapper.readValue(fileBytes, SignaturePOJO.class);

//        String content = new String(fileBytes);
        System.out.println("Token Found Out " + fileName + " ->\n" + signatures.getSignature());
        // To parse the JWS and verify it, e.g. on client-side
//        JWSObject jwsObject = JWSObject.parse(content);

        // On the consumer side, parse the JWS and verify its RSA signature
        SignedJWT signedJWT = SignedJWT.parse(signatures.getSignature());

        JWSVerifier verifier = new MACVerifier(sharedSecret);
//        boolean isValid = jwsObject.verify(verifier);
        boolean isValid = signedJWT.verify(verifier);
        System.out.println("JWS Object isValid -> " + isValid);

        String payload = (String) signedJWT.getJWTClaimsSet().getClaim("files");
        System.out.println("JWS Object Payload ->\n" + payload);

        List<FilesPOJO> files = null;
        try {
            CollectionType javaType = mapper.getTypeFactory()
                    .constructCollectionType(List.class, FilesPOJO.class);
            files = mapper.readValue(payload, javaType);
//            files = mapper.readValue(payload, new TypeReference<List<FilesPOJO>>() {
//            });
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (FilesPOJO file : files) {
                // Verify the SHA of decoded payload files
                byte[] buffer = new byte[8192];
                int count;
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file.getName()));
                while ((count = bis.read(buffer)) > 0) {
                    digest.update(buffer, 0, count);
                }
                bis.close();

                byte[] hash = digest.digest();

                if (!file.getSha256().equals(encodeHexString(hash))) {
                    System.out.println("File has different SHA256. \nExpected=" + file.getSha256() + "\nGot=" + encodeHexString(hash));
                }
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String scanDir(String dirPath) {
        List<FilesPOJO> files = new ArrayList<>();

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (Stream<Path> walk = Files.walk(Paths.get(dirPath))) {
                List<String> results = walk.filter(Files::isRegularFile)
                        .map(Path::toString).collect(Collectors.toList());

                for (String fileName : results) {
                    if (!fileName.endsWith(".signature-compact-RSA") && !fileName.endsWith(".signature-full-RSA")
                            && !fileName.endsWith(".signature-compact-HMAC") && !fileName.endsWith(".DS_Store")) {
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
                        file.setSha256(encodeHexString(hash));
                        files.add(file);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        ObjectMapper mapper = new ObjectMapper();
        // Java objects to JSON string - compact-print
        String jsonString = null;
        try {
            jsonString = mapper.writeValueAsString(files);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return jsonString;
    }

    private static String encodeHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }

    private static String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    private static String getKey(String filename) throws IOException {
        // Read key from file
        String strKeyPEM = "";
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();
        return strKeyPEM;
    }
}
