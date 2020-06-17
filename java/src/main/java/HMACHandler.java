import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.fasterxml.jackson.databind.type.CollectionType;
import java.util.List;

public class HMACHandler {

    public static void createJWSWithHMAC(String sharedSecret, String filesJson, String sigFileName) throws JOSEException, IOException {

        ObjectMapper mapper = new ObjectMapper();

         // Unmarshal files JSON into Files array
         CollectionType javaType = mapper.getTypeFactory()
         .constructCollectionType(List.class, FilesPOJO.class);
        List<FilesPOJO> files = mapper.readValue(filesJson, javaType);

        // Create HMAC signer
        JWSSigner signer = new MACSigner(sharedSecret);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
//                .subject("alice")
                .issuer("JWTService")
                .issueTime(new Date())
//                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                // .claim("files", filesJson)
                .claim("files", files)
                .claim("scope", "AU.GLOBAL.OPA.WRITE")
                .claim("jwks-url", "https://github.com/csp/opa-sourcedata-bundles")
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("uam2-opa-poc").build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);

        String jsonString = signedJWT.serialize();
//        System.out.println("[HMAC] JWT token generated: \n" + jsonString);
        // Set the signature object
        SignaturePOJO signatures = new SignaturePOJO();
        signatures.setSignatures(Arrays.asList(jsonString));

        String signatureString = mapper.writeValueAsString(signatures);

        Files.write(Paths.get(sigFileName), signatureString.getBytes());
        System.out.println("[HMAC] Signature file generated: " + sigFileName);
    }

    public static void verifyJWSWithHMAC(String sharedSecret, String fileName, String targetDir) throws Exception, JOSEException, ParseException, IOException, NoSuchAlgorithmException {
        byte[] fileBytes = new byte[0];
        if (Files.exists(Paths.get(fileName), LinkOption.NOFOLLOW_LINKS)) {
            fileBytes = Files.readAllBytes(Paths.get(fileName));
        }
        if (fileBytes.length == 0) {
            throw new Exception("[HMAC] No content found in the file: " + fileName);
        }
        ObjectMapper mapper = new ObjectMapper();
        SignaturePOJO signatures = mapper.readValue(fileBytes, SignaturePOJO.class);
//        System.out.println("[HMAC] JWT token found in the file " + fileName + ": \n" + signatures.getSignature());

        // On the consumer side, parse the JWS and verify its RSA signature
        SignedJWT signedJWT = SignedJWT.parse(signatures.getSignatures().get(0));

        JWSVerifier verifier = new MACVerifier(sharedSecret);
        Boolean isValid = signedJWT.verify(verifier);
        System.out.println("[HMAC] Signature valid flag: " + isValid.toString().toUpperCase());

         // String payload = (String) signedJWT.getJWTClaimsSet().getClaim("files");
         Object payload = signedJWT.getJWTClaimsSet().getClaim("files");
         // Java objects to JSON string - compact-print
         String jsonString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload);
         System.out.println("[RSA] Payload Decoded: \n" + jsonString);

        boolean isFilesValid = SigningHelper.verifyPayloadFiles(jsonString, targetDir);
        if (!isFilesValid) {
            throw new Exception("SHA hash of one or more files could not be verified");
        }
        System.out.println("[RSA] SHA hash of all the files is verified successfully");
    }

}
