import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.SignedJWT;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.text.ParseException;

import java.lang.*;

import picocli.CommandLine;

import static picocli.CommandLine.*;

/**
 * This example uses the NIMBUS_JOSE_JWT library (https://bitbucket.org/connect2id/nimbus-jose-jwt/wiki/Home).
 * Currently only compact serialisation is supported, not the non-compact i.e. JSON serialisation (https://connect2id.com/products/nimbus-jose-jwt/roadmap)
 * <p>
 * Another most popular library JJWT (https://github.com/jwtk/jjwt) also doesnt support non-compact i.e. JSON serialisation yet
 * Another popular library JOSE4j (https://bitbucket.org/b_c/jose4j/wiki/Home) also doesnt support non-compact i.e. JSON serialisation yet
 * <p>
 * PICOCLI (https://picocli.info/) librarcy is used to create command line program
 */

@Command(
        name = "opasign",
        mixinStandardHelpOptions = true,
        subcommands = {HelpCommand.class}
)
public class OpaSignature implements Runnable {

    // Below security provider is added for nimbus-jose-jwt to be able to parse and read RSA key pair from a PEM file
    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

//        @ArgGroup(exclusive = true, multiplicity = "1")
//        PayloadData payloadData;
//
//         class PayloadData {
//            @Option(names = {"-p", "--payload"}, arity = "1", description = "The payload to be signed.") Path payload;
//            @Option(names = {"-td", "--targetDir"}, arity = "1", description = "The target directory whose content needs to be signed.")
//            String targetDir;
//        }

    public static void main(String[] args) throws JOSEException, ParseException, IOException {
        CommandLine commandLine = new CommandLine(new OpaSignature());

//        commandLine.registerConverter(PayloadData.class, );
        commandLine.setExecutionStrategy(new RunAll());
        int exitCode = commandLine.execute(args);
        System.out.println("Exit Code: " + exitCode);
        System.exit(exitCode);
    }

    @Override
    public void run() {
    }

    @Command(name = "create", description = "Create the signature for the given payload")
    private int createCommand(@Parameters(index = "0", arity = "1", description = "The target signature JSON file.") String sigFileName,
                              @Option(names = {"-k", "--privateKey"}, arity = "1", description = "The path private/public key file used to sign/verify the payload for RSA algo. For HMAC, its the secret key string") String key,
                              @Option(names = {"-a", "--algo"}, arity = "1", description = "The payload to be signed. Possible values are RSA & HMAC. Default is RSA.") String algo,
                              @Option(names = {"-p", "--payload"}, arity = "1", description = "The payload to be signed. --targetDir/-t will take precedence if --targetDir/-t is also supplied.") Path payload,
                              @Option(names = {"-t", "--targetDir"}, arity = "1", description = "The target directory whose content needs to be signed or verified. --targetDir will take precedence if --payload/-p is also supplied.") String targetDir) {
        System.out.println("Creating the signature for the supplied payload or the content of the supplied directory...");

        /**
         Process RSA Algorithm for Signing
         */
        if (algo == null || algo.isEmpty() || algo.equals("RSA")) {
            try {
                // Parse PEM-encoded key to RSA public / private JWK
                RSAKey rsaJWK = SigningHelper.getRSAKey(Paths.get(key).toFile());

                String jsonString;
                if (targetDir != null && !targetDir.isEmpty()) {
                    jsonString = SigningHelper.getPayloadFromDir(targetDir);
                } else {
                    jsonString = SigningHelper.getJSONContent(payload);
                }

                RSAHandler.createJWSWithRSA(rsaJWK, jsonString, sigFileName);
            } catch (Exception e) {
                System.out.println(e.getMessage());
                return 1;
            }
        }

        /**
         Process HMAC Algorithm for Signing
         */
        if (algo != null && !algo.isEmpty() && algo.equals("HMAC")) {
            try {
                String jsonString;
                if (targetDir != null && !targetDir.isEmpty()) {
                    jsonString = SigningHelper.getPayloadFromDir(targetDir);
                } else {
                    jsonString = SigningHelper.getJSONContent(payload);
                }

                HMACHandler.createJWSWithHMAC(key, jsonString, sigFileName);
            } catch (Exception e) {
                System.out.println(e.getMessage());
                return 1;
            }
        }
        return 0;
    }

    @Command(name = "verify", description = "Verify the supplied signature for the given public key")
    private int verifyCommand(@Parameters(index = "0", arity = "1", description = "The target signature JSON file.") String sigFileName,
                              @Option(names = {"-k", "--key"}, arity = "1", required = true, description = "The path private/public key file used to sign/verify the payload for RSA algo. For HMAC, its the secret key string") String key,
                              @Option(names = {"-a", "--algo"}, arity = "1", description = "The payload to be signed. Possible values are RSA & HMAC. Default is RSA.") String algo,
                              @Option(names = {"-t", "--targetDir"}, arity = "1", required = true, description = "The target directory whose content needs to be signed or verified.") String targetDir
    ) {
        System.out.println("Verifying the supplied signature...");

        /**
         Process RSA Algorithm for Verification
         */
        if (algo == null || algo.isEmpty() || algo.equals("RSA")) {
            try {
                // Parse PEM-encoded key to RSA public / private JWK
                RSAKey rsaJWK = SigningHelper.getRSAKey(Paths.get(key).toFile());
                // Retrieve public key as RSA JWK
                RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();

                // Verify JWS Object
                RSAHandler.verifyJWSWithRSA(rsaPublicJWK, sigFileName, targetDir);
            } catch (Exception e) {
                System.out.println(e.getMessage());
                return 1;
            }
        }

        /**
         Process HMAC Algorithm for Verification
         */
        if (algo != null && !algo.isEmpty() && algo.equals("HMAC")) {
            try {
                // Verify JWS Object
                HMACHandler.verifyJWSWithHMAC(key, sigFileName, targetDir);
            } catch (Exception e) {
                System.out.println(e.getMessage());
                return 1;
            }
        }
        return 0;
    }

    @Command(name = "list", description = "List the signature defined in the supplied file")
    private int listCommand(@Parameters(index = "0", arity = "1", description = "The target signature JSON file.") Path sigFile) {
        System.out.println("Listing the signature defined in the supplied file...");

        try {
            byte[] fileBytes = new byte[0];
            if (Files.exists(sigFile, LinkOption.NOFOLLOW_LINKS)) {
                fileBytes = Files.readAllBytes(sigFile);
            }
            if (fileBytes.length == 0) {
                System.out.println("No content found in the file: " + sigFile);
                return 1;
            }
            ObjectMapper mapper = new ObjectMapper();
            SignaturePOJO signatures = mapper.readValue(fileBytes, SignaturePOJO.class);
            // On the consumer side, parse the JWS and verify its RSA signature
            SignedJWT signedJWT = SignedJWT.parse(signatures.getSignatures().get(0));
            String payload = (String) signedJWT.getJWTClaimsSet().getClaim("files");
            System.out.println("JWT claims decoded: \n" + payload);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return 1;
        }
        return 0;
    }
}
