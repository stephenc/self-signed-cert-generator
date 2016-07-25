package io.github.stephenc.crypto.sscg;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/**
 * @author Stephen Connolly
 */
@RunWith(Theories.class)
public class SelfSignedCertificateIT {

    @DataPoints
    public static List<KeyPair> keyPairs() throws Exception {
        List<KeyPair> result = new ArrayList<KeyPair>();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
        gen.initialize(1024); // maximum supported by JVM with export restrictions
        result.add(gen.generateKeyPair());
        gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(256); // this is the default keysize supported by SunEC
        result.add(gen.generateKeyPair());
        gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048); // maximum supported by JVM with export restrictions
        result.add(gen.generateKeyPair());
        return result;
    }

    @Theory
    public void smokes(KeyPair pair) throws IOException {
        SelfSignedCertificate.forKeyPair(pair).cn("smoke").cn("test").c("US").generate();
    }
}
