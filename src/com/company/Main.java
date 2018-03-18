package com.company;

import com.company.abe.generators.FLTCCDKeyPairGenerator;
import com.company.abe.generators.FLTCCDParametersGenerator;
import com.company.abe.kem.FLTCCDKEMEngine;
import com.company.abe.parameters.FLTCCDEncryptionParameters;
import com.company.abe.parameters.FLTCCDKeyPairGenerationParameters;
import com.company.abe.parameters.FLTCCDPublicKeyParameters;
import it.unisa.dia.gas.crypto.kem.KeyEncapsulationMechanism;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.fail;

public class Main {

    private static final int rBits = 160;
    private static final int qBits = 512;

    private AsymmetricCipherKeyPair setup(int n) {
        FLTCCDKeyPairGenerator setup = new FLTCCDKeyPairGenerator();
        setup.init(new FLTCCDKeyPairGenerationParameters(
                new SecureRandom(),
                new FLTCCDParametersGenerator().init(
                        PairingFactory.getPairing(new TypeACurveGenerator(rBits, qBits).generate()), n
                ).generateParameters()
        ));
        return setup.generateKeyPair();
    }

    private byte[][] encaps(CipherParameters publicKey, String w) {
        try {
            KeyEncapsulationMechanism kem = new FLTCCDKEMEngine();
            kem.init(true, new FLTCCDEncryptionParameters((FLTCCDPublicKeyParameters) publicKey, w));

            byte[] cipherText = kem.process();

            assertNotNull(cipherText);
            assertNotSame(0, cipherText.length);

            byte[] key = Arrays.copyOfRange(cipherText, 0, kem.getKeyBlockSize());
            byte[] ct = Arrays.copyOfRange(cipherText, kem.getKeyBlockSize(), cipherText.length);

            return new byte[][]{key, ct};
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
        return null;
    }

    public static void main(String[] args) {
        int n = 4;

        Main main = new Main();

        AsymmetricCipherKeyPair keyPair = main.setup(n);
        String assignment = "1101";
        byte[][] ct = main.encaps(keyPair.getPublic(), assignment);
    }
}
