package com.company;

import com.company.abe.circuit.FLTCCDDefaultCircuit;
import com.company.abe.circuit.FLTCCDDefaultCircuit.FLTCCDDefaultGate;
import com.company.abe.generators.FLTCCDKeyPairGenerator;
import com.company.abe.generators.FLTCCDParametersGenerator;
import com.company.abe.generators.FLTCCDSecretKeyGenerator;
import com.company.abe.kem.FLTCCDKEMEngine;
import com.company.abe.parameters.*;
import it.unisa.dia.gas.crypto.kem.KeyEncapsulationMechanism;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import static com.company.abe.circuit.FLTCCDDefaultCircuit.FLTCCDGateType.*;
import static org.junit.Assert.*;

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

            byte[] result = kem.process();
            byte[] size = new byte[4];

            for (int i = 0; i < 4; i++) {
                size[i] = result[i];
            }

            ByteBuffer wrapped = ByteBuffer.wrap(size);

            int secretSize = wrapped.getInt();
            byte[] secret = new byte[secretSize];
            for (int i = 0; i < secretSize; i++) {
                secret[i] = result[i + 4];
            }

            byte[] encryptionParams = new byte[result.length - secretSize - 4];
            for (int i = 0; i < result.length - secretSize - 4; i++) {
                encryptionParams[i] = result[i + secretSize + 4];
            }

            return new byte[][]{secret, encryptionParams};
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
        return null;
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterSecretKey, FLTCCDDefaultCircuit circuit) {
        FLTCCDSecretKeyGenerator keyGen = new FLTCCDSecretKeyGenerator();
        keyGen.init(new FLTCCDSecretKeyGenerationParameters(
                (FLTCCDPublicKeyParameters) publicKey,
                (FLTCCDMasterSecretKeyParameters) masterSecretKey,
                circuit
        ));
        return keyGen.generateKey();
    }

    public byte[] decaps(CipherParameters secretKey, byte[] encryptionParams, String w) {
        try {
            KeyEncapsulationMechanism kem = new FLTCCDKEMEngine();

            kem.init(false, new FLTCCDDecryptionParameters((FLTCCDSecretKeyParameters) secretKey, w));
            byte[] key = kem.processBlock(encryptionParams);

            assertNotNull(key);
            assertNotSame(0, key.length);

            return key;
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }

        return null;
    }

    public static void main(String[] args) throws IOException {
        int n = 4;
        int q = 5;

        FLTCCDDefaultCircuit circuit = new FLTCCDDefaultCircuit(n, q, 3, new FLTCCDDefaultGate[]{
                new FLTCCDDefaultGate(INPUT, 0, 1),
                new FLTCCDDefaultGate(INPUT, 1, 1),
                new FLTCCDDefaultGate(INPUT, 2, 1),
                new FLTCCDDefaultGate(INPUT, 3, 1),

                new FLTCCDDefaultGate(FO, 4, 2, new int[]{2}),
                new FLTCCDDefaultGate(OR, 5, 3, new int[]{1, 4}),
                new FLTCCDDefaultGate(AND, 6, 3, new int[]{3, 4}),
                new FLTCCDDefaultGate(AND, 7, 4, new int[]{0, 5}),
                new FLTCCDDefaultGate(OR, 8, 3, new int[]{6, 7})
        });

        Main main = new Main();

        // Setup phase
        AsymmetricCipherKeyPair keyPair = main.setup(n);
        String assignment = "1101";

        // Encryption phase
        byte[][] ct = main.encaps(keyPair.getPublic(), assignment);

        assert ct != null;
        byte[] secret = ct[0];

        // Key Generation phase
        CipherParameters secretKey = main.keyGen(keyPair.getPublic(), keyPair.getPrivate(), circuit);

        // Decryption phase
        assertEquals(true, Arrays.equals(secret, main.decaps(secretKey, ct[1], assignment)));
    }
}
