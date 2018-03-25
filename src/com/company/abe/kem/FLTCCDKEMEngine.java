package com.company.abe.kem;

import com.company.abe.parameters.*;
import it.unisa.dia.gas.crypto.jpbc.kem.PairingKeyEncapsulationMechanism;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.util.io.PairingStreamWriter;

import java.io.IOException;
import java.nio.ByteBuffer;

public class FLTCCDKEMEngine extends PairingKeyEncapsulationMechanism {
    public FLTCCDKEMEngine() {
    }

    public void initialize() {
        if (this.forEncryption) {
            if (!(this.key instanceof FLTCCDEncryptionParameters)) {
                throw new IllegalArgumentException("FLTCCDEncryptionParameters are required for encryption.");
            }
        } else if (!(this.key instanceof FLTCCDDecryptionParameters)) {
            throw new IllegalArgumentException("GGHSW13SecretKeyParameters are required for decryption.");
        }

        FLTCCDKeyParameters keyParameters = (FLTCCDKeyParameters)this.key;
        this.pairing = keyParameters.getParameters().getPairing();
        this.keyBytes = this.pairing.getFieldAt(this.pairing.getDegree()).getCanonicalRepresentationLengthInBytes();
    }

    @Override
    public byte[] process(byte[] bytes, int inOff, int inLen) {
        String assignment;
        if (this.key instanceof FLTCCDDecryptionParameters) {
            FLTCCDDecryptionParameters decKey = (FLTCCDDecryptionParameters) this.key;
            FLTCCDSecretKeyParameters sk = (FLTCCDSecretKeyParameters)decKey.getSecretKey();
            assignment = decKey.getAssignment();

            assert assignment.length() == sk.getCircuit().getN();

            for (int i = 0; i < sk.getCircuit().getN(); i++) {
//                sk.getParameters()
//                        .getPairing()
//                        .pairing()
            }
            return null;
        } else {
            FLTCCDEncryptionParameters encKey = (FLTCCDEncryptionParameters)this.key;
            FLTCCDPublicKeyParameters publicKey = encKey.getPublicKey();
            assignment = encKey.getAssignment();
            PairingStreamWriter writer = new PairingStreamWriter(this.getOutputBlockSize());

            try {
                Element s = this.pairing.getZr().newRandomElement().getImmutable();
                Element mask = publicKey.getY().powZn(s);

                writer.write(ByteBuffer.allocate(4).putInt(mask.toCanonicalRepresentation().length).array());
                writer.write(mask.toCanonicalRepresentation());

                int n = publicKey.getParameters().getN();

                for(int i = 0; i < n; ++i) {
                    if (assignment.charAt(i) == '1') {
                        writer.write(publicKey.getCapitalTAt(i).powZn(s));
                    }
                }

                writer.write(this.pairing.getFieldAt(1).newElement().powZn(s));
            } catch (IOException var19) {
                throw new RuntimeException(var19);
            }

            return writer.toBytes();
        }
    }
}
