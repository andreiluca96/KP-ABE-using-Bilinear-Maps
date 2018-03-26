package com.company.abe.kem;

import com.company.abe.parameters.*;
import com.google.common.collect.Lists;
import it.unisa.dia.gas.crypto.jpbc.kem.PairingKeyEncapsulationMechanism;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.util.io.PairingStreamReader;
import it.unisa.dia.gas.plaf.jpbc.util.io.PairingStreamWriter;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

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
    public byte[] process(byte[] in, int inOff, int inLen) {
        String assignment;
        if (this.key instanceof FLTCCDDecryptionParameters) {
            FLTCCDDecryptionParameters decKey = (FLTCCDDecryptionParameters) this.key;
            FLTCCDSecretKeyParameters sk = decKey.getSecretKey();
            assignment = decKey.getAssignment();
            PairingStreamReader reader = new PairingStreamReader(this.pairing, in, inOff);
            List<Element> ts = Lists.newArrayList();

            assert assignment.length() == sk.getCircuit().getN();

            for (int i = 0; i < sk.getCircuit().getN(); i++) {
                if (assignment.charAt(i) == '1') {
                    ts.add(reader.readG1Element());
                } else {
                    ts.add(null);
                }
            }

            List<List<Element>> vA = Lists.newArrayList();
            for (int i = 0; i < sk.getCircuit().getN(); i++) {
                if (assignment.charAt(i) == '1') {
                    vA.add(Lists.newArrayList());
                } else {
                    vA.add(null);
                    continue;
                }

                List<Element> di = sk.getDElementsAt(i);
                for (int j = 0; j < di.size(); i++) {
                    Element element1 = pairing
                            .getG1()
                            .newOneElement()
                            .powZn(ts.get(i));
                    Element element2 = pairing
                            .getG2()
                            .newOneElement()
                            .powZn(sk.getDElementsAt(i).get(j));
                    Element element = pairing
                            .pairing(element1, element2);

                    vA.get(i).add(element);
                }
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
