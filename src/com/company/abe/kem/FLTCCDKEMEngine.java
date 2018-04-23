package com.company.abe.kem;

import com.company.abe.circuit.FLTCCDDefaultCircuit;
import com.company.abe.parameters.*;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import it.unisa.dia.gas.crypto.jpbc.kem.PairingKeyEncapsulationMechanism;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.util.io.PairingStreamReader;
import it.unisa.dia.gas.plaf.jpbc.util.io.PairingStreamWriter;
import org.junit.Assert;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

import static com.company.abe.circuit.FLTCCDDefaultCircuit.*;
import static com.company.abe.circuit.FLTCCDDefaultCircuit.FLTCCDGateType.INPUT;
import static com.google.common.collect.Lists.newArrayList;

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
            // decryption phase

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

            Element gs = reader.readG1Element();

            Map<Integer, List<Element>> vA = Maps.newHashMap();
            for (int i = 0; i < sk.getCircuit().getN(); i++) {
                if (assignment.charAt(i) == '1') {
                    vA.put(i, Lists.newArrayList());
                } else {
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

            Element key = reconstruct(decKey.getSecretKey().getCircuit(), decKey.getSecretKey(), vA, gs);

            return key.toBytes();
        } else {
            // encryption phase

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

    private Element reconstruct(FLTCCDDefaultCircuit circuit, FLTCCDSecretKeyParameters secretKey, Map<Integer, List<Element>> vA, Element gs) {
        Map<Integer, List<Element>> r = Maps.newHashMap();

        Map<Integer, Integer> foGateCounterMapping = Maps.newHashMap();

        List<FLTCCDDefaultGate> bottomUpGates = newArrayList(circuit.iterator());
        for (FLTCCDDefaultGate gate : bottomUpGates) {
            if (gate.getType() == INPUT) {
                // assign to each wire that connects to an input gate the vA value.
                for (FLTCCDDefaultGate outputGate : bottomUpGates) {
                    for (int i = 0; i < outputGate.getInputSize(); i++) {
                        if (outputGate.getInputIndexAt(i) == gate.getIndex()) {
                            r.put(circuit.getWireIndex(gate.getIndex(), outputGate.getIndex()), vA.get(gate.getIndex()));
                        }
                    }
                }
            } else {
                switch (gate.getType()) {
                    case OR: {
                        int outputGateIndex = -1;
                        for (FLTCCDDefaultGate outputGate : bottomUpGates) {
                            for (int i = 0; i < outputGate.getInputSize(); i++) {
                                if (outputGate.getInputIndexAt(i) == gate.getIndex()) {
                                    outputGateIndex = outputGate.getIndex();
                                }
                            }
                        }

                        Assert.assertEquals(r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).size(),
                                r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).size());
                        List<Element> elements = Lists.newArrayList();
                        for (int i = 0; i < r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).size(); i++) {
                            if (r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).get(i) == null) {
                                if (r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).get(i) == null) {
                                    elements.add(null);
                                } else {
                                    elements.add(r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).get(i));
                                }
                            } else {
                                Assert.assertEquals(r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).get(i),
                                        r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).get(i));
                                elements.add(r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).get(i));
                            }
                        }

                        r.put(circuit.getWireIndex(gate.getIndex(), outputGateIndex), elements);

                        break;
                    }
                    case AND: {
                        List<Element> rIJ;
                        if (r.get(inputGate.getIndex()).get(0) == null || r.get(inputGate.getIndex()).get(1) == null) {
                            rIJ = null;
                        } else {
                            rIJ = Lists.newArrayList();
                            for (int j = 0; j < r.get(inputGate.getIndex()).get(0).size(); j++) {
                                Element element1 = r.get(inputGate.getIndex()).get(0).get(j);
                                Element element2 = r.get(inputGate.getIndex()).get(1).get(j);

                                rIJ.add(element1.mul(element2));
                            }
                        }

                        elements.add(rIJ);

                        break;
                    }
                    case FO: {
                        int currentCounter = 0;
                        if (foGateCounterMapping.containsKey(inputGate.getIndex())) {
                            currentCounter = foGateCounterMapping.get(inputGate.getIndex()) + 1;
                        }
                        foGateCounterMapping.put(inputGate.getIndex(), currentCounter);

                        List<Element> rWK = Lists.newArrayList();
                        if (Lists.reverse(r.get(inputGate.getIndex())).get(currentCounter) == null) {
                            rWK = null;
                        } else {
                            for (int j = 0; j < Lists.reverse(r.get(inputGate.getIndex())).get(currentCounter).size(); j++) {
                                Element rkElement = Lists.reverse(r.get(inputGate.getIndex())).get(currentCounter).get(j);
                                Element pairingElement = pairing.pairing(Lists.reverse(secretKey.getPElementsAt(inputGate.getIndex())).get(j), gs);

                                rWK.add(rkElement.mul(pairingElement));
                            }
                        }

                        elements.add(rWK);

                        break;
                    }
                    default:
                        break;
                }

                List<List<Element>> elements = Lists.newArrayList();
                for (int i = 0; i < gate.getInputSize(); i++) {
                    FLTCCDDefaultGate inputGate = gate.getInputAt(i);

                    switch (inputGate.getType()) {
                        case OR: {
                            if (r.get(inputGate.getIndex()).get(0) == null) {
                                if (r.get(inputGate.getIndex()).get(1) == null) {
                                    elements.add(null);
                                } else {
                                    elements.add(r.get(inputGate.getIndex()).get(1));
                                }
                            } else {
                                elements.add(r.get(inputGate.getIndex()).get(0));
                            }

                            break;
                        }
                        case AND: {
                            List<Element> rIJ;
                            if (r.get(inputGate.getIndex()).get(0) == null || r.get(inputGate.getIndex()).get(1) == null) {
                                rIJ = null;
                            } else {
                                rIJ = Lists.newArrayList();
                                for (int j = 0; j < r.get(inputGate.getIndex()).get(0).size(); j++) {
                                    Element element1 = r.get(inputGate.getIndex()).get(0).get(j);
                                    Element element2 = r.get(inputGate.getIndex()).get(1).get(j);

                                    rIJ.add(element1.mul(element2));
                                }
                            }

                            elements.add(rIJ);

                            break;
                        }
                        case FO: {
                            int currentCounter = 0;
                            if (foGateCounterMapping.containsKey(inputGate.getIndex())) {
                                currentCounter = foGateCounterMapping.get(inputGate.getIndex()) + 1;
                            }
                            foGateCounterMapping.put(inputGate.getIndex(), currentCounter);

                            List<Element> rWK = Lists.newArrayList();
                            if (Lists.reverse(r.get(inputGate.getIndex())).get(currentCounter) == null) {
                                rWK = null;
                            } else {
                                for (int j = 0; j < Lists.reverse(r.get(inputGate.getIndex())).get(currentCounter).size(); j++) {
                                    Element rkElement = Lists.reverse(r.get(inputGate.getIndex())).get(currentCounter).get(j);
                                    Element pairingElement = pairing.pairing(Lists.reverse(secretKey.getPElementsAt(inputGate.getIndex())).get(j), gs);

                                    rWK.add(rkElement.mul(pairingElement));
                                }
                            }

                            elements.add(rWK);

                            break;
                        }
                        default:
                            break;
                    }
                }

                r.put(gate.getIndex(), elements);

                elements = Lists.newArrayList();
                if (gate.getIndex() == circuit.getOutputGate().getIndex()) {
                    switch (gate.getType()) {
                        case OR: {
                            if (r.get(gate.getIndex()).get(0) == null) {
                                if (r.get(gate.getIndex()).get(1) == null) {
                                    elements.add(null);
                                } else {
                                    elements.add(r.get(gate.getIndex()).get(1));
                                }
                            } else {
                                elements.add(r.get(gate.getIndex()).get(0));
                            }

                            break;
                        }
                        case AND: {
                            List<Element> rIJ;
                            if (r.get(gate.getIndex()).get(0) == null || r.get(gate.getIndex()).get(1) == null) {
                                rIJ = null;
                            } else {
                                rIJ = Lists.newArrayList();
                                for (int j = 0; j < r.get(gate.getIndex()).get(0).size(); j++) {
                                    Element element1 = r.get(gate.getIndex()).get(0).get(j);
                                    Element element2 = r.get(gate.getIndex()).get(1).get(j);

                                    rIJ.add(element1.mul(element2));
                                }
                            }

                            elements.add(rIJ);

                            break;
                        }
                        default:
                            break;
                    }

                    r.put(circuit.getOutputGate().getIndex() + 1, elements);
                }
            }
        }


        return r.get(circuit.getOutputGate().getIndex() + 1).get(0).get(0);
    }
}
