package com.company.abe.kem;

import com.company.abe.circuit.FLTCCDDefaultCircuit;
import com.company.abe.kem.results.FLTCCDKEMEngineDecryptionResult;
import com.company.abe.kem.results.FLTCCDKEMEngineEncryptionResult;
import com.company.abe.kem.results.FLTCCDKEMEngineResult;
import com.company.abe.parameters.*;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.junit.Assert;

import java.util.List;
import java.util.Map;

import static com.company.abe.circuit.FLTCCDDefaultCircuit.*;
import static com.company.abe.circuit.FLTCCDDefaultCircuit.FLTCCDGateType.INPUT;
import static com.google.common.collect.Lists.newArrayList;

public class FLTCCDKEMEngine {
    private boolean forEncryption;
    private FLTCCDKeyParameters keyParameters;
    private Pairing pairing;

    public FLTCCDKEMEngine(boolean forEncryption, FLTCCDKeyParameters keyParameters) {
        this.forEncryption = forEncryption;
        this.keyParameters = keyParameters;

        if (this.forEncryption) {
            if (!(this.keyParameters instanceof FLTCCDEncryptionParameters)) {
                throw new IllegalArgumentException("FLTCCDEncryptionParameters are required for encryption.");
            }
        } else if (!(this.keyParameters instanceof FLTCCDDecryptionParameters)) {
            throw new IllegalArgumentException("GGHSW13SecretKeyParameters are required for decryption.");
        }

        this.pairing = keyParameters.getParameters().getPairing();
    }

    public FLTCCDKEMEngineResult process() {
        String assignment;
        if (this.keyParameters instanceof FLTCCDDecryptionParameters) {
            FLTCCDKEMEngineDecryptionResult decryptionResult = new FLTCCDKEMEngineDecryptionResult();


            // decryption phase
            FLTCCDDecryptionParameters decKey = (FLTCCDDecryptionParameters) this.keyParameters;
            FLTCCDSecretKeyParameters sk = decKey.getSecretKey();
            assignment = decKey.getAssignment();

            List<Element> e = decKey.getSecretKey().getEncryptionResult().getE();

            Map<Integer, List<Element>> vA = Maps.newHashMap();
            for (int i = 0; i < sk.getCircuit().getN(); i++) {
                List<Element> elements = Lists.newArrayList();

                for (int j = 0; j < decKey.getSecretKey().getDElementsAt(i).size(); j++) {
                    if (assignment.charAt(i) == '1') {
                        Element element1 = e.get(i).duplicate();
                        Element element2 = decKey.getSecretKey().getDElementsAt(i).get(j);
                        Element element = pairing.pairing(element1, element2);

                        elements.add(element);
                    } else {
                        elements.add(null);
                    }
                }
            }

            Element key = reconstruct(decKey.getSecretKey().getCircuit(), decKey.getSecretKey(), vA, decKey.getSecretKey().getEncryptionResult().getGs());
            decryptionResult.setKey(key);

            return decryptionResult;
        } else {
            FLTCCDKEMEngineEncryptionResult encryptionResult = new FLTCCDKEMEngineEncryptionResult();
            // encryption phase
            FLTCCDEncryptionParameters encKey = (FLTCCDEncryptionParameters) this.keyParameters;
            FLTCCDPublicKeyParameters publicKey = encKey.getPublicKey();
            assignment = encKey.getAssignment();

            Element s = this.pairing.getZr().newRandomElement().getImmutable();
            int n = publicKey.getParameters().getN();
            List<Element> e = Lists.newArrayList();

            for(int i = 0; i < n; ++i) {
                if (assignment.charAt(i) == '1') {
                    e.add(publicKey.getCapitalTAt(i).powZn(s));
                } else {
                    e.add(null);
                }
            }

            Element ys = this.pairing.getG1().newOneElement().powZn(s);

            encryptionResult.setE(e);
            encryptionResult.setYs(ys);

            return encryptionResult;
        }
    }

    private Element reconstruct(FLTCCDDefaultCircuit circuit, FLTCCDSecretKeyParameters secretKey, Map<Integer, List<Element>> vA, Element gs) {
        Map<Integer, List<Element>> r = Maps.newHashMap();

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
                        int outputGateIndex = getOutputGateIndex(bottomUpGates, gate);

                        Assert.assertEquals(r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).size(),
                                r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).size());
                        List<Element> elements = Lists.newArrayList();
                        for (int i = 0; i < r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).size(); i++) {
                            if (r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).get(i) == null) {
                                if (r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).get(i) == null) {
                                    elements.add(null);
                                } else {
                                    elements.add(r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).get(i).duplicate());
                                }
                            } else {
                                Assert.assertEquals(r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).get(i),
                                        r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).get(i));
                                elements.add(r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).get(i).duplicate());
                            }
                        }

                        r.put(circuit.getWireIndex(gate.getIndex(), outputGateIndex), elements);

                        break;
                    }
                    case AND: {
                        int outputGateIndex = getOutputGateIndex(bottomUpGates, gate);

                        Assert.assertEquals(r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).size(),
                                r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).size());

                        List<Element> elements = Lists.newArrayList();
                        for (int i = 0; i < r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).size(); i++) {
                            if (r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).get(i) == null ||
                                    r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).get(i) == null) {
                                elements.add(null);
                            } else {
                                Assert.assertEquals(r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).get(i),
                                        r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).get(i));

                                Element element1 = r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(0))).get(i).duplicate();
                                Element element2 = r.get(circuit.getWireIndex(gate.getIndex(), gate.getInputIndexAt(1))).get(i).duplicate();

                                elements.add(element1.mul(element2));
                            }
                        }

                        r.put(circuit.getWireIndex(gate.getIndex(), outputGateIndex), elements);

                        break;
                    }
                    case FO: {
                        List<Integer> foGateIndexes = getFOGateIndexes(bottomUpGates, gate);

                        // splitting
                        Map<Integer, List<Element>> splittedRs = Maps.newHashMap();
                        List<Element> gateRs = r.get(circuit.getWireIndex(gate.getInputIndexAt(0), gate.getIndex()));
                        for (int i = 0; i < foGateIndexes.size(); i++) {
                            int wireIndex = circuit.getWireIndex(gate.getIndex(), foGateIndexes.get(i));
                            int listSize = secretKey.getPElementsAt(wireIndex).size();

                            splittedRs.put(wireIndex, gateRs.subList(0, listSize));
                            gateRs.subList(listSize, gateRs.size());
                        }

                        for (int i = 0; i < foGateIndexes.size(); i++) {
                            int wireIndex = circuit.getWireIndex(gate.getIndex(), foGateIndexes.get(i));

                            List<Element> elements = Lists.newArrayList();
                            for (int j = 0; j < splittedRs.get(wireIndex).size(); j++) {
                                Element element = splittedRs.get(wireIndex).get(j).duplicate().mul(pairing.pairing(secretKey.getPElementsAt(wireIndex).get(j), gs));
                                elements.add(element);
                            }
                            r.put(circuit.getWireIndex(gate.getIndex(), wireIndex), elements);
                        }

                        break;
                    }
                    default:
                        break;
                }
            }
        }


        return r.get(circuit.getWireIndex(circuit.getOutputGate().getIndex(), -1)).get(0);
    }

    private int getOutputGateIndex(List<FLTCCDDefaultGate> bottomUpGates, FLTCCDDefaultGate gate) {
        int outputGateIndex = -1;
        for (FLTCCDDefaultGate outputGate : bottomUpGates) {
            for (int i = 0; i < outputGate.getInputSize(); i++) {
                if (outputGate.getInputIndexAt(i) == gate.getIndex()) {
                    outputGateIndex = outputGate.getIndex();

                    break;
                }
            }
        }

        return outputGateIndex;
    }

    private List<Integer> getFOGateIndexes(List<FLTCCDDefaultGate> bottomUpGates, FLTCCDDefaultGate gate) {
        List<Integer> foGateIndexes = Lists.newArrayList();
        for (FLTCCDDefaultGate outputGate : Lists.reverse(bottomUpGates)) {
            for (int i = 0; i < outputGate.getInputSize(); i++) {
                if (outputGate.getInputIndexAt(i) == gate.getIndex()) {
                    foGateIndexes.add(outputGate.getIndex());
                }
            }
        }

        return foGateIndexes;
    }
}
