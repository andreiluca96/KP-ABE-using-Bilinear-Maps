package com.company.abe.generators;

import com.company.abe.circuit.FLTCCDDefaultCircuit;
import com.company.abe.parameters.FLTCCDMasterSecretKeyParameters;
import com.company.abe.parameters.FLTCCDPublicKeyParameters;
import com.company.abe.parameters.FLTCCDSecretKeyGenerationParameters;
import com.company.abe.parameters.FLTCCDSecretKeyParameters;
import com.google.common.collect.Lists;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.company.abe.circuit.FLTCCDDefaultCircuit.*;
import static com.google.common.collect.Lists.*;
import static org.junit.Assert.assertEquals;

public class FLTCCDSecretKeyGenerator {
    private FLTCCDSecretKeyGenerationParameters params;
    private Pairing pairing;
    private FLTCCDDefaultCircuit circuit;

    public FLTCCDSecretKeyGenerator() {
    }

    public void init(KeyGenerationParameters params) {
        this.params = (FLTCCDSecretKeyGenerationParameters)params;
        this.pairing = this.params.getMasterSecretKeyParameters().getParameters().getPairing();
        this.circuit = this.params.getCircuit();
    }

    public CipherParameters generateKey() {
        FLTCCDMasterSecretKeyParameters msk = this.params.getMasterSecretKeyParameters();
        FLTCCDPublicKeyParameters pp = this.params.getPublicKeyParameters();

        FLTCCDDefaultCircuit circuit = this.circuit;

        // create S mapping
        final Map<Integer, List<List<Element>>> s = new HashMap<>();
        final Map<Integer, List<Element>> p = new HashMap<>();


        // Put y to the output gate for the S mapping
        List<List<Element>> elements = newArrayList();
        elements.add(newArrayList(params.getMasterSecretKeyParameters().getY()));
        s.put(circuit.getOutputGate().getIndex(), elements);

        // Parse the gates in top-down order
        List<FLTCCDDefaultGate> topDownGates = reverse(newArrayList(circuit.iterator()));
        for (FLTCCDDefaultGate gate : topDownGates) {
            switch (gate.getType()) {
                case OR: {
                    for (int i = 0; i < gate.getInputSize(); i++) {
                        s.put(gate.getInputIndexAt(i), s.get(gate.getIndex()));
                    }

                    break;
                }
                case AND: {
                    elements = newArrayList();
                    elements.add(newArrayList());
                    elements.add(newArrayList());

                    for (int j = 0; j < s.get(gate.getIndex()).get(0).size(); j++) {
                        Element x1 = pairing.getZr()
                                .newRandomElement();
                        Element x2 = pairing.getZr()
                                .newElement(x1.toBigInteger().negate().add(s.get(gate.getIndex()).get(0).get(j).toBigInteger()));

                        elements.get(0).add(x1);
                        elements.get(1).add(x2);
                    }

                    s.put(gate.getIndex(), elements);

                    break;
                }
                case FO: {
                    elements = newArrayList();
                    elements.add(newArrayList());

                    List<Element> pElements = newArrayList();

                    for (FLTCCDDefaultGate foInputGate : topDownGates) {
                        for (int i = 0; i < foInputGate.getInputSize(); i++) {
                            if (foInputGate.getInputAt(i).getIndex() == gate.getIndex()) {
                                for (int j = 0; j < s.get(foInputGate.getIndex()).get(i).size(); j++) {
                                    Element x1 = pairing.getZr()
                                            .newRandomElement();
                                    Element x2 = pairing.getZr()
                                            .newElement(x1.toBigInteger().negate().add(s.get(foInputGate.getIndex()).get(i).get(j).toBigInteger()));

                                    elements.get(0).add(x1);
                                    pElements.add(pairing.getG1().newOneElement().powZn(x2));
                                }
                            }
                        }
                    }

                    s.put(gate.getIndex(), elements);
                    p.put(gate.getIndex(), pElements);

                    break;
                }
                case INPUT: {
                    elements = newArrayList();

                    for (FLTCCDDefaultGate inputInputGate : topDownGates) {
                        for (int i = 0; i < inputInputGate.getInputSize(); i++) {
                            if (inputInputGate.getInputAt(i).getIndex() == gate.getIndex()) {
                                elements.add(s.get(inputInputGate.getIndex()).get(i));
                                break;
                            }
                        }
                    }

                    s.put(gate.getIndex(), elements);

                    break;
                }
                default: break;
            }
        }

        List<List<Element>> d = Lists.newArrayList();
        for (int i = 0; i < circuit.getN(); i++) {
            assertEquals(s.get(i).size(), 1);
            d.add(Lists.newArrayList());
            for (int j = 0; j < s.get(i).get(0).size(); j++) {
                Element dElement = pairing.getG1()
                        .newOneElement()
                        .powZn(s.get(i).get(0).get(j))
                        .powZn(params.getPublicKeyParameters().getCapitalTAt(i));

                d.get(i).add(dElement);
            }
        }

        return new FLTCCDSecretKeyParameters(this.params.getPublicKeyParameters().getParameters(), circuit, d, p);
    }
}
