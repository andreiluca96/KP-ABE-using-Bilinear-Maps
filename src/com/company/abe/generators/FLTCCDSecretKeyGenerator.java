package com.company.abe.generators;

import com.company.abe.circuit.FLTCCDDefaultCircuit;
import com.company.abe.parameters.FLTCCDMasterSecretKeyParameters;
import com.company.abe.parameters.FLTCCDPublicKeyParameters;
import com.company.abe.parameters.FLTCCDSecretKeyGenerationParameters;
import com.company.abe.parameters.FLTCCDSecretKeyParameters;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.junit.Assert;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.company.abe.circuit.FLTCCDDefaultCircuit.*;
import static com.google.common.collect.Lists.*;

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

        // create S and P mapping
        final Map<Integer, List<Element>> s = new HashMap<>();
        final Map<Integer, List<Element>> p = new HashMap<>();


        // Put y to the output gate for the S mapping
        Element y = msk.getY();

        // Parse the gates in top-down order
        List<FLTCCDDefaultGate> topDownGates = reverse(newArrayList(circuit.iterator()));
        for (FLTCCDDefaultGate gate : topDownGates) {
            switch (gate.getType()) {
                case OR: {
                    List<Element> elements = getSimpleGateElements(s, y, topDownGates, gate);

                    s.put(this.circuit.getWireIndex(gate.getInputIndexAt(0), gate.getIndex()), elements);
                    s.put(this.circuit.getWireIndex(gate.getInputIndexAt(1), gate.getIndex()), elements);

                    break;
                }
                case AND: {
                    List<Element> elements = getSimpleGateElements(s, y, topDownGates, gate);

                    List<Element> l1 = Lists.newArrayList();
                    List<Element> l2 = Lists.newArrayList();

                    for (Element element : elements) {
                        Element x1 = pairing.getZr()
                                .newRandomElement();
                        Element x2 = x1.duplicate()
                                        .negate()
                                        .add(element.duplicate());

                        l1.add(x1);
                        l2.add(x2);
                    }

                    s.put(this.circuit.getWireIndex(gate.getInputIndexAt(0), gate.getIndex()), l1);
                    s.put(this.circuit.getWireIndex(gate.getInputIndexAt(1), gate.getIndex()), l2);

                    break;
                }
                case FO: {
                    Map<Integer, List<Element>> elements = getFOGateElements(s, y, topDownGates, gate);
                    List<Element> sElements = Lists.newArrayList();

                    for (Map.Entry<Integer, List<Element>> entry : elements.entrySet()) {
                        List<Element> pElements = Lists.newArrayList();
                        for (Element element : entry.getValue()) {
                            Element x1 = pairing.getZr()
                                    .newRandomElement();
                            Element x2 = x1.duplicate().negate().add(element);

                            sElements.add(x1);
                            pElements.add(pairing.getG1().newOneElement().powZn(x2));
                        }

                        p.put(entry.getKey(), pElements);
                    }

                    s.put(this.circuit.getWireIndex(gate.getInputIndexAt(0), gate.getIndex()), sElements);

                    break;
                }
                case INPUT: {

                    break;
                }
                default: break;
            }
        }

        Map<Integer, List<Element>> d = Maps.newHashMap();
        for (int i = 0; i < circuit.getN(); i++) {
            d.put(i, Lists.newArrayList());
            List<Element> elements = getSimpleGateElements(s, y, topDownGates, this.circuit.getGateAt(i));

            for (int j = 0; j < elements.size(); j++) {
                Element dElement = pairing.getG1()
                        .newOneElement()
                        .powZn(elements.get(j))
                        .powZn(params.getPublicKeyParameters().getCapitalTAt(i));

                d.get(i).add(dElement);
            }
        }

        return new FLTCCDSecretKeyParameters(pp.getParameters(), circuit, d, p, params.getEncryptionResult());
    }

    private List<Element> getSimpleGateElements(Map<Integer, List<Element>> s, Element y, List<FLTCCDDefaultGate> topDownGates, FLTCCDDefaultGate gate) {
        List<Element> elements = Lists.newArrayList();
        if (gate.getIndex() == this.circuit.getOutputGate().getIndex()) {
            elements = Lists.newArrayList(y);
        } else {
            for (FLTCCDDefaultGate outputGate : topDownGates) {
                if (outputGate.getType() == FLTCCDGateType.INPUT) {
                    continue;
                }
                for (int i = 0; i < outputGate.getInputSize(); i++) {
                    if (outputGate.getInputIndexAt(i) == gate.getIndex()) {
                        elements = s.get(this.circuit.getWireIndex(gate.getIndex(), outputGate.getIndex()));
                        break;
                    }
                }
            }
        }
        return elements;
    }

    private Map<Integer, List<Element>> getFOGateElements(Map<Integer, List<Element>> s, Element y, List<FLTCCDDefaultGate> topDownGates, FLTCCDDefaultGate gate) {
        Map<Integer, List<Element>> elements = Maps.newHashMap();

        if (gate.getIndex() == this.circuit.getOutputGate().getIndex()) {
            Assert.fail();
        } else {
            for (FLTCCDDefaultGate outputGate : topDownGates) {
                if (outputGate.getType() == FLTCCDGateType.INPUT) {
                    continue;
                }
                for (int i = 0; i < outputGate.getInputSize(); i++) {
                    if (outputGate.getInputIndexAt(i) == gate.getIndex()) {
                        elements.put(this.circuit.getWireIndex(gate.getIndex(), outputGate.getIndex()), s.get(this.circuit.getWireIndex(gate.getIndex(), outputGate.getIndex())));
                    }
                }
            }
        }

        return elements;
    }
}
