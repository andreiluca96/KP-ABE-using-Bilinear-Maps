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

        // Put y to the output gate for the S mapping
        List<List<Element>> elements = Lists.newArrayList();
        elements.add(Lists.newArrayList(params.getMasterSecretKeyParameters().getY()));
        s.put(circuit.getOutputGate().getIndex(), elements);

        // Parse the gates in top-down order
        List<FLTCCDDefaultGate> topDownGates = Lists.reverse(Lists.newArrayList(circuit.iterator()));
        for (FLTCCDDefaultGate gate : topDownGates) {
            switch (gate.getType()) {
                case OR: {
                    for (int i = 0; i < gate.getInputSize(); i++) {
                        s.put(gate.getInputIndexAt(i), s.get(gate.getIndex()));
                    }
                    break;
                }
                case AND: {
                    elements = Lists.newArrayList();
                    elements.add(Lists.newArrayList());
                    elements.add(Lists.newArrayList());

                    for (int j = 0; j < s.get(gate.getIndex()).size(); j++) {
                        Element x1 = pairing.getG1()
                                .newRandomElement();
                        Element x2 = x1.duplicate()
                                .negate()
                                .add(s.get(gate.getIndex()).get(0).get(j));

                        elements.get(0).add(x1);
                        elements.get(1).add(x2);
                    }

                    s.put(gate.getIndex(), elements);

                    break;
                }
                case FO: {
                    break;
                }
                case INPUT: {
                    break;
                }
                default: break;
            }
        }

        final Map<Integer, List<List<Element>>> p = new HashMap<>();



        return new FLTCCDSecretKeyParameters(this.params.getPublicKeyParameters().getParameters(), circuit, s, p);
    }
}
