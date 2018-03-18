package com.company.abe.parameters;

import it.unisa.dia.gas.crypto.circuit.Circuit;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class FLTCCDSecretKeyParameters extends FLTCCDKeyParameters {
    private Circuit circuit;
    private Map<Integer, Element[]> s;
    private Map<Integer, Element[]> p;

    public FLTCCDSecretKeyParameters(boolean isPrivate, FLTCCDParameters parameters, Circuit circuit, Map<Integer, Element[]> s, Map<Integer, Element[]> p) {
        super(isPrivate, parameters);

        this.circuit = circuit;
        this.s = s;
        this.p = p;
    }

    public Circuit getCircuit() {
        return circuit;
    }

    public Element[] getSElementsAt(int index) {
        return this.s.get(index);
    }
    public Element[] getPElementsAt(int index) {
        return this.p.get(index);
    }

}
