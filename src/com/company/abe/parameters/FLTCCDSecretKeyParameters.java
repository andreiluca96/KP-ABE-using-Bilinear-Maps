package com.company.abe.parameters;

import com.company.abe.circuit.FLTCCDDefaultCircuit;
import it.unisa.dia.gas.jpbc.Element;

import java.util.List;
import java.util.Map;

public class FLTCCDSecretKeyParameters extends FLTCCDKeyParameters {
    private FLTCCDDefaultCircuit circuit;
    private Map<Integer, List<Element[]>> s;
    private Map<Integer, List<Element[]>> p;

    public FLTCCDSecretKeyParameters(FLTCCDParameters parameters, FLTCCDDefaultCircuit circuit,
                                     Map<Integer, List<Element[]>> s,
                                     Map<Integer, List<Element[]>> p) {
        super(true, parameters);

        this.circuit = circuit;
        this.s = s;
        this.p = p;
    }

    public FLTCCDDefaultCircuit getCircuit() {
        return circuit;
    }

    public List<Element[]> getSElementsAt(int index) {
        return this.s.get(index);
    }
    public List<Element[]> getPElementsAt(int index) {
        return this.p.get(index);
    }
}
