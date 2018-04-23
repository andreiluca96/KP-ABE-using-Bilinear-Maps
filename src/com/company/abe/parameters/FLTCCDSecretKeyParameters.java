package com.company.abe.parameters;

import com.company.abe.circuit.FLTCCDDefaultCircuit;
import it.unisa.dia.gas.jpbc.Element;

import java.util.List;
import java.util.Map;

public class FLTCCDSecretKeyParameters extends FLTCCDKeyParameters {
    private FLTCCDDefaultCircuit circuit;
    private Map<Integer, List<Element>> d;
    private Map<Integer, List<Element>> p;

    public FLTCCDSecretKeyParameters(FLTCCDParameters parameters, FLTCCDDefaultCircuit circuit,
                                     Map<Integer, List<Element>> d, Map<Integer, List<Element>> p) {
        super(true, parameters);

        this.circuit = circuit;
        this.d = d;
        this.p = p;
    }

    public FLTCCDDefaultCircuit getCircuit() {
        return circuit;
    }

    public List<Element> getDElementsAt(int index) {
        return this.d.get(index);
    }
    public List<Element> getPElementsAt(int index) {
        return this.p.get(index);
    }
}
