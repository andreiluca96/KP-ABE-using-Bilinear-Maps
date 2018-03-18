package com.company.abe.circuit;

import java.util.Arrays;
import java.util.Iterator;

public class FLTCCDDefaultCircuit {
    private int n;
    private int q;
    private int depth;
    private FLTCCDDefaultGate[] gates;

    public FLTCCDDefaultCircuit(int n, int q, int depth, FLTCCDDefaultGate[] gates) {
        this.n = n;
        this.q = q;
        this.depth = depth;
        this.gates = gates;
        FLTCCDDefaultGate[] arr$ = gates;
        int len$ = gates.length;

        for(int i$ = 0; i$ < len$; ++i$) {
            FLTCCDDefaultGate gate = arr$[i$];
            gate.setCircuit(this);
        }
    }

    public int getN() {
        return n;
    }

    public int getQ() {
        return q;
    }


    public int getDepth() {
        return depth;
    }

    public Iterator<FLTCCDDefaultGate> iterator() {
        return Arrays.asList(gates).iterator();
    }

    public FLTCCDDefaultGate getGateAt(int i) {
        return this.gates[i];
    }

    public FLTCCDDefaultGate getOutputGate() {
        return this.gates[this.n + this.q - 1];
    }

    public static class FLTCCDDefaultGate {
        private FLTCCDDefaultCircuit circuit;
        private FLTCCDGateType type;
        private int index;
        private int depth;
        private int[] inputs;
        private boolean value;

        public FLTCCDDefaultGate(FLTCCDGateType type, int index, int depth) {
            this.type = type;
            this.index = index;
            this.depth = depth;
        }

        public FLTCCDDefaultGate(FLTCCDGateType type, int index, int depth, int[] inputs) {
            this.type = type;
            this.index = index;
            this.depth = depth;
            this.inputs = Arrays.copyOf(inputs, inputs.length);
        }

        public FLTCCDGateType getType() {
            return this.type;
        }

        public int getIndex() {
            return this.index;
        }

        public int getDepth() {
            return this.depth;
        }

        public int getInputIndexAt(int index) {
            return this.inputs[index];
        }

        public FLTCCDDefaultGate getInputAt(int index) {
            return this.circuit.getGateAt(this.getInputIndexAt(index));
        }

        public void set(boolean value) {
            this.value = value;
        }

        public boolean isSet() {
            return this.value;
        }

        public FLTCCDDefaultGate evaluate() {
            switch(this.type) {
                case AND:
                    this.value = this.getInputAt(0).isSet() && this.getInputAt(1).isSet();
                    break;
                case OR:
                    this.value = this.getInputAt(0).isSet() || this.getInputAt(1).isSet();
                    break;
                default:
                    throw new IllegalStateException("Invalid type to be evaluated.");
            }

            return this;
        }

        public String toString() {
            return "Gate{type=" + this.type + ", index=" + this.index + ", depth=" + this.depth + ", inputs=" + Arrays.toString(this.inputs) + ", value=" + this.value + '}';
        }

        protected void setCircuit(FLTCCDDefaultCircuit circuit) {
            this.circuit = circuit;
        }
    }

    public enum FLTCCDGateType {
        INPUT,
        AND,
        OR,
        FO;
    }
}
