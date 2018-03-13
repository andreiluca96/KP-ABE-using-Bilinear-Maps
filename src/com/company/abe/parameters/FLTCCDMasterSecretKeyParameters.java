package com.company.abe.parameters;

import it.unisa.dia.gas.jpbc.Element;

public class FLTCCDMasterSecretKeyParameters extends FLTCCDKeyParameters {
    private Element alpha;

    public FLTCCDMasterSecretKeyParameters(FLTCCDParameters parameters, Element alpha) {
        super(true, parameters);
        this.alpha = alpha.getImmutable();
    }

    public Element getAlpha() {
        return this.alpha;
    }
}
