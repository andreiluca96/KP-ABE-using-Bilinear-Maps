package com.company.abe.parameters;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

public class FLTCCDPublicKeyParameters extends FLTCCDKeyParameters {
    private Element H;
    private Element[] hs;

    public FLTCCDPublicKeyParameters(FLTCCDParameters parameters, Element H, Element[] hs) {
        super(false, parameters);
        this.H = H.getImmutable();
        this.hs = ElementUtils.cloneImmutable(hs);
    }

    public Element getH() {
        return this.H;
    }

    public Element getHAt(int index) {
        return this.hs[index];
    }
}
