package com.company.abe.parameters;

import it.unisa.dia.gas.crypto.circuit.Circuit;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class FLTCCDSecretKeyGenerationParameters extends KeyGenerationParameters{
    private FLTCCDPublicKeyParameters publicKeyParameters;
    private FLTCCDMasterSecretKeyParameters masterSecretKeyParameters;
    private Circuit circuit;

    public FLTCCDSecretKeyGenerationParameters(FLTCCDPublicKeyParameters publicKeyParameters, FLTCCDMasterSecretKeyParameters masterSecretKeyParameters, Circuit circuit) {
        super(null, 0);
        this.publicKeyParameters = publicKeyParameters;
        this.masterSecretKeyParameters = masterSecretKeyParameters;
        this.circuit = circuit;
    }

    public FLTCCDPublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public FLTCCDMasterSecretKeyParameters getMasterSecretKeyParameters() {
        return this.masterSecretKeyParameters;
    }

    public Circuit getCircuit() {
        return this.circuit;
    }
}
