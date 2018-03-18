package com.company.abe.parameters;

import com.company.abe.circuit.FLTCCDDefaultCircuit;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class FLTCCDSecretKeyGenerationParameters extends KeyGenerationParameters{
    private FLTCCDPublicKeyParameters publicKeyParameters;
    private FLTCCDMasterSecretKeyParameters masterSecretKeyParameters;
    private FLTCCDDefaultCircuit circuit;

    public FLTCCDSecretKeyGenerationParameters(FLTCCDPublicKeyParameters publicKeyParameters, FLTCCDMasterSecretKeyParameters masterSecretKeyParameters, FLTCCDDefaultCircuit circuit) {
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

    public FLTCCDDefaultCircuit getCircuit() {
        return this.circuit;
    }
}
