package com.company.abe.generators;

import com.company.abe.circuit.FLTCCDDefaultCircuit;
import com.company.abe.parameters.FLTCCDMasterSecretKeyParameters;
import com.company.abe.parameters.FLTCCDPublicKeyParameters;
import com.company.abe.parameters.FLTCCDSecretKeyGenerationParameters;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

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


        return null;
    }
}
