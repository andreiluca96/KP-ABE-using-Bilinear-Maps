package com.company.abe.generators;

import com.company.abe.parameters.FLTCCDKeyPairGenerationParameters;
import com.company.abe.parameters.FLTCCDParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13MasterSecretKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.abe.gghsw13.params.GGHSW13PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class FLTCCDKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    FLTCCDKeyPairGenerationParameters parameters;

    @Override
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (FLTCCDKeyPairGenerationParameters) keyGenerationParameters;
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair() {
        FLTCCDParameters parameters = this.parameters.getParameters();

        Pairing pairing = parameters.getPairing();

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        int n = parameters.getN();
        Element[] hs = new Element[n];

        for(int i = 0; i < hs.length; ++i) {
            hs[i] = pairing.getFieldAt(1).newRandomElement().getImmutable();
        }

        Element H = pairing.getFieldAt(pairing.getDegree()).newElement().powZn(alpha).getImmutable();
        return new AsymmetricCipherKeyPair(new GGHSW13PublicKeyParameters(parameters, H, hs), new GGHSW13MasterSecretKeyParameters(parameters, alpha));    }
}
