package com.company;

//Generating a key using EdDSA Algorithm.

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;


public class jwsFinal {
    public static void main(String[] args) throws JOSEException {
        OctetKeyPair kpair = new OctetKeyPairGenerator(Curve.Ed25519).keyID("123").generate();//private key rn
        OctetKeyPair pub = kpair.toPublicJWK(); //converting to public

        JWSSigner signed = new Ed25519Signer(kpair); //takes parameter as private key pair<signing the kpair>
        //generating signature for kpr which will be appended to the jws object

        //key pair has been generated
        //now we will look after the payload and generate a jwe object
        JWSObject fn = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(kpair.getKeyID()).build(),
                new Payload("This is my first JWS Object Payload!"));
        fn.sign(signed);
        //object required jwsheader builder to firstly process the algo, find the keyid and then build it
        //object required payload; the message you want to show with the jws object

        //Searializing all of this in a rather compact form
        String kek = fn.serialize();
        System.out.println(kek);

        //the key is public and hence can be verified
        JWSVerifier verifier = new Ed25519Verifier(pub);//takes public key as parameter
        assertTrue("Ed25519 signature verified", fn.verify(verifier));//response
        assertEquals("This is my first JWS Object Payload!", fn.getPayload().toString()); //Since i know the payload

        System.out.println();
        System.out.println(fn.getHeader().toString());
        System.out.println(fn.getPayload().toString());
        System.out.println(fn.getSignature().toString());

    }
}
