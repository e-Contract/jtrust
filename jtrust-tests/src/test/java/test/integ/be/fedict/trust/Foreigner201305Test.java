/*
 * Java Trust Project.
 * Copyright (C) 2013 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.
 */

package test.integ.be.fedict.trust;

import static org.junit.Assert.assertEquals;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

public class Foreigner201305Test {

    private static final Log LOG = LogFactory.getLog(Foreigner201305Test.class);

    @Test
    public void testForeigner201305() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate rootCert = (X509Certificate) certificateFactory.generateCertificate(Foreigner201305Test.class.getResourceAsStream("/belgiumrca2.crt"));
        X509Certificate foreigner201304Cert = (X509Certificate) certificateFactory.generateCertificate(Foreigner201305Test.class.getResourceAsStream("/foreigner201304.crt"));

        foreigner201304Cert.verify(rootCert.getPublicKey());

        X509Certificate foreigner201305Cert = (X509Certificate) certificateFactory.generateCertificate(Foreigner201305Test.class.getResourceAsStream("/foreigner201305.crt"));

        foreigner201305Cert.verify(rootCert.getPublicKey());

        byte[] foreigner201304SignatureValue = foreigner201304Cert.getSignature();
        byte[] foreigner201305SignatureValue = foreigner201305Cert.getSignature();
        LOG.debug("201304 signature size: " + foreigner201304SignatureValue.length);
        LOG.debug("201305 signature size: " + foreigner201305SignatureValue.length);

        RSAPublicKey rootPublicKey = (RSAPublicKey) rootCert.getPublicKey();

        BigInteger foreigner201304Signature = new BigInteger(foreigner201304SignatureValue);
        BigInteger foreigner201305Signature = new BigInteger(foreigner201305SignatureValue);

        LOG.debug("201305 signature size: " + foreigner201305Signature.toByteArray().length);

        BigInteger foreigner201304PaddedMessage = foreigner201304Signature.modPow(rootPublicKey.getPublicExponent(), rootPublicKey.getModulus());
        BigInteger foreigner201305PaddedMessage = foreigner201305Signature.modPow(rootPublicKey.getPublicExponent(), rootPublicKey.getModulus());

        LOG.debug("201304 padded message: " + new String(Hex.encodeHex(foreigner201304PaddedMessage.toByteArray())));
        LOG.debug("201305 padded message: " + new String(Hex.encodeHex(foreigner201305PaddedMessage.toByteArray())));

        LOG.debug("201304 modulus size: " + ((RSAPublicKey)foreigner201304Cert.getPublicKey()).getModulus().toByteArray().length);
        LOG.debug("201305 modulus size: " + ((RSAPublicKey)foreigner201305Cert.getPublicKey()).getModulus().toByteArray().length);
        LOG.debug("201304 modulus: " + new String(Hex.encodeHex(((RSAPublicKey)foreigner201304Cert.getPublicKey()).getModulus().toByteArray())));
        LOG.debug("201305 modulus: " + new String(Hex.encodeHex(((RSAPublicKey)foreigner201305Cert.getPublicKey()).getModulus().toByteArray())));
    }

    /**
     * wget --recursive -e robots=off http://certs.eid.belgium.be
     * 
     * @throws Exception
     */
    @Test
    public void testAllCertificateAuthorities() throws Exception {
        File dirFile = new File("/home/fcorneli/certs/certs.eid.belgium.be");
        LOG.debug("directory: " + dirFile.getAbsolutePath());
        File[] certFiles = dirFile.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                LOG.debug(name);
                return name.endsWith("crt");
            }
        });
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        for (File certFile : certFiles) {
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(certFile));
            LOG.debug("certificate: " + certificate.getSubjectX500Principal());
            RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
            int modulusSize = rsaPublicKey.getModulus().toByteArray().length;
            LOG.debug("modulus size: " + modulusSize);
            int signatureSize = certificate.getSignature().length;
            LOG.debug("signature size: " + signatureSize);
            assertEquals(modulusSize -1, signatureSize);
        }
        LOG.debug("total number of CAs: " + certFiles.length);
    }
}
