/*
 * Java Trust Project.
 * Copyright (C) 2013 FedICT.
 * Copyright (C) 2019-2022 e-Contract.be BV.
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

import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Foreigner201305Test {

	private static final Logger LOGGER = LoggerFactory.getLogger(Foreigner201305Test.class);

	@Test
	public void testForeigner201305() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate rootCert = (X509Certificate) certificateFactory
				.generateCertificate(Foreigner201305Test.class.getResourceAsStream("/belgiumrca2.crt"));
		X509Certificate foreigner201304Cert = (X509Certificate) certificateFactory
				.generateCertificate(Foreigner201305Test.class.getResourceAsStream("/foreigner201304.crt"));

		foreigner201304Cert.verify(rootCert.getPublicKey());

		X509Certificate foreigner201305Cert = (X509Certificate) certificateFactory
				.generateCertificate(Foreigner201305Test.class.getResourceAsStream("/foreigner201305.crt"));

		foreigner201305Cert.verify(rootCert.getPublicKey());

		byte[] foreigner201304SignatureValue = foreigner201304Cert.getSignature();
		byte[] foreigner201305SignatureValue = foreigner201305Cert.getSignature();
		LOGGER.debug("201304 signature size: {}", foreigner201304SignatureValue.length);
		LOGGER.debug("201305 signature size: {}", foreigner201305SignatureValue.length);

		RSAPublicKey rootPublicKey = (RSAPublicKey) rootCert.getPublicKey();

		BigInteger foreigner201304Signature = new BigInteger(foreigner201304SignatureValue);
		BigInteger foreigner201305Signature = new BigInteger(foreigner201305SignatureValue);

		LOGGER.debug("201305 signature size: {}", foreigner201305Signature.toByteArray().length);

		BigInteger foreigner201304PaddedMessage = foreigner201304Signature.modPow(rootPublicKey.getPublicExponent(),
				rootPublicKey.getModulus());
		BigInteger foreigner201305PaddedMessage = foreigner201305Signature.modPow(rootPublicKey.getPublicExponent(),
				rootPublicKey.getModulus());

		LOGGER.debug("201304 padded message: {}",
				new String(Hex.encodeHex(foreigner201304PaddedMessage.toByteArray())));
		LOGGER.debug("201305 padded message: {}",
				new String(Hex.encodeHex(foreigner201305PaddedMessage.toByteArray())));

		LOGGER.debug("201304 modulus size: {}",
				((RSAPublicKey) foreigner201304Cert.getPublicKey()).getModulus().toByteArray().length);
		LOGGER.debug("201305 modulus size: {}",
				((RSAPublicKey) foreigner201305Cert.getPublicKey()).getModulus().toByteArray().length);
		LOGGER.debug("201304 modulus: {}", new String(
				Hex.encodeHex(((RSAPublicKey) foreigner201304Cert.getPublicKey()).getModulus().toByteArray())));
		LOGGER.debug("201305 modulus: {}", new String(
				Hex.encodeHex(((RSAPublicKey) foreigner201305Cert.getPublicKey()).getModulus().toByteArray())));
	}
}
