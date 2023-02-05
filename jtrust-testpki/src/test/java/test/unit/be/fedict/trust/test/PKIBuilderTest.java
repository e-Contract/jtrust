/*
 * Java Trust Project.
 * Copyright (C) 2023 e-Contract.be BV.
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
package test.unit.be.fedict.trust.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

import be.fedict.trust.test.PKIBuilder;

public class PKIBuilderTest {

	@Test
	public void testBuildRSAKeyPair() throws Exception {
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		assertEquals("RSA", keyPair.getPublic().getAlgorithm());
	}

	@Test
	public void testBuildECKeyPair() throws Exception {
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().withKeyAlgorithm("EC").build();
		assertEquals("EC", keyPair.getPublic().getAlgorithm());
	}

	@Test
	public void testBuildCertificate() throws Exception {
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair).build();
		assertNotNull(certificate);
	}

	@Test
	public void testBuildCertificateWith() throws Exception {
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair) //
				.withSubjectName("CN=hehe") //
				.withBasicConstraints(5) //
				.withCertificatePolicy("1.2.3.4") //
				.withValidityYears(2) //
				.withCrlUri("https://crl") //
				.withOcspUri("https://ocsp") //
				.withOcspResponder() //
				.withQCCompliance() //
				.withQCRetentionPeriod() //
				.withQCSSCD() //
				.withTimeStamping() //
				.build();
		assertNotNull(certificate);
	}

	@Test
	public void testBuildPKI() throws Exception {
		KeyPair rootCaKeyPair = new PKIBuilder.KeyPairBuilder().withKeyAlgorithm("EC").build();
		X509Certificate rootCaCert = new PKIBuilder.CertificateBuilder(rootCaKeyPair) //
				.withSubjectName("CN=Root CA, C=BE") //
				.withBasicConstraints(2) //
				.withCertificatePolicy("1.2.3.4") //
				.withCrlUri("http://rootCrl") //
				.withValidityYears(30) //
				.build();

		KeyPair caKeyPair = new PKIBuilder.KeyPairBuilder().withKeyAlgorithm("EC").build();
		X509Certificate caCert = new PKIBuilder.CertificateBuilder(caKeyPair.getPublic(), rootCaKeyPair.getPrivate(),
				rootCaCert) //
				.withSubjectName("CN=Intermediate CA, C=BE") //
				.withBasicConstraints(1) //
				.withCertificatePolicy("1.2.3.4.5") //
				.withCrlUri("http://caCrl") //
				.withOcspUri("https://ocsp") //
				.withValidityYears(20) // ·
				.build();
		assertNotNull(caCert);
	}
}
