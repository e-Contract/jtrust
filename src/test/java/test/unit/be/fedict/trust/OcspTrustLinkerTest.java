/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
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

package test.unit.be.fedict.trust;

import static org.junit.Assert.assertNull;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.trust.OcspTrustLinker;

public class OcspTrustLinkerTest {

	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void noOcspUriInCertificate() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test", notBefore, notAfter, rootCertificate,
				rootKeyPair.getPrivate());

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker();
		Boolean result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, null);

		assertNull(result);
	}
	
	@Test
	public void ocspUriInCertificate() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test", notBefore, notAfter, rootCertificate,
				rootKeyPair.getPrivate(), false, -1, null, "ocsp-uri");

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker();
		Boolean result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, null);

		assertNull(result);
	}
}
