/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2015-2023 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.easymock.EasyMock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import be.fedict.trust.crl.CachedCrlRepository;
import be.fedict.trust.crl.CrlRepository;
import be.fedict.trust.test.PKIBuilder;

public class CachedCrlRepositoryTest {

	private X509CRL testCrl;
	private X509CRL testCrl2;
	private X509Certificate testCertificate;
	private KeyPair testKeyPair;

	@BeforeEach
	public void setup() throws Exception {
		this.testKeyPair = new PKIBuilder.KeyPairBuilder().build();
		this.testCertificate = new PKIBuilder.CertificateBuilder(this.testKeyPair).withValidityMonths(1).build();
		this.testCrl = new PKIBuilder.CRLBuilder(this.testKeyPair.getPrivate(), this.testCertificate).build();
		this.testCrl2 = new PKIBuilder.CRLBuilder(this.testKeyPair.getPrivate(), this.testCertificate).build();
	}

	@Test
	public void emptyCache() throws Exception {
		// setup
		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();

		CachedCrlRepository testedInstance = new CachedCrlRepository(mockCrlRepository);

		// expectations
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, this.testCertificate, validationDate))
				.andReturn(this.testCrl);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri, this.testCertificate, validationDate);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(this.testCrl, resultCrl);
	}

	@Test
	public void cacheBeingUsed() throws Exception {
		// setup
		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();

		CachedCrlRepository testedInstance = new CachedCrlRepository(mockCrlRepository);

		// expectations
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, this.testCertificate, validationDate))
				.andReturn(this.testCrl);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri, this.testCertificate, validationDate);
		X509CRL resultCrl2 = testedInstance.findCrl(crlUri, this.testCertificate, validationDate);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(this.testCrl, resultCrl);
		assertEquals(this.testCrl, resultCrl2);
	}

	@Test
	public void testEvictCRLCache() throws Exception {
		// setup
		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();

		CachedCrlRepository testedInstance = new CachedCrlRepository(mockCrlRepository);

		// expectations
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, this.testCertificate, validationDate))
				.andReturn(this.testCrl);
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, this.testCertificate, validationDate))
				.andReturn(this.testCrl);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri, this.testCertificate, validationDate);
		testedInstance.evictCrlCache(crlUri);
		X509CRL resultCrl2 = testedInstance.findCrl(crlUri, this.testCertificate, validationDate);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(this.testCrl, resultCrl);
		assertEquals(this.testCrl, resultCrl2);
	}

	@Test
	public void testFailingCrlNotCached() throws Exception {
		// setup
		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();

		CachedCrlRepository testedInstance = new CachedCrlRepository(mockCrlRepository);

		// expectations
		// fail the first time with null
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, this.testCertificate, validationDate)).andReturn(null);
		// second call behaves "normal"
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, this.testCertificate, validationDate))
				.andReturn(this.testCrl);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri, this.testCertificate, validationDate);
		X509CRL resultCrl2 = testedInstance.findCrl(crlUri, this.testCertificate, validationDate);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertNull(resultCrl);
		assertEquals(this.testCrl, resultCrl2);
	}

	@Test
	public void cacheRefreshing() throws Exception {
		// setup
		LocalDateTime thisUpdate = LocalDateTime.now();
		LocalDateTime nextUpdate = thisUpdate.plusDays(7);
		this.testCrl = new PKIBuilder.CRLBuilder(this.testKeyPair.getPrivate(), this.testCertificate)
				.withValidityDays(7).build();
		this.testCrl2 = new PKIBuilder.CRLBuilder(this.testKeyPair.getPrivate(), this.testCertificate)
				.withValidityDays(7).build();
		X509CRL testCrl3 = new PKIBuilder.CRLBuilder(this.testKeyPair.getPrivate(), this.testCertificate)
				.withThisUpdate(LocalDateTime.now().plusDays(7)).withValidityDays(7).build();

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		LocalDateTime validationDate = LocalDateTime.now();
		LocalDateTime validationDate2 = validationDate.plusHours(2);
		LocalDateTime validationDate3 = validationDate.plusHours(4);
		LocalDateTime validationDate4 = nextUpdate.plusHours(1);

		CachedCrlRepository testedInstance = new CachedCrlRepository(mockCrlRepository);
		testedInstance.setCacheAgingHours(3);

		// verify
		assertEquals(3, testedInstance.getCacheAgingHours());

		// expectations
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, this.testCertificate,
				Date.from(validationDate.atZone(ZoneId.systemDefault()).toInstant()))).andReturn(this.testCrl);
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, this.testCertificate,
				Date.from(validationDate3.atZone(ZoneId.systemDefault()).toInstant()))).andReturn(this.testCrl2);
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, this.testCertificate,
				Date.from(validationDate4.atZone(ZoneId.systemDefault()).toInstant()))).andReturn(testCrl3);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri, this.testCertificate,
				Date.from(validationDate.atZone(ZoneId.systemDefault()).toInstant()));
		X509CRL resultCrl2 = testedInstance.findCrl(crlUri, this.testCertificate,
				Date.from(validationDate2.atZone(ZoneId.systemDefault()).toInstant()));
		X509CRL resultCrl3 = testedInstance.findCrl(crlUri, this.testCertificate,
				Date.from(validationDate3.atZone(ZoneId.systemDefault()).toInstant()));
		X509CRL resultCrl4 = testedInstance.findCrl(crlUri, this.testCertificate,
				Date.from(validationDate4.atZone(ZoneId.systemDefault()).toInstant()));

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(this.testCrl, resultCrl);
		assertEquals(this.testCrl, resultCrl2);
		assertEquals(this.testCrl2, resultCrl3);
		assertEquals(testCrl3, resultCrl4);
	}

	@Test
	public void cacheExpiredCacheValidationDateRefreshing() throws Exception {
		// setup
		this.testCrl = new PKIBuilder.CRLBuilder(this.testKeyPair.getPrivate(), this.testCertificate)
				.withValidityDays(7).build();

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		LocalDateTime validationDate = LocalDateTime.now();
		LocalDateTime expiredCacheValidationDate = validationDate.plusHours(4);

		CachedCrlRepository testedInstance = new CachedCrlRepository(mockCrlRepository);

		// expectations
		EasyMock.expect(mockCrlRepository.findCrl(crlUri, this.testCertificate,
				Date.from(expiredCacheValidationDate.atZone(ZoneId.systemDefault()).toInstant())))
				.andReturn(this.testCrl).times(2);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri, this.testCertificate,
				Date.from(expiredCacheValidationDate.atZone(ZoneId.systemDefault()).toInstant()));
		X509CRL resultCrl2 = testedInstance.findCrl(crlUri, this.testCertificate,
				Date.from(expiredCacheValidationDate.atZone(ZoneId.systemDefault()).toInstant()));

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(this.testCrl, resultCrl);
		assertEquals(this.testCrl, resultCrl2);
	}
}
