/*
 * Java Trust Project.
 * Copyright (C) 2019-2020 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.tsl.TSLConsumer;
import be.fedict.trust.tsl.TSLParser;

public class TrustedListTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(TrustedListTest.class);

	@Test
	public void testEUTL() throws Exception {
		String tslLocation = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";
		TSLParser tslParser = new TSLParser(tslLocation);
		TestTSLConsumer testTSLConsumer = new TestTSLConsumer();
		tslParser.addTSLConsumer(testTSLConsumer);
		tslParser.parseTrustedList();

		Map<String, Integer> serviceTypeIdentifierHistogram = testTSLConsumer.getServiceTypeIdentifierHistogram();
		List<Map.Entry<String, Integer>> entryList = new LinkedList<>(serviceTypeIdentifierHistogram.entrySet());
		entryList.sort(new HistogramEntryComparator());
		for (Map.Entry<String, Integer> entry : entryList) {
			LOGGER.debug("service: {} - count {}", entry.getKey(), entry.getValue());
		}

		Map<String, Integer> signatureAlgNameHistogram = testTSLConsumer.getSignatureAlgNameHistorgram();
		entryList = new LinkedList<>(signatureAlgNameHistogram.entrySet());
		entryList.sort(new HistogramEntryComparator());
		for (Map.Entry<String, Integer> entry : entryList) {
			LOGGER.debug("signature alg name: {} - count {}", entry.getKey(), entry.getValue());
		}

		Map<String, Integer> cnHistogram = testTSLConsumer.getCNHistogram();
		entryList = new LinkedList<>(cnHistogram.entrySet());
		entryList.sort(new HistogramEntryComparator());
		for (Map.Entry<String, Integer> entry : entryList) {
			LOGGER.debug("CN field: {} - count {}", entry.getKey(), entry.getValue());
		}

		Map<String, Integer> extensionHistogram = testTSLConsumer.getExtensionHistogram();
		entryList = new LinkedList<>(extensionHistogram.entrySet());
		entryList.sort(new HistogramEntryComparator());
		for (Map.Entry<String, Integer> entry : entryList) {
			LOGGER.debug("extension OID: {} - count {}", entry.getKey(), entry.getValue());
		}

		Map<String, Integer> policyHistogram = testTSLConsumer.getPolicyHistogram();
		entryList = new LinkedList<>(policyHistogram.entrySet());
		entryList.sort(new HistogramEntryComparator());
		for (Map.Entry<String, Integer> entry : entryList) {
			LOGGER.debug("policy OID: {} - count {}", entry.getKey(), entry.getValue());
		}

		for (TestTSLConsumer.TSLError tslError : testTSLConsumer.errors) {
			LOGGER.warn("TSL error on " + tslError.tslLocation + ": " + tslError.error.getMessage());
		}

		LOGGER.debug("CAs with policy: {}", testTSLConsumer.getHasPolicy());
		LOGGER.debug("CAs without policy: {}", testTSLConsumer.getHasNoPolicy());
	}

	private final class HistogramEntryComparator implements Comparator<Map.Entry<String, Integer>> {

		@Override
		public int compare(Entry<String, Integer> o1, Entry<String, Integer> o2) {
			return o1.getValue().compareTo(o2.getValue());
		}
	}

	private final class TestTSLConsumer implements TSLConsumer {

		private final Map<String, Integer> serviceTypeIdentifierHistogram;

		private final Map<String, Integer> signatureAlgNameHistogram;

		private final Map<String, Integer> cnHistogram;

		private final Map<String, Integer> extensionHistogram;

		private final Map<String, Integer> policyHistogram;

		private int hasPolicy;

		private int hasNoPolicy;

		private final List<TSLError> errors;

		private final class TSLError {
			String tslLocation;
			Exception error;
		}

		public TestTSLConsumer() {
			this.serviceTypeIdentifierHistogram = new HashMap<>();
			this.signatureAlgNameHistogram = new HashMap<>();
			this.cnHistogram = new HashMap<>();
			this.extensionHistogram = new HashMap<>();
			this.policyHistogram = new HashMap<>();
			this.errors = new LinkedList<>();
			this.hasPolicy = 0;
			this.hasNoPolicy = 0;
		}

		public Map<String, Integer> getServiceTypeIdentifierHistogram() {
			return this.serviceTypeIdentifierHistogram;
		}

		public Map<String, Integer> getSignatureAlgNameHistorgram() {
			return this.signatureAlgNameHistogram;
		}

		public Map<String, Integer> getCNHistogram() {
			return this.cnHistogram;
		}

		public Map<String, Integer> getExtensionHistogram() {
			return this.extensionHistogram;
		}

		public Map<String, Integer> getPolicyHistogram() {
			return this.policyHistogram;
		}

		public int getHasPolicy() {
			return this.hasPolicy;
		}

		public int getHasNoPolicy() {
			return this.hasNoPolicy;
		}

		@Override
		public void setTSLSequenceNumber(BigInteger tslSequenceNumber) {
		}

		@Override
		public void service(String serviceTypeIdentifier, X509Certificate serviceCertificate) throws Exception {
			Integer count = this.serviceTypeIdentifierHistogram.get(serviceTypeIdentifier);
			if (count == null) {
				count = 1;
			} else {
				count++;
			}
			this.serviceTypeIdentifierHistogram.put(serviceTypeIdentifier, count);
			if (!"http://uri.etsi.org/TrstSvc/Svctype/CA/QC".equals(serviceTypeIdentifier)) {
				return;
			}
			if (null == serviceCertificate) {
				fail("no service certificate");
				return;
			}

			String sigAlgName = serviceCertificate.getSigAlgName();
			count = this.signatureAlgNameHistogram.get(sigAlgName);
			if (null == count) {
				count = 1;
			} else {
				count++;
			}
			this.signatureAlgNameHistogram.put(sigAlgName, count);

			X509CertificateHolder certificateHolder = new JcaX509CertificateHolder(serviceCertificate);
			X500Name x500name = certificateHolder.getSubject();
			for (RDN rdn : x500name.getRDNs()) {
				for (AttributeTypeAndValue attributeTypeAndValue : rdn.getTypesAndValues()) {
					ASN1ObjectIdentifier type = attributeTypeAndValue.getType();
					String typeId = type.getId();
					count = this.cnHistogram.get(typeId);
					if (null == count) {
						count = 1;
					} else {
						count++;
					}
					this.cnHistogram.put(typeId, count);
				}
			}

			List<ASN1ObjectIdentifier> extensionOids = certificateHolder.getExtensionOIDs();
			boolean policyPresent = false;
			for (ASN1ObjectIdentifier extensionOid : extensionOids) {
				String oid = extensionOid.getId();
				count = this.extensionHistogram.get(oid);
				if (null == count) {
					count = 1;
				} else {
					count++;
				}
				this.extensionHistogram.put(oid, count);
				if (oid.equals("2.5.29.32")) {
					policyPresent = true;
					Extension certificatePoliciesExtension = certificateHolder.getExtension(extensionOid);
					CertificatePolicies certificatePolicies = CertificatePolicies
							.getInstance(certificatePoliciesExtension.getParsedValue());
					for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
						String certPolicyId = policyInformation.getPolicyIdentifier().getId();
						count = this.policyHistogram.get(certPolicyId);
						if (null == count) {
							count = 1;
						} else {
							count++;
						}
						this.policyHistogram.put(certPolicyId, count);
					}
				}
			}
			if (policyPresent) {
				this.hasPolicy++;
			} else {
				this.hasNoPolicy++;
			}
		}

		@Override
		public void error(String tslLocation, Exception e) {
			TSLError tslError = new TSLError();
			tslError.error = e;
			tslError.tslLocation = tslLocation;
			this.errors.add(tslError);
		}
	}
}
