/*
 * Java Trust Project.
 * Copyright (C) 2019 e-Contract.be BVBA.
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
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.junit.Test;
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
	}

	private final class HistogramEntryComparator implements Comparator<Map.Entry<String, Integer>> {

		@Override
		public int compare(Entry<String, Integer> o1, Entry<String, Integer> o2) {
			return o1.getValue().compareTo(o2.getValue());
		}
	}

	private final class TestTSLConsumer implements TSLConsumer {

		private final Map<String, Integer> serviceTypeIdentifierHistogram;

		public TestTSLConsumer() {
			this.serviceTypeIdentifierHistogram = new HashMap<>();
		}

		public Map<String, Integer> getServiceTypeIdentifierHistogram() {
			return this.serviceTypeIdentifierHistogram;
		}

		@Override
		public void setTSLSequenceNumber(BigInteger tslSequenceNumber) {
		}

		@Override
		public void service(String serviceTypeIdentifier, X509Certificate serviceCertificate) {
			Integer count = this.serviceTypeIdentifierHistogram.get(serviceTypeIdentifier);
			if (count == null) {
				count = 1;
			} else {
				count++;
			}
			this.serviceTypeIdentifierHistogram.put(serviceTypeIdentifier, count);
		}
	}
}
