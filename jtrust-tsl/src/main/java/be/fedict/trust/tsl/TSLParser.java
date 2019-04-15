/*
 * Java Trust Project.
 * Copyright (C) 2009-2011 FedICT.
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

package be.fedict.trust.tsl;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.LinkedList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.eid.tsl.jaxb.tsl.ObjectFactory;
import be.fedict.eid.tsl.jaxb.tsl.TSLSchemeInformationType;
import be.fedict.eid.tsl.jaxb.tsl.TrustStatusListType;

/**
 * @author Frank Cornelis
 * 
 */
public class TSLParser {

	private static final Logger LOGGER = LoggerFactory.getLogger(TSLParser.class);

	private final InputStream tslInputStream;

	private final PublicKey tslSignerPublicKey;

	private final List<TSLConsumer> tslConsumers;

	/**
	 * Main constructor.
	 * 
	 * @param tslInputStream
	 * @param tslSignerPublicKey
	 */
	public TSLParser(InputStream tslInputStream, PublicKey tslSignerPublicKey) {
		this.tslInputStream = tslInputStream;
		this.tslSignerPublicKey = tslSignerPublicKey;
		this.tslConsumers = new LinkedList<TSLConsumer>();
	}

	public void addTSLConsumer(TSLConsumer tslConsumer) {
		this.tslConsumers.add(tslConsumer);
	}

	public void parseTrustedList() {
		TrustStatusListType trustStatusList;
		try {
			trustStatusList = parseTslInputStream();
		} catch (JAXBException e) {
			throw new RuntimeException("TSL parsing error: " + e.getMessage(), e);
		}
		LOGGER.debug("TSL parsed");
		TSLSchemeInformationType tslSchemeInformation = trustStatusList.getSchemeInformation();
		BigInteger tslSequenceNumber = tslSchemeInformation.getTSLSequenceNumber();
		LOGGER.debug("TSL sequence number: {}", tslSequenceNumber);
		for (TSLConsumer tslConsumer : this.tslConsumers) {
			tslConsumer.setTSLSequenceNumber(tslSequenceNumber);
		}
	}

	private TrustStatusListType parseTslInputStream() throws JAXBException {
		Unmarshaller unmarshaller = getUnmarshaller();
		JAXBElement<TrustStatusListType> jaxbElement = (JAXBElement<TrustStatusListType>) unmarshaller
				.unmarshal(this.tslInputStream);
		TrustStatusListType trustServiceStatusList = jaxbElement.getValue();
		return trustServiceStatusList;
	}

	private Unmarshaller getUnmarshaller() throws JAXBException {
		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		return unmarshaller;
	}
}
