/*
 * Java Trust Project.
 * Copyright (C) 2011 FedICT.
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

package be.fedict.trust;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

/**
 * Certificate path builder. Helper class to complete partial certificate chains
 * (e.g. for SSL with a missing root). The given chain can also be completely
 * out of order.
 * <p/>
 * Keep in mind that this helper class does not perform any PKI validation at
 * all. It just constructs a certificate path (best-effort).
 * 
 * @author Frank Cornelis
 * 
 */
public class CertificatePathBuilder {

	private static final Log LOG = LogFactory
			.getLog(CertificatePathBuilder.class);

	private final Map<String, X509Certificate> rootsBySkid;

	private final Map<String, X509Certificate> rootsByDNSerialNr;

	private static final class IssuerNameSerialNumber {
		private final X500Principal name;
		private final BigInteger serialNumber;

		public IssuerNameSerialNumber(X500Principal name,
				BigInteger serialNumber) {
			this.name = name;
			this.serialNumber = serialNumber;
		}

		@Override
		public boolean equals(Object obj) {
			if (null == obj) {
				return false;
			}
			if (this == obj) {
				return true;
			}
			if (false == obj instanceof IssuerNameSerialNumber) {
				return false;
			}
			IssuerNameSerialNumber other = (IssuerNameSerialNumber) obj;
			if (false == this.name.equals(other.name)) {
				return false;
			}
			if (false == this.serialNumber.equals(other.serialNumber)) {
				return false;
			}
			return false;
		}

		@Override
		public int hashCode() {
			return this.name.hashCode() + this.serialNumber.hashCode();
		}
	}

	private static final String[] ROOT_RESOURCES = { "/be/fedict/trust/roots/globalsign-be.crt" };

	/**
	 * Main constructor.
	 */
	public CertificatePathBuilder() {
		CertificateFactory certificateFactory;
		this.rootsBySkid = new HashMap<String, X509Certificate>();
		this.rootsByDNSerialNr = new HashMap<String, X509Certificate>();
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException("certificate factory error: "
					+ e.getMessage());
		}
		for (String rootResource : ROOT_RESOURCES) {
			InputStream certificateInputStream = CertificatePathBuilder.class
					.getResourceAsStream(rootResource);
			X509Certificate certificate;
			try {
				certificate = (X509Certificate) certificateFactory
						.generateCertificate(certificateInputStream);
			} catch (CertificateException e) {
				throw new RuntimeException("error loading certificate: "
						+ e.getMessage());
			}
			String skidId = getSubjectKeyIdentifier(certificate);
			if (this.rootsBySkid.containsKey(skidId)) {
				throw new RuntimeException("SKI already present: " + skidId);
			}
			LOG.debug("reg SKI: " + skidId);
			LOG.debug("certificate: " + certificate.getSubjectX500Principal());
			this.rootsBySkid.put(skidId, certificate);

			String dnAndSerialNumber = certificate.getSubjectX500Principal()
					.toString() + certificate.getSerialNumber();
			LOG.debug("reg DNSN: " + dnAndSerialNumber);
			if (this.rootsByDNSerialNr.containsKey(dnAndSerialNumber)) {
				throw new RuntimeException("DN-SN already present: "
						+ dnAndSerialNumber);
			}
			this.rootsByDNSerialNr.put(dnAndSerialNumber, certificate);
		}
	}

	private String getDNandSerialNumber(X509Certificate certificate) {
		String dnAndSerialNumber = certificate.getIssuerX500Principal()
				.toString() + certificate.getSerialNumber();
		return dnAndSerialNumber;
	}

	private String getSubjectKeyIdentifier(X509Certificate certificate) {
		JcaX509ExtensionUtils utils;
		try {
			utils = new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		SubjectKeyIdentifier subjectKeyIdentifier = utils
				.createSubjectKeyIdentifier(certificate.getPublicKey());
		String skidId = new String(Hex.encodeHex(subjectKeyIdentifier
				.getKeyIdentifier()));
		return skidId;
	}

	private String getAuthorityKeyIdentifier(X509Certificate certificate) {
		byte[] authorityKeyIdentifierData = certificate
				.getExtensionValue(X509Extension.authorityKeyIdentifier.getId());
		if (null == authorityKeyIdentifierData) {
			return null;
		}
		AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier(
				authorityKeyIdentifierData);
		String akidId = new String(Hex.encodeHex(authorityKeyIdentifier
				.getKeyIdentifier()));
		return akidId;
	}

	/**
	 * Builds a path using the given partial certificate chain.
	 * 
	 * @param partialCertificateChain
	 * @return a complete certificate chain up to a known (!= trusted) root.
	 */
	public List<X509Certificate> buildPath(
			List<X509Certificate> partialCertificateChain) {
		Map<String, X509Certificate> certMapBySkid = new HashMap<String, X509Certificate>();
		Map<String, X509Certificate> certMapByDNandSN = new HashMap<String, X509Certificate>();
		for (X509Certificate certificate : partialCertificateChain) {
			String skidId = getSubjectKeyIdentifier(certificate);
			if (certMapBySkid.containsKey(skidId)) {
				throw new RuntimeException("duplicate entries for SKI: "
						+ skidId);
			}
			certMapBySkid.put(skidId, certificate);

			AuthorityKeyIdentifierStructure akis;
			try {
				akis = new AuthorityKeyIdentifierStructure(certificate);
			} catch (CertificateParsingException e) {
				throw new RuntimeException("AKI parsing error: "
						+ e.getMessage());
			}
			String dnAndSerialNumber = akis.getAuthorityCertIssuer().getNames()[0]
					.getName().toString() + akis.getAuthorityCertSerialNumber();
			LOG.debug("entry DNSN: " + dnAndSerialNumber);
			if (certMapByDNandSN.containsKey(dnAndSerialNumber)) {
				throw new RuntimeException("duplicate entries for DN/SN: "
						+ dnAndSerialNumber);
			}
			certMapByDNandSN.put(dnAndSerialNumber, certificate);
		}
		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
		/*
		 * We assume the first certificate is the end-entity certificate.
		 */
		X509Certificate certificate = partialCertificateChain.get(0);
		while (certificate != null) {
			certificateChain.add(certificate);
			X509Name subjectName;
			try {
				subjectName = new X509Name(
						(ASN1Sequence) new ASN1InputStream(certificate
								.getSubjectX500Principal().getEncoded())
								.readObject());
			} catch (IOException e) {
				throw new RuntimeException("subject name parser: "
						+ e.getMessage());
			}
			X509Name issuerName;
			try {
				issuerName = new X509Name(
						(ASN1Sequence) new ASN1InputStream(certificate
								.getIssuerX500Principal().getEncoded())
								.readObject());
			} catch (IOException e) {
				throw new RuntimeException("issuer name parser: "
						+ e.getMessage());
			}
			LOG.debug("subject: " + subjectName);
			LOG.debug("issuer: " + issuerName);
			if (subjectName.equals(issuerName)) {
				break;
			}
			String akiId = getAuthorityKeyIdentifier(certificate);
			if (akiId != null) {
				certificate = certMapBySkid.get(akiId);
			} else {
				String dnSn = getAuthorityDNSN(certificate);
				LOG.debug("DNSN: " + dnSn);
				certificate = certMapByDNandSN.get(dnSn);
			}
		}
		X509Certificate topCert = certificateChain
				.get(certificateChain.size() - 1);
		try {
			topCert.verify(topCert.getPublicKey());
			return certificateChain;
		} catch (Exception e) {
			// not a self-signed. So find a root.
		}
		LOG.debug("last cert: " + topCert.getSubjectX500Principal());
		String akidId = getAuthorityKeyIdentifier(topCert);
		LOG.debug("AKI id: " + akidId);
		if (null != akidId) {
			X509Certificate rootCert = this.rootsBySkid.get(akidId);
			if (null == rootCert) {
				throw new RuntimeException("no matching root found for AKI: "
						+ akidId);
			}
			certificateChain.add(rootCert);
			LOG.debug("path: " + rootCert.getSubjectX500Principal());
		} else {
			String dnSn = getAuthorityDNSN(topCert);
			LOG.debug("find DNSN: " + dnSn);
			X509Certificate rootCert = this.rootsByDNSerialNr.get(dnSn);
			if (null == rootCert) {
				throw new RuntimeException("no matching root found for DNSN: "
						+ dnSn);
			}
			certificateChain.add(rootCert);
		}
		return certificateChain;
	}

	private String getAuthorityDNSN(X509Certificate certificate) {
		byte[] authorityKeyIdentifierData = certificate
				.getExtensionValue(X509Extensions.AuthorityKeyIdentifier
						.getId());
		if (null == authorityKeyIdentifierData) {
			return null;
		}
		AuthorityKeyIdentifierStructure authorityKeyIdentifierStructure;
		try {
			authorityKeyIdentifierStructure = new AuthorityKeyIdentifierStructure(
					authorityKeyIdentifierData);
		} catch (IOException e) {
			throw new RuntimeException("error parsing AKI: " + e.getMessage());
		}
		if (null == authorityKeyIdentifierStructure.getAuthorityCertIssuer()) {
			return null;
		}
		String dn = authorityKeyIdentifierStructure.getAuthorityCertIssuer()
				.getNames()[0].getName().toString();
		LOG.debug("issuer DN: " + dn);
		String dnSn = dn + certificate.getSerialNumber();
		return dnSn;
	}
}
