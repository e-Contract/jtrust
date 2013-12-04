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

package be.fedict.trust.crl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidParameterException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.X509Extension;

import be.fedict.trust.linker.TrustLinker;
import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.policy.AlgorithmPolicy;
import be.fedict.trust.revocation.CRLRevocationData;
import be.fedict.trust.revocation.RevocationData;

/**
 * Trust linker implementation based on CRL revocation information.
 * 
 * @author Frank Cornelis
 * 
 */
public class CrlTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory.getLog(CrlTrustLinker.class);

	private final CrlRepository crlRepository;

	/**
	 * Main constructor.
	 * 
	 * @param crlRepository
	 *            the CRL repository used by this CRL trust linker.
	 */
	public CrlTrustLinker(CrlRepository crlRepository) {
		this.crlRepository = crlRepository;
	}

	public TrustLinkerResult hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate,
			RevocationData revocationData, AlgorithmPolicy algorithmPolicy)
			throws TrustLinkerResultException, Exception {

		URI crlUri = getCrlUri(childCertificate);
		if (null == crlUri) {
			LOG.debug("no CRL uri in certificate: "
					+ childCertificate.getSubjectX500Principal());
			return TrustLinkerResult.UNDECIDED;
		}

		LOG.debug("CRL URI: " + crlUri);
		X509CRL x509crl = this.crlRepository.findCrl(crlUri, certificate,
				validationDate);
		if (null == x509crl) {
			return TrustLinkerResult.UNDECIDED;
		}

		// check CRL integrity
		boolean crlIntegrityResult = checkCrlIntegrity(x509crl, certificate,
				validationDate);
		if (false == crlIntegrityResult) {
			return TrustLinkerResult.UNDECIDED;
		}

		// check CRL signature algorithm
		algorithmPolicy.checkSignatureAlgorithm(x509crl.getSigAlgOID(),
				validationDate);

		// we don't support indirect CRLs
		if (isIndirectCRL(x509crl)) {
			LOG.debug("indirect CRL detected");
			return TrustLinkerResult.UNDECIDED;
		}

		LOG.debug("CRL number: " + getCrlNumber(x509crl));

		// fill up revocation data if not null with this valid CRL
		if (null != revocationData) {
			try {
				CRLRevocationData crlRevocationData = new CRLRevocationData(
						x509crl.getEncoded(), crlUri.toString());
				revocationData.getCrlRevocationData().add(crlRevocationData);
			} catch (CRLException e) {
				LOG.error("CRLException: " + e.getMessage(), e);
				throw new TrustLinkerResultException(
						TrustLinkerResultReason.UNSPECIFIED, "CRLException : "
								+ e.getMessage(), e);
			}
		}

		X509CRLEntry crlEntry = x509crl.getRevokedCertificate(childCertificate
				.getSerialNumber());
		if (null == crlEntry) {
			LOG.debug("CRL OK for: "
					+ childCertificate.getSubjectX500Principal());
			return TrustLinkerResult.TRUSTED;
		} else if (crlEntry.getRevocationDate().after(validationDate)) {
			LOG.debug("CRL OK for: "
					+ childCertificate.getSubjectX500Principal() + " at "
					+ validationDate);
			return TrustLinkerResult.TRUSTED;
		}

		LOG.debug("certificate revoked/suspended at: "
				+ crlEntry.getRevocationDate());
		if (crlEntry.hasExtensions()) {
			LOG.debug("critical extensions: "
					+ crlEntry.getCriticalExtensionOIDs());
			LOG.debug("non-critical extensions: "
					+ crlEntry.getNonCriticalExtensionOIDs());
			byte[] reasonCodeExtension = crlEntry
					.getExtensionValue(X509Extension.reasonCode.getId());
			if (null != reasonCodeExtension) {
				try {
					DEROctetString octetString = (DEROctetString) (new ASN1InputStream(
							new ByteArrayInputStream(reasonCodeExtension))
							.readObject());
					byte[] octets = octetString.getOctets();
					CRLReason crlReason = CRLReason.getInstance(DEREnumerated
							.getInstance(new ASN1InputStream(octets)
									.readObject()));
					BigInteger crlReasonValue = crlReason.getValue();
					LOG.debug("CRL reason value: " + crlReasonValue);
					switch (crlReasonValue.intValue()) {
					case CRLReason.certificateHold:
						throw new TrustLinkerResultException(
								TrustLinkerResultReason.INVALID_REVOCATION_STATUS,
								"certificate suspended by CRL="
										+ crlEntry.getSerialNumber());
					}
				} catch (IOException e) {
					throw new TrustLinkerResultException(
							TrustLinkerResultReason.UNSPECIFIED, "IO error: "
									+ e.getMessage(), e);
				}
			}
		}

		throw new TrustLinkerResultException(
				TrustLinkerResultReason.INVALID_REVOCATION_STATUS,
				"certificate revoked by CRL=" + crlEntry.getSerialNumber());

	}

	/**
	 * Checks the integrity of the given X509 CRL.
	 * 
	 * @param x509crl
	 *            the X509 CRL to verify the integrity.
	 * @param issuerCertificate
	 *            the assumed issuer of the given X509 CRL.
	 * @param validationDate
	 *            the validate date.
	 * @return <code>true</code> if integrity is OK, <code>false</code>
	 *         otherwise.
	 */
	public static boolean checkCrlIntegrity(X509CRL x509crl,
			X509Certificate issuerCertificate, Date validationDate) {
		if (false == x509crl.getIssuerX500Principal().equals(
				issuerCertificate.getSubjectX500Principal())) {
			return false;
		}
		try {
			x509crl.verify(issuerCertificate.getPublicKey());
		} catch (Exception e) {
			return false;
		}
		Date thisUpdate = x509crl.getThisUpdate();
		LOG.debug("validation date: " + validationDate);
		LOG.debug("CRL this update: " + thisUpdate);
		if (thisUpdate.after(validationDate)) {
			LOG.warn("CRL too young");
			return false;
		}
		LOG.debug("CRL next update: " + x509crl.getNextUpdate());
		if (null != x509crl.getNextUpdate()) {
			if (validationDate.after(x509crl.getNextUpdate())) {
				LOG.debug("CRL too old");
				return false;
			}
		} else {
			LOG.warn("CRL has no nextUpdate");
		}

		// assert cRLSign KeyUsage bit
		if (null == issuerCertificate.getKeyUsage()) {
			LOG.warn("No KeyUsage extension for CRL issuing certificate");
			/*
			 * Not really required according to RFC2459.
			 */
			return true;
		}

		if (false == issuerCertificate.getKeyUsage()[6]) {
			LOG.debug("cRLSign bit not set for CRL issuing certificate");
			return false;
		}

		return true;
	}

	/**
	 * Gives back the CRL URI meta-data found within the given X509 certificate.
	 * 
	 * @param certificate
	 *            the X509 certificate.
	 * @return the CRL URI, or <code>null</code> if the extension is not
	 *         present.
	 */
	public static URI getCrlUri(X509Certificate certificate) {
		byte[] crlDistributionPointsValue = certificate
				.getExtensionValue(X509Extension.cRLDistributionPoints.getId());
		if (null == crlDistributionPointsValue) {
			return null;
		}
		ASN1Sequence seq;
		try {
			DEROctetString oct;
			oct = (DEROctetString) (new ASN1InputStream(
					new ByteArrayInputStream(crlDistributionPointsValue))
					.readObject());
			seq = (ASN1Sequence) new ASN1InputStream(oct.getOctets())
					.readObject();
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
		CRLDistPoint distPoint = CRLDistPoint.getInstance(seq);
		DistributionPoint[] distributionPoints = distPoint
				.getDistributionPoints();
		for (DistributionPoint distributionPoint : distributionPoints) {
			DistributionPointName distributionPointName = distributionPoint
					.getDistributionPoint();
			if (DistributionPointName.FULL_NAME != distributionPointName
					.getType()) {
				continue;
			}
			GeneralNames generalNames = (GeneralNames) distributionPointName
					.getName();
			GeneralName[] names = generalNames.getNames();
			for (GeneralName name : names) {
				if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
					LOG.debug("not a uniform resource identifier");
					continue;
				}
				DERIA5String derStr = DERIA5String.getInstance(name.getName());
				String str = derStr.getString();
				if (false == str.startsWith("http")) {
					/*
					 * skip ldap:// protocols
					 */
					LOG.debug("not HTTP/HTTPS: " + str);
					continue;
				}
				URI uri = toURI(str);
				return uri;
			}
		}
		return null;
	}

	private BigInteger getCrlNumber(X509CRL crl) {
		byte[] crlNumberExtensionValue = crl
				.getExtensionValue(X509Extension.cRLNumber.getId());
		if (null == crlNumberExtensionValue) {
			return null;
		}
		try {
			DEROctetString octetString = (DEROctetString) (new ASN1InputStream(
					new ByteArrayInputStream(crlNumberExtensionValue))
					.readObject());
			byte[] octets = octetString.getOctets();
			DERInteger integer = (DERInteger) new ASN1InputStream(octets)
					.readObject();
			BigInteger crlNumber = integer.getPositiveValue();
			return crlNumber;
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
	}

	private boolean isIndirectCRL(X509CRL crl) {
		byte[] idp = crl
				.getExtensionValue(X509Extension.issuingDistributionPoint
						.getId());
		boolean isIndirect = false;
		if (idp != null) {
			isIndirect = IssuingDistributionPoint.getInstance(idp)
					.isIndirectCRL();
		}

		return isIndirect;
	}

	private static URI toURI(String str) {
		try {
			URI uri = new URI(str);
			return uri;
		} catch (URISyntaxException e) {
			throw new InvalidParameterException("CRL URI syntax error: "
					+ e.getMessage());
		}
	}
}
