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

package be.fedict.trust.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidParameterException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;

import be.fedict.trust.AlgorithmPolicy;
import be.fedict.trust.OCSPRevocationData;
import be.fedict.trust.PublicKeyTrustLinker;
import be.fedict.trust.RevocationData;
import be.fedict.trust.TrustLinker;
import be.fedict.trust.TrustLinkerResult;
import be.fedict.trust.TrustLinkerResultReason;

/**
 * Trust linker based on OCSP revocation information.
 * 
 * @author Frank Cornelis
 * 
 */
public class OcspTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory.getLog(OcspTrustLinker.class);

	private final OcspRepository ocspRepository;

	/**
	 * Default OCSP freshness interval. Apparently 10 seconds it too low for NTP
	 * synchronized servers.
	 */
	public static final long DEFAULT_FRESHNESS_INTERVAL = 1000 * 60 * 5;

	private long freshnessInterval = DEFAULT_FRESHNESS_INTERVAL;

	/**
	 * Main constructor.
	 * 
	 * @param ocspRepository
	 *            the OCSP repository component used by this OCSP trust linker.
	 */
	public OcspTrustLinker(OcspRepository ocspRepository) {
		this.ocspRepository = ocspRepository;
	}

	/**
	 * Sets the OCSP response freshness interval in milliseconds. This interval
	 * is used to determine whether an OCSP response can be considered fresh
	 * enough to use as basis for linking trust between child certificate and
	 * parent certificate.
	 * 
	 * @param freshnessInterval
	 */
	public void setFreshnessInterval(long freshnessInterval) {
		this.freshnessInterval = freshnessInterval;
	}

	public TrustLinkerResult hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate,
			RevocationData revocationData, AlgorithmPolicy algorithmPolicy) {
		URI ocspUri = getOcspUri(childCertificate);
		if (null == ocspUri) {
			return null;
		}
		LOG.debug("OCSP URI: " + ocspUri);

		OCSPResp ocspResp = this.ocspRepository.findOcspResponse(ocspUri,
				childCertificate, certificate);
		if (null == ocspResp) {
			LOG.debug("OCSP response not found");
			return null;
		}

		int ocspRespStatus = ocspResp.getStatus();
		if (OCSPResponseStatus.SUCCESSFUL != ocspRespStatus) {
			LOG.debug("OCSP response status: " + ocspRespStatus);
			return null;
		}

		Object responseObject;
		try {
			responseObject = ocspResp.getResponseObject();
		} catch (OCSPException e) {
			LOG.debug("OCSP exception: " + e.getMessage(), e);
			return null;
		}
		BasicOCSPResp basicOCSPResp = (BasicOCSPResp) responseObject;

		try {
			X509Certificate[] responseCertificates = basicOCSPResp
					.getCerts(BouncyCastleProvider.PROVIDER_NAME);
			for (X509Certificate responseCertificate : responseCertificates) {
				LOG.debug("OCSP response cert: "
						+ responseCertificate.getSubjectX500Principal());
				LOG.debug("OCSP response cert issuer: "
						+ responseCertificate.getIssuerX500Principal());
			}

			try {
				algorithmPolicy.checkSignatureAlgorithm(basicOCSPResp
						.getSignatureAlgOID());
			} catch (SignatureException e) {
				return new TrustLinkerResult(false,
						TrustLinkerResultReason.INVALID_SIGNATURE,
						"algorithm error: " + e.getMessage());
			}

			if (0 == responseCertificates.length) {
				/*
				 * This means that the OCSP response has been signed by the
				 * issuing CA itself.
				 */
				boolean verificationResult = basicOCSPResp.verify(
						certificate.getPublicKey(),
						BouncyCastleProvider.PROVIDER_NAME);
				if (false == verificationResult) {
					LOG.debug("OCSP response signature invalid");
					return null;
				}

			} else {
				/*
				 * We're dealing with a dedicated authorized OCSP Responder
				 * certificate, or of course with a CA that issues the OCSP
				 * Responses itself.
				 */

				X509Certificate ocspResponderCertificate = responseCertificates[0];
				boolean verificationResult = basicOCSPResp.verify(
						ocspResponderCertificate.getPublicKey(),
						BouncyCastleProvider.PROVIDER_NAME);
				if (false == verificationResult) {
					LOG.debug("OCSP Responser response signature invalid");
					return null;
				}
				if (false == Arrays.equals(certificate.getEncoded(),
						ocspResponderCertificate.getEncoded())) {
					// check certificate signature algorithm
					try {
						algorithmPolicy
								.checkSignatureAlgorithm(ocspResponderCertificate
										.getSigAlgOID());
					} catch (SignatureException e) {
						return new TrustLinkerResult(false,
								TrustLinkerResultReason.INVALID_SIGNATURE,
								"algorithm error: " + e.getMessage());
					}

					X509Certificate issuingCaCertificate;
					if (responseCertificates.length < 2) {
						LOG.debug("OCSP responder complete certificate chain missing");
						/*
						 * Here we assume that the OCSP Responder is directly
						 * signed by the CA.
						 */
						issuingCaCertificate = certificate;
					} else {
						issuingCaCertificate = responseCertificates[1];
						/*
						 * Is next check really required?
						 */
						if (false == certificate.equals(issuingCaCertificate)) {
							LOG.debug("OCSP responder certificate not issued by CA");
							return null;
						}
					}
					// check certificate signature
					try {
						algorithmPolicy
								.checkSignatureAlgorithm(issuingCaCertificate
										.getSigAlgOID());
					} catch (SignatureException e) {
						return new TrustLinkerResult(false,
								TrustLinkerResultReason.INVALID_SIGNATURE,
								"algorithm error: " + e.getMessage());
					}

					PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();
					TrustLinkerResult trustResult = publicKeyTrustLinker
							.hasTrustLink(ocspResponderCertificate,
									issuingCaCertificate, validationDate,
									revocationData, algorithmPolicy);
					if (null != trustResult) {
						if (!trustResult.isValid()) {
							LOG.debug("OCSP responder not trusted");
							return null;
						}
					}
					if (null == ocspResponderCertificate
							.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck
									.getId())) {
						LOG.debug("OCSP Responder certificate should have id-pkix-ocsp-nocheck");
						/*
						 * TODO: perform CRL validation on the OCSP Responder
						 * certificate. On the other hand, do we really want to
						 * check the checker?
						 */
						return null;
					}
					List<String> extendedKeyUsage;
					try {
						extendedKeyUsage = ocspResponderCertificate
								.getExtendedKeyUsage();
					} catch (CertificateParsingException e) {
						LOG.debug(
								"OCSP Responder parsing error: "
										+ e.getMessage(), e);
						return null;
					}
					if (null == extendedKeyUsage) {
						LOG.debug("OCSP Responder certificate has no extended key usage extension");
						return null;
					}
					if (false == extendedKeyUsage
							.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
						LOG.debug("OCSP Responder certificate should have a OCSPSigning extended key usage");
						return null;
					}
				} else {
					LOG.debug("OCSP Responder certificate equals the CA certificate");
				}
			}
		} catch (NoSuchProviderException e) {
			LOG.debug("JCA provider exception: " + e.getMessage(), e);
			return null;
		} catch (OCSPException e) {
			LOG.debug("OCSP exception: " + e.getMessage(), e);
			return null;
		} catch (CertificateEncodingException e) {
			LOG.debug("certificate encoding error: " + e.getMessage(), e);
			return null;
		}

		CertificateID certificateId;
		try {
			certificateId = new CertificateID(CertificateID.HASH_SHA1,
					certificate, childCertificate.getSerialNumber());
		} catch (OCSPException e) {
			LOG.debug("OCSP exception: " + e.getMessage(), e);
			return null;
		}

		SingleResp[] singleResps = basicOCSPResp.getResponses();
		for (SingleResp singleResp : singleResps) {
			CertificateID responseCertificateId = singleResp.getCertID();
			if (false == certificateId.equals(responseCertificateId)) {
				continue;
			}
			Date thisUpdate = singleResp.getThisUpdate();
			LOG.debug("OCSP thisUpdate: " + thisUpdate);
			LOG.debug("OCSP nextUpdate: " + singleResp.getNextUpdate());
			long dt = Math.abs(thisUpdate.getTime() - validationDate.getTime());
			if (dt > this.freshnessInterval) {
				LOG.warn("freshness interval exceeded: " + dt + " milliseconds");
				continue;
			}
			if (null == singleResp.getCertStatus()) {
				LOG.debug("OCSP OK for: "
						+ childCertificate.getSubjectX500Principal());
				addRevocationData(revocationData, ocspResp, ocspUri);
				return new TrustLinkerResult(true);
			} else {
				LOG.debug("OCSP certificate status: "
						+ singleResp.getCertStatus().getClass().getName());
				if (singleResp.getCertStatus() instanceof RevokedStatus) {
					LOG.debug("OCSP status revoked");
				}
				addRevocationData(revocationData, ocspResp, ocspUri);
				return new TrustLinkerResult(false,
						TrustLinkerResultReason.INVALID_REVOCATION_STATUS,
						"certificate revoked by OCSP");
			}
		}

		LOG.debug("no matching OCSP response entry");
		return null;
	}

	private void addRevocationData(RevocationData revocationData,
			OCSPResp ocspResp, URI uri) {
		if (null != revocationData) {
			try {
				OCSPRevocationData ocspRevocationData = new OCSPRevocationData(
						ocspResp.getEncoded(), uri.toString());
				revocationData.getOcspRevocationData().add(ocspRevocationData);
			} catch (IOException e) {
				LOG.error("IOException: " + e.getMessage(), e);
				throw new RuntimeException("IOException : " + e.getMessage(), e);
			}
		}
	}

	private URI getOcspUri(X509Certificate certificate) {
		URI ocspURI = getAccessLocation(certificate,
				X509ObjectIdentifiers.ocspAccessMethod);
		return ocspURI;
	}

	private URI getAccessLocation(X509Certificate certificate,
			DERObjectIdentifier accessMethod) {
		byte[] authInfoAccessExtensionValue = certificate
				.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
		if (null == authInfoAccessExtensionValue) {
			return null;
		}
		AuthorityInformationAccess authorityInformationAccess;
		try {
			DEROctetString oct = (DEROctetString) (new ASN1InputStream(
					new ByteArrayInputStream(authInfoAccessExtensionValue))
					.readObject());
			authorityInformationAccess = new AuthorityInformationAccess(
					(ASN1Sequence) new ASN1InputStream(oct.getOctets())
							.readObject());
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
		AccessDescription[] accessDescriptions = authorityInformationAccess
				.getAccessDescriptions();
		for (AccessDescription accessDescription : accessDescriptions) {
			LOG.debug("access method: " + accessDescription.getAccessMethod());
			boolean correctAccessMethod = accessDescription.getAccessMethod()
					.equals(accessMethod);
			if (!correctAccessMethod) {
				continue;
			}
			GeneralName gn = accessDescription.getAccessLocation();
			if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
				LOG.debug("not a uniform resource identifier");
				continue;
			}
			DERIA5String str = DERIA5String.getInstance(gn.getName());
			String accessLocation = str.getString();
			LOG.debug("access location: " + accessLocation);
			URI uri = toURI(accessLocation);
			LOG.debug("access location URI: " + uri);
			return uri;
		}
		return null;
	}

	private URI toURI(String str) {
		try {
			URI uri = new URI(str);
			return uri;
		} catch (URISyntaxException e) {
			throw new InvalidParameterException("URI syntax error: "
					+ e.getMessage());
		}
	}
}
