/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import be.fedict.trust.common.ServerNotAvailableException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.joda.time.DateTime;

import be.fedict.trust.linker.PublicKeyTrustLinker;
import be.fedict.trust.linker.TrustLinker;
import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.policy.AlgorithmPolicy;
import be.fedict.trust.revocation.OCSPRevocationData;
import be.fedict.trust.revocation.RevocationData;

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
	public OcspTrustLinker(final OcspRepository ocspRepository) {
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
	public void setFreshnessInterval(final long freshnessInterval) {
		this.freshnessInterval = freshnessInterval;
	}

	@Override
	public TrustLinkerResult hasTrustLink(final X509Certificate childCertificate,
			final X509Certificate certificate, final Date validationDate,
			final RevocationData revocationData, final AlgorithmPolicy algorithmPolicy)
			throws TrustLinkerResultException, Exception {
		final URI ocspUri = getOcspUri(childCertificate);
		if (null == ocspUri) {
			return TrustLinkerResult.UNDECIDED;
		}
		LOG.debug("OCSP URI: " + ocspUri);

		OCSPResp ocspResp = null;
		try {
			ocspResp = this.ocspRepository.findOcspResponse(ocspUri, childCertificate, certificate, validationDate);
		} catch (ServerNotAvailableException e) {
			LOG.error("OCSP server is unavailable!", e);
			throw new TrustLinkerResultException(TrustLinkerResultReason.OCSP_UNAVAILABLE, "OCSP server is unavailable!");
		}
		if (null == ocspResp) {
			LOG.debug("OCSP response not found");
			return TrustLinkerResult.UNDECIDED;
		}

		final int ocspRespStatus = ocspResp.getStatus();
		if (OCSPResponseStatus.SUCCESSFUL != ocspRespStatus) {
			LOG.debug("OCSP response status: " + ocspRespStatus);
			return TrustLinkerResult.UNDECIDED;
		}

		final Object responseObject = ocspResp.getResponseObject();
		final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) responseObject;

		final X509CertificateHolder[] responseCertificates = basicOCSPResp.getCerts();
		for (final X509CertificateHolder responseCertificate : responseCertificates) {
			LOG.debug("OCSP response cert: " + responseCertificate.getSubject());
			LOG.debug("OCSP response cert issuer: "
					+ responseCertificate.getIssuer());
		}

		algorithmPolicy.checkSignatureAlgorithm(basicOCSPResp
				.getSignatureAlgOID().getId(), validationDate);

		if (0 == responseCertificates.length) {
			/*
			 * This means that the OCSP response has been signed by the issuing
			 * CA itself.
			 */
			final ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
					.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
							certificate.getPublicKey());
			final boolean verificationResult = basicOCSPResp
					.isSignatureValid(contentVerifierProvider);
			if (false == verificationResult) {
				LOG.debug("OCSP response signature invalid");
				return TrustLinkerResult.UNDECIDED;
			}
		} else {
			/*
			 * We're dealing with a dedicated authorized OCSP Responder
			 * certificate, or of course with a CA that issues the OCSP
			 * Responses itself.
			 */

			final X509CertificateHolder ocspResponderCertificate = responseCertificates[0];
			final ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
					.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
							ocspResponderCertificate);

			final boolean verificationResult = basicOCSPResp
					.isSignatureValid(contentVerifierProvider);
			if (false == verificationResult) {
				LOG.debug("OCSP Responser response signature invalid");
				return TrustLinkerResult.UNDECIDED;
			}
			if (false == Arrays.equals(certificate.getEncoded(),
					ocspResponderCertificate.getEncoded())) {
				// check certificate signature algorithm
				algorithmPolicy.checkSignatureAlgorithm(
						ocspResponderCertificate.getSignatureAlgorithm()
								.getAlgorithm().getId(), validationDate);

				X509Certificate issuingCaCertificate;
				if (responseCertificates.length < 2) {
					// so the OCSP certificate chain only contains a single
					// entry
					LOG.debug("OCSP responder complete certificate chain missing");
					/*
					 * Here we assume that the OCSP Responder is directly signed
					 * by the CA.
					 */
					issuingCaCertificate = certificate;
				} else {
					final CertificateFactory certificateFactory = CertificateFactory
							.getInstance("X.509");
					issuingCaCertificate = (X509Certificate) certificateFactory
							.generateCertificate(new ByteArrayInputStream(
									responseCertificates[1].getEncoded()));
					/*
					 * Is next check really required?
					 */
					if (false == certificate.equals(issuingCaCertificate)) {
						LOG.debug("OCSP responder certificate not issued by CA");
						return TrustLinkerResult.UNDECIDED;
					}
				}
				// check certificate signature
				algorithmPolicy.checkSignatureAlgorithm(
						issuingCaCertificate.getSigAlgOID(), validationDate);

				final PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();
				final CertificateFactory certificateFactory = CertificateFactory
						.getInstance("X.509");
				final X509Certificate x509OcspResponderCertificate = (X509Certificate) certificateFactory
						.generateCertificate(new ByteArrayInputStream(
								ocspResponderCertificate.getEncoded()));
				LOG.debug("OCSP Responder public key fingerprint: "
						+ DigestUtils.sha1Hex(x509OcspResponderCertificate
								.getPublicKey().getEncoded()));
				publicKeyTrustLinker.hasTrustLink(x509OcspResponderCertificate,
						issuingCaCertificate, validationDate, revocationData,
						algorithmPolicy);
				if (null == x509OcspResponderCertificate
						.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck
								.getId())) {
					LOG.debug("OCSP Responder certificate should have id-pkix-ocsp-nocheck");
					/*
					 * TODO: perform CRL validation on the OCSP Responder
					 * certificate. On the other hand, do we really want to
					 * check the checker?
					 */
					return TrustLinkerResult.UNDECIDED;
				}
				final List<String> extendedKeyUsage = x509OcspResponderCertificate
						.getExtendedKeyUsage();
				if (null == extendedKeyUsage) {
					LOG.debug("OCSP Responder certificate has no extended key usage extension");
					return TrustLinkerResult.UNDECIDED;
				}
				if (false == extendedKeyUsage
						.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
					LOG.debug("OCSP Responder certificate should have a OCSPSigning extended key usage");
					return TrustLinkerResult.UNDECIDED;
				}
			} else {
				LOG.debug("OCSP Responder certificate equals the CA certificate");
				// and the CA certificate is already trusted at this point
			}
		}

		final DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
		final CertificateID certificateId = new CertificateID(
				digCalcProv.get(CertificateID.HASH_SHA1),
				new JcaX509CertificateHolder(certificate),
				childCertificate.getSerialNumber());

		final SingleResp[] singleResps = basicOCSPResp.getResponses();
		for (final SingleResp singleResp : singleResps) {
			final CertificateID responseCertificateId = singleResp.getCertID();
			if (false == certificateId.equals(responseCertificateId)) {
				continue;
			}
			final DateTime thisUpdate = new DateTime(singleResp.getThisUpdate());
			DateTime nextUpdate;
			if (null != singleResp.getNextUpdate()) {
				nextUpdate = new DateTime(singleResp.getNextUpdate());
			} else {
				LOG.debug("no OCSP nextUpdate");
				nextUpdate = thisUpdate;
			}
			LOG.debug("OCSP thisUpdate: " + thisUpdate);
			LOG.debug("(OCSP) nextUpdate: " + nextUpdate);
			final DateTime beginValidity = thisUpdate.minus(this.freshnessInterval);
			final DateTime endValidity = nextUpdate.plus(this.freshnessInterval);
			final DateTime validationDateTime = new DateTime(validationDate);
			if (validationDateTime.isBefore(beginValidity)) {
				LOG.warn("OCSP response not yet valid");
				continue;
			}
			if (validationDateTime.isAfter(endValidity)) {
				LOG.warn("OCSP response expired");
				continue;
			}
			if (null == singleResp.getCertStatus()) {
				LOG.debug("OCSP OK for: "
						+ childCertificate.getSubjectX500Principal());
				addRevocationData(revocationData, ocspResp, ocspUri);
				return TrustLinkerResult.TRUSTED;
			} else {
				LOG.debug("OCSP certificate status: "
						+ singleResp.getCertStatus().getClass().getName());
				if (singleResp.getCertStatus() instanceof RevokedStatus) {
					LOG.debug("OCSP status revoked");
				}
				addRevocationData(revocationData, ocspResp, ocspUri);
				throw new TrustLinkerResultException(
						TrustLinkerResultReason.INVALID_REVOCATION_STATUS,
						"certificate revoked by OCSP");
			}
		}

		LOG.debug("no matching OCSP response entry");
		return TrustLinkerResult.UNDECIDED;
	}

	private void addRevocationData(final RevocationData revocationData,
			final OCSPResp ocspResp, final URI uri) throws IOException {
		if (null == revocationData) {
			return;
		}
		final OCSPRevocationData ocspRevocationData = new OCSPRevocationData(
				ocspResp.getEncoded(), uri.toString());
		revocationData.getOcspRevocationData().add(ocspRevocationData);
	}

	private URI getOcspUri(final X509Certificate certificate) throws IOException,
			URISyntaxException {
		final URI ocspURI = getAccessLocation(certificate,
				X509ObjectIdentifiers.ocspAccessMethod);
		return ocspURI;
	}

	private URI getAccessLocation(final X509Certificate certificate,
			final ASN1ObjectIdentifier accessMethod) throws IOException,
			URISyntaxException {
		final byte[] authInfoAccessExtensionValue = certificate
				.getExtensionValue(Extension.authorityInfoAccess.getId());
		if (null == authInfoAccessExtensionValue) {
			return null;
		}
		AuthorityInformationAccess authorityInformationAccess;
		try (final ASN1InputStream authInfoStream = new ASN1InputStream(
				new ByteArrayInputStream(authInfoAccessExtensionValue))) {
			final DEROctetString oct = (DEROctetString) (authInfoStream.readObject());
			try (final ASN1InputStream octStream = new ASN1InputStream(oct.getOctets())) {
				authorityInformationAccess = AuthorityInformationAccess.getInstance(octStream.readObject());
			}
		}
		final AccessDescription[] accessDescriptions = authorityInformationAccess
				.getAccessDescriptions();
		for (final AccessDescription accessDescription : accessDescriptions) {
			LOG.debug("access method: " + accessDescription.getAccessMethod());
			final boolean correctAccessMethod = accessDescription.getAccessMethod()
					.equals(accessMethod);
			if (!correctAccessMethod) {
				continue;
			}
			final GeneralName gn = accessDescription.getAccessLocation();
			if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
				LOG.debug("not a uniform resource identifier");
				continue;
			}
			final DERIA5String str = DERIA5String.getInstance(gn.getName());
			final String accessLocation = str.getString();
			LOG.debug("access location: " + accessLocation);
			final URI uri = toURI(accessLocation);
			LOG.debug("access location URI: " + uri);
			return uri;
		}
		return null;
	}

	private URI toURI(final String str) throws URISyntaxException {
		final URI uri = new URI(str);
		return uri;
	}
}
