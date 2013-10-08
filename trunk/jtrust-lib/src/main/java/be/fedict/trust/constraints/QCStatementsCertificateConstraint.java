/*
 * Java Trust Project.
 * Copyright (C) 2009-2010 FedICT.
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

package be.fedict.trust.constraints;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;

import be.fedict.trust.CertificateConstraint;
import be.fedict.trust.TrustLinkerResultException;
import be.fedict.trust.TrustLinkerResultReason;

/**
 * QCStatements certificate constraint.
 * 
 * @author Frank Cornelis
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc3039.txt">RFC 3039</a>
 */
public class QCStatementsCertificateConstraint implements CertificateConstraint {

	private static final Log LOG = LogFactory
			.getLog(QCStatementsCertificateConstraint.class);

	private final Boolean qcComplianceFilter;

	public QCStatementsCertificateConstraint(Boolean qcComplianceFilter) {
		this.qcComplianceFilter = qcComplianceFilter;
	}

	public void check(X509Certificate certificate)
			throws TrustLinkerResultException, Exception {
		byte[] extensionValue = certificate
				.getExtensionValue(X509Extension.qCStatements.getId());
		if (null == extensionValue) {
			throw new TrustLinkerResultException(
					TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					"missing QCStatements extension");
		}
		DEROctetString oct = (DEROctetString) (new ASN1InputStream(
				new ByteArrayInputStream(extensionValue)).readObject());
		ASN1Sequence qcStatements = (ASN1Sequence) new ASN1InputStream(
				oct.getOctets()).readObject();
		Enumeration<?> qcStatementEnum = qcStatements.getObjects();
		boolean qcCompliance = false;
		while (qcStatementEnum.hasMoreElements()) {
			QCStatement qcStatement = QCStatement.getInstance(qcStatementEnum
					.nextElement());
			DERObjectIdentifier statementId = qcStatement.getStatementId();
			LOG.debug("statement Id: " + statementId.getId());
			if (QCStatement.id_etsi_qcs_QcCompliance.equals(statementId)) {
				qcCompliance = true;
			}
		}
		if (null != this.qcComplianceFilter) {
			if (qcCompliance != this.qcComplianceFilter) {
				throw new TrustLinkerResultException(
						TrustLinkerResultReason.CONSTRAINT_VIOLATION,
						"QCStatements not matching");
			}
		}
	}
}
