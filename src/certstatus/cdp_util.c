/** 
* @file cdp_util.c
* 
* @brief Utilities needed by and assisting the CDP functionality
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2021
*
* @author David von Oheimb <david.von.oheimb@siemens.com>
*
* This work is licensed under the terms of the Apache Software License 
* 2.0. See the COPYING file in the top-level directory.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <certstatus/cdp_util.h>
#include <certstatus/certstatus.h>

int CDP_get_x509_name(
    X509_NAME       *name,
    char            *name_utf8_buf,
    size_t          name_utf8_buf_len,
    unsigned long   flags)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);

    /* write the name into the memory buffer */
    X509_NAME_print_ex(bio, name, 0, flags);
    /* append terminating NUL */
    BIO_write(bio, "", 1);
    UTIL_safe_string_copy(bptr->data, name_utf8_buf, name_utf8_buf_len, NULL);
    BIO_free(bio);
    return 1;
}

int CDP_get_x509_time(
    const ASN1_TIME *time,
    char            *name_utf8_buf,
    size_t          name_utf8_buf_len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);

    /* write the time into the memory buffer */
    ASN1_TIME_print(bio, time);
    /* append terminating NUL */
    BIO_write(bio, "", 1);
    UTIL_safe_string_copy(bptr->data, name_utf8_buf, name_utf8_buf_len, NULL);
    BIO_free(bio);
    return 1;
}



/* Get the first general name from a stack of general names
 * that is of type GEN_URI. Return a const char * pointer to
 * the internal data. The pointer is valid only as long as
 * the genereral_names parameter given is not freed.
 */
const char *CDP_get_uri_from_general_names(
    GENERAL_NAMES *general_names)
{
    GENERAL_NAME    *name_entry;
    int             i;
    int             gtype;
    ASN1_STRING     *uri;

    for(i = 0; i < sk_GENERAL_NAME_num(general_names); ++i)
    {
        /* walk through all of the distribution points general names */
        name_entry = sk_GENERAL_NAME_value(general_names, i);
        /* if type is a URI, and if it contains one of the necessary
           protocol prefixes, the distribution point has been found
        */
        uri = GENERAL_NAME_get0_value(name_entry, &gtype);
        if(gtype == GEN_URI && ASN1_STRING_length(uri) > 7)
        {
            /* uri is of type ASN1_STRING */
            const char* asn1_uri = (char*)ASN1_STRING_get0_data(uri);
            if(strncasecmp(asn1_uri, "http://", 7) == 0
               || strncasecmp(asn1_uri, "https://", 8) == 0)
            {
                return asn1_uri;
            }
        }
    }
    return NULL;
}



const char *CDP_get_crl_distribution_point_from_distpoint(
    DIST_POINT *distpoint)
{
    /* RFC 5280 Page 46
     * If the DistributionPoint omits the reasons field, the CRL MUST
     * include revocation information for all reasons.  This profile
     * RECOMMENDS against segmenting CRLs by reason code.  When a conforming
     * CA includes a cRLDistributionPoints extension in a certificate, it
     * MUST include at least one DistributionPoint that points to a CRL that
     * covers the certificate for all reasons.
     */
    if (distpoint->reasons) {
        CDP_REASON_FLAGS reason_flags = 0;
        CDP_REASON_FLAGS single_flag = 1;   /* this is shifted throug all flags */
        int bit;
        for (bit = 0; bit < CDP_REASON_FLAGSCOUNT; ++bit) {
            if (ASN1_BIT_STRING_get_bit(distpoint->reasons, bit)) {
                reason_flags |= single_flag;
            }
            single_flag <<= 1;
        }

        if (reason_flags != CDP_REASON_FLAGSALL) {
            return NULL;
        }
    }
    /* no else, for distpoint->reasons==0 means all reasons are included */

    if (distpoint->distpoint) {
        if (distpoint->distpoint->type == 0) {
            /* type 0 means this is a fullname cdp */
            /* RFC 5280 Page 46
             * If the DistributionPointName contains a general name of type URI, the
             * following semantics MUST be assumed: the URI is a pointer to the
             * current CRL for the associated reasons and will be issued by the
             * associated cRLIssuer.  When the HTTP or FTP URI scheme is used, the
             * URI MUST point to a single DER encoded CRL as specified in
             * [RFC2585].
             */
            return CDP_get_uri_from_general_names(distpoint->distpoint->name.fullname);
        }
        else {
            /* RFC 5280 Page 46
             * If the DistributionPointName contains the single value
             * nameRelativeToCRLIssuer, the value provides a distinguished name
             * fragment.  The fragment is appended to the X.500 distinguished name
             * of the CRL issuer to obtain the distribution point name.
             *
             * -> this is not an URI scheme and therefore ignored in the current
             * implementation.
             */
#if 0 /* ignored */
            const STACK_OF(X509_NAME_ENTRY) *relNames = point->distpoint->name.relativename;
            // X509_NAME_print_ex(out, &ntmp, 0, XN_FLAG_ONELINE);
            // TODO: add issuer and handle more relative name stuff
            int j;
            for (j = 0; j < sk_X509_NAME_ENTRY_num(relNames); ++j) {
                X509_NAME_ENTRY *entry  = sk_X509_NAME_ENTRY_value(relNames, j);
                ASN1_OBJECT     *obj    = X509_NAME_ENTRY_get_object(entry);
                ASN1_STRING     *data   = X509_NAME_ENTRY_get_data(entry);
                const unsigned char *dat_str    = ASN1_STRING_get0_data(data);
                int                  extlen     = ASN1_STRING_length(data);
            }
#endif
        }
    }

    if (distpoint->CRLissuer) {
        /* RFC 5280 Page 47
         * The cRLIssuer identifies the entity that signs and issues the CRL.
         * If present, the cRLIssuer MUST only contain the distinguished name
         * (DN) from the issuer field of the CRL to which the DistributionPoint
         * is pointing.  The encoding of the name in the cRLIssuer field MUST be
         * exactly the same as the encoding in issuer field of the CRL.  If the
         * cRLIssuer field is included and the DN in that field does not
         * correspond to an X.500 or LDAP directory entry where CRL is located,
         * then conforming CAs MUST include the distributionPoint field.
         *
         * -> this is only used, when the crl is in a X.500 or LDAP directory
         * otherwise the distributionPoint (see above is needed). It can safely
         * be ignored in this implementation.
         */
    }
    return NULL;
}

const char *CDP_get_crl_distribution_point_from_extension(
    CRL_DIST_POINTS *cdp_extension)
{
    DIST_POINT *point;
    int i;
    /* CRL_DIST_POINTS is just a stack of DIST_POINT */
    for (i = 0; i < sk_DIST_POINT_num(cdp_extension); ++i) {
        /* take the next distribution point from the stack */
        point = sk_DIST_POINT_value(cdp_extension, i);

        const char *crl_distpoint =
            CDP_get_crl_distribution_point_from_distpoint(point);
        if (crl_distpoint != NULL) {
            return crl_distpoint;
        }
    }

    return NULL;
}

int CDP_get_crl_distribution_point_from_cert(
    const X509  *cert,
    int         nid,
    char        *cdp_utf8_buf,
    size_t      cdp_utf8_buf_len)
{
    /* only these to extensions carry a CDP */
    if (nid != NID_crl_distribution_points &&
        nid != NID_freshest_crl)
    {
        return 0;
    }

    /* retrieve the stack of extensions from the x509 certificate */
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    if (sk_X509_EXTENSION_num(exts) <= 0) {
        /* extension pointer not valid */
        return 0;
    }

    /* Use openssl to get the only extension of type nid. There are two
     * extensions that contain CDPs NID_crl_distribution_points,
     * NID_freshest_crl. If there are more than one of the requested
     * extensions it is an error and X509_get_ext_d2i returns null.
     */
    int critical = 0;
    CRL_DIST_POINTS *cdp_extension = X509_get_ext_d2i(cert, nid, &critical,
        0 /*no index, make sure it's only one extension*/);
    if (cdp_extension == NULL) {
        /* evaluate critical for error reason, if it matters */
        return 0;
    }

    const char *cdp_url = CDP_get_crl_distribution_point_from_extension(cdp_extension);
    if (cdp_url) {
        UTIL_safe_string_copy(cdp_url, cdp_utf8_buf, cdp_utf8_buf_len, NULL);
    }
    CRL_DIST_POINTS_free(cdp_extension);
    return cdp_url != 0 ? 1 : 0;
}


void LOG_cert_CDP(
    OPTIONAL const char *func,
    OPTIONAL const char *file,
    int                 lineno,
    severity            level,
    const X509          *cert)
{
    const size_t    CDP_LEN         = 2048;
    char            cdp[CDP_LEN];

    if (CDP_get_x509_name(X509_get_subject_name(cert), cdp, CDP_LEN,XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB)) {
        LOG(func, file, lineno, level, "subject  : %s", cdp);
    }
    if (CDP_get_x509_name(X509_get_issuer_name(cert), cdp, CDP_LEN, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB)) {
        LOG(func, file, lineno, level, "issuer   : %s", cdp);
    }
    if (CDP_get_crl_distribution_point_from_cert(cert,
        NID_crl_distribution_points, cdp, CDP_LEN))
    {
        LOG(func, file, lineno, level, "cdp      : %s", cdp);
    }
    if (CDP_get_crl_distribution_point_from_cert(cert,
        NID_freshest_crl, cdp, CDP_LEN))
    {
        LOG(func, file, lineno, level, "delta cdp: %s", cdp);
    }
}
