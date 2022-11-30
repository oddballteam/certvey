# EZAPP Bug
> Ezapp is missing these 6 parameters when they should show for some reason
- /mymedicare-sls/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /shared/INTERNAL_CERT	
- /sls/shared/ACM_PACE_NGINX_CERT	
- /slsgw/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /urr/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /app2/shared/ACM_PACE_NGINX_CERT	

# Content
- [EZAPP Bug](#ezapp-bug)
    + [Implemented](#implemented)
    + [as](#as)
- [DOCKER CMD](#docker-cmd)
- [📝 Dev Notes](#---dev-notes)
  * [CLI](#cli)
    + [Verify](#verify)
    + [Relevant Data](#relevant-data)
    + [Questions](#questions)
    + [Junk Notes](#junk-notes)
- [Exhaustive SSM parameter search for certs](#exhaustive-ssm-parameter-search-for-certs)
  * [PET](#pet)
    + [CERTS](#certs)
    + [Potential conditional](#potential-conditional)
  * [EZAPP](#ezapp)
    + [Valid certs](#valid-certs)
    + [Potential conditional](#potential-conditional-1)
    + [IAM](#iam)
  * [FLH](#flh)
    + [Potential conditional](#potential-conditional-2)
    + [Valid SSM certs](#valid-ssm-certs)
    + [IAM](#iam-1)
  * [ECWS](#ecws)
    + [Potential conditional](#potential-conditional-3)
    + [Valid SSM certs](#valid-ssm-certs-1)
    + [IAM](#iam-2)
- [Final conditional](#final-conditional)
- [Always return something useful for SSM](#always-return-something-useful-for-ssm)

### Implemented
help
-h
--help

-p
--profile

-v
--version
--verbose

### as
-d
--debug
--log

--output
--options
--config

-q
--quiet

# DOCKER CMD
docker build --tag certvey . && docker run \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN \
  certvey --profile flh

# 📝 Dev Notes
## CLI 
- aws acm describe-certificate --certificate-arn
- aws acm get-certificate --certificate-arn (do at least once)
- aws acm list-certificates
- aws iam list-server-certificates | jq -r '.ServerCertificateMetadataList[].ServerCertificateName'
- aws iam get-server-certificate --server-certificate-name pet-elb.healthcare.gov-20230116
- aws acm list-certificates | jq -r  '.CertificateSummaryList[].CertificateArn'
- aws acm describe-certificate --certificate-arn arn:aws:acm:us-east-1:521784486762:certificate/04cf9240-a071-4dff-b05d-3aeea1ae5487
  - DomainName
  - NotAfter
  - IssuedAt
- aws acm describe-certificate --certificate-arn arn:aws:acm:us-east-1:350076322261:certificate/6265afa4-857d-4af8-ad81-5f3084b370ad | jq '.Certificate.InUseBy'
- aws elb describe-load-balancers --load-balancer-names "plancompare-perf-v3-lb" | jq -r ".LoadBalancerDescriptions[].DNSName"
  - this name can be grabbed from the InUseBy arn with split
  - example result = "plancompare-perf-v3-lb-298567288.us-east-1.elb.amazonaws.com"
- aws ssm get-parameter --with-decryption --parameter-filter Key=Name,Option=Contains,Values=cert  | jq -r '.Parameter.Value'
- aws acm describe-certificate --certificate-arn ARN | jq '.Certificate.InUseBy'

### Verify
> Not all ACM certs should be considered live. This should be verified somehow. The best method is likely with the Status property. This could be checked to see if it matches the value "ISSUED". Alternatively There is another property DomainValidationOptions[0].ResourceRecord.Type == "CNAME". But this seems less reliable.

### Relevant Data
- DomainName
- NotAfter
- IssuedAt
- InUseBy[] .split('/')[0]
  - splitting this does not work as planned with /app/ or /net/ (application or network load balancers. However, after investigating no accounts use certificates with elbv2)
- CNAME or  DomainValidationOptions[0].ResourceRecord.Name (this doesn't seem that important but could be printed with the use of an extra flag)
- ELB DNSName (bonus data)

### Questions
- when can the acm be expected to auto-renew ([Confluence](https://confluence.cms.gov/display/WNMGWDSDEV/Application+and+Storage+Info+-+WDS+Certs) said 45-90 days before expiration)
- what is the best way to see if a cert is currently in use .Certificate.Status == 'ISSUED'?
- why does a cert chain have multiple expiration dates and what should be tracked for thes cert chains?
- The info on "_CHAIN" certs is very limited. But there are matching (root?) certs with more info. Should this (root) info be also given for the chain. This 

### Junk Notes
aws elbv2 describe-load-balancers --names "marketplace-prod-coverage-nlb" | jq '.LoadBalancers[].DNSName'
- example result = "marketplace-prod-coverage-nlb-0900c308d3f82948.elb.us-east-1.amazonaws.com"
aws elbv2 describe-load-balancers --load-balancer-arns arn:aws:elasticloadbalancing:us-east-1:350076322261:loadbalancer/net/marketplace-prod-coverage-nlb/0900c308d3f82948 | jq '.LoadBalancers[].DNSName'
- example result = "marketplace-prod-coverage-nlb-0900c308d3f82948.elb.us-east-1.amazonaws.com"
- should have /net/ in its arn to mean its v2
openssl x509 -text -noout


# Exhaustive SSM parameter search for certs
- aws ssm get-parameter  --with-decryption --name $1 | jq -r '.Parameter.Value' | openssl x509 -noout -dates | grep notAfter=
- aws ssm get-parameter  --with-decryption --name $1 | jq -r '.Parameter.Value' | openssl x509 -noout -text

## PET
- /marketplace-api/shared/ACM_PACE_NGINX_CERT
- /marketplace-api/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /marketplace-coverage/shared/ACM_PACE_NGINX_CERT	
- /marketplace-coverage/shared/ACM_PACE_NGINX_CERT_CHAIN	
-   /ops/internal/WDS_NGINX_INTERNAL_CERTIFICATE_KEY	
-   /plancompare/imp1a-v3/FFM_CA_CERT_PATH	
- /plancompare/imp1a-v3/FFM_CLIENT_CERT	
-   /plancompare/imp1a-v3/FFM_CLIENT_CERT_KEY	
- /plancompare/imp1a-v3/FFM_SAML_CERT	
-   /plancompare/imp1b-v3/FFM_CA_CERT_PATH	
- /plancompare/imp1b-v3/FFM_CLIENT_CERT	
-   /plancompare/imp1b-v3/FFM_CLIENT_CERT_KEY	
- /plancompare/imp1b-v3/FFM_SAML_CERT	
-   /plancompare/perf-v3/FFM_CA_CERT_DIR	
- /plancompare/perf-v3/FFM_SAML_CERT	
-   /plancompare/perf/FFM_CA_CERT_PATH	
-   /plancompare/prod-v3/FFM_CA_CERT_DIR	
- /plancompare/prod-v3/FFM_CLIENT_CERT	
-   /plancompare/prod-v3/FFM_CLIENT_CERT_KEY	
- /plancompare/prod-v3/FFM_SAML_CERT	
- /plancompare/shared/ACM_PACE_NGINX_CERT	
- /plancompare/shared/ACM_PACE_NGINX_CERT_CHAIN	
-   /plancompare/test-v3/FFM_CA_CERT_DIR	
- /plancompare/test-v3/FFM_CLIENT_CERT	
-   /plancompare/test-v3/FFM_CLIENT_CERT_KEY	
- /plancompare/test-v3/FFM_SAML_CERT	
- /shared/INTERNAL_CERT	
- /shared/INTERNAL_CERT_CHAIN	

### CERTS
> 17

- /plancompare/imp1a-v3/FFM_CLIENT_CERT	 (cert)
- /plancompare/imp1a-v3/FFM_SAML_KEY	   (RSA private key)
- /plancompare/imp1b-v3/FFM_CLIENT_CERT	 (cert)
- /plancompare/imp1b-v3/FFM_SAML_CERT	   (cert)
- /plancompare/imp1b-v3/FFM_SAML_KEY	   (RSA private key)
- /plancompare/prod-v3/FFM_CLIENT_CERT	 (cert)
- /plancompare/prod-v3/FFM_SAML_CERT	   (cert)
- /plancompare/test-v3/FFM_CLIENT_CERT	 (cert)
- /plancompare/test-v3/FFM_SAML_CERT	   (cert)
- /plancompare/test-v3/FFM_CLIENT_CERT_KEY	(Private Key)
- /plancompare/imp1b-v3/FFM_CLIENT_CERT_KEY	(Private Key)
- /plancompare/imp1a-v3/FFM_CLIENT_CERT_KEY	(Private Key)

### Potential conditional
> if the parameter has "CERT" and not "KEY"

## EZAPP
- /app2/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /app3/shared/ACM_PACE_NGINX_CERT	
- /app3/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /mymedicare-sls/shared/ACM_PACE_NGINX_CERT	
- /shared/INTERNAL_CERT_CHAIN	
-   /sls/imp/SLS2_JWT_CERT_BASE64	
-   /sls/mmdev/SLS2_JWT_CERT_BASE64	
-   /sls/mmprod/SLS2_JWT_CERT_BASE64	
-   /sls/perf/SLS2_JWT_CERT_BASE64	
-   /sls/prod/SLS2_JWT_CERT_BASE64	
- /sls/shared/ACM_PACE_NGINX_CERT_CHAIN	
-   /slsgw-web/imp/saml_ar_idp_cert	
-   /slsgw-web/imp/saml_esw_idp_cert	
-   /slsgw-web/imp/saml_esw_maximus_idp_cert	
-   /slsgw-web/imp/saml_esw_serco_idp_cert	
-   /slsgw-web/prod/jwt_session_cert	
-   /slsgw-web/prod/saml_esw_serco_idp_cert	
-   /slsgw-web/prod/saml_sp_cert	
-   /slsgw-web/test/jwt_session_cert	
-   /slsgw-web/test/saml_ar_idp_cert	
-   /slsgw-web/test/saml_esw_maximus_idp_cert	
-   /slsgw-web/test/saml_sp_cert	                    (malformed: -----END CERTIFICATE-----)
-   /slsgw-web/test/sessions_cert_0_pem	              (malformed: ')
-   /slsgw/prod/saml_ar_idp_cert	
-   /slsgw/prod/saml_esw_serco_idp_cert	
-   /slsgw/prod/saml_sp_cert	                        (malformed: ')
- /slsgw/shared/ACM_PACE_NGINX_CERT	
-   /slsgw/test/saml_ar_idp_cert	
-   /slsgw/test/saml_esw_idp_cert	
-   /slsgw/test/saml_esw_maximus_idp_cert	
-   /slsgw/test/saml_sp_cert	                        (malformed: -----END CERTIFICATE-----)
- /urr/shared/ACM_PACE_NGINX_CERT	
- /mymedicare-sls/shared/ACM_PACE_NGINX_CERT_CHAIN	
-   /ops/internal/WDS_NGINX_INTERNAL_CERTIFICATE_KEY	(RSA)
- /shared/INTERNAL_CERT	
-   /sls/mmdev/SESSION_JWT_CERT_BASE64	
-   /sls/mmimp/SLS2_JWT_CERT_BASE64	
-   /sls/mmtest/SLS2_JWT_CERT_BASE64	
- /sls/shared/ACM_PACE_NGINX_CERT	
-   /sls/test/SLS2_JWT_CERT_BASE64	
-   /slsgw-web/imp/jwt_session_cert	                  (malformed: ')
-   /slsgw-web/imp/saml_esw_eidm_idp_cert	
-   /slsgw-web/imp/saml_sp_cert	                      (malformed: ')
-   /slsgw-web/imp/sessions_cert_0_pem	              (malformed: ')
-   /slsgw-web/prod/sessions_cert_0_pem	              (malformed: ')
-   /slsgw-web/test/saml_esw_serco_idp_cert	
-   /slsgw/imp/jwt_session_cert	                      (malformed: ')
-   /slsgw/imp/saml_ar_idp_cert	
-   /slsgw/imp/saml_esw_serco_idp_cert	
-   /slsgw/imp/sessions_cert_0_pem	                  (malformed: ')
-   /slsgw/prod/jwt_session_cert	                    (malformed: ')
-   /slsgw/prod/saml_esw_maximus_idp_cert	 
-   /slsgw/prod/sessions_cert_0_pem	                  (malformed: ')
- /slsgw/shared/ACM_PACE_NGINX_CERT_CHAIN	
-   /slsgw/test/jwt_session_cert	                    (malformed: ')
-   /slsgw/test/saml_esw_eidm_idp_cert	
-   /slsgw/test/sessions_cert_0_pem	                  (malformed: ')
- /urr/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /app2/shared/ACM_PACE_NGINX_CERT	
-   /slsgw/test/saml_esw_serco_idp_cert	

### Valid certs
- /app2/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /app3/shared/ACM_PACE_NGINX_CERT	
- /app3/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /mymedicare-sls/shared/ACM_PACE_NGINX_CERT	
- /shared/INTERNAL_CERT_CHAIN	
- /sls/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /slsgw/shared/ACM_PACE_NGINX_CERT	
- /urr/shared/ACM_PACE_NGINX_CERT	
- /mymedicare-sls/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /shared/INTERNAL_CERT	
- /sls/shared/ACM_PACE_NGINX_CERT	
- /slsgw/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /urr/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /app2/shared/ACM_PACE_NGINX_CERT	

### Potential conditional
> has "ACM_PACE_NGINX_CERT" or is "/shared/INTERNAL_CERT_CHAIN" or is "/shared/INTERNAL_CERT"

### IAM
> ezapp has none

## FLH
- /flh/shared/ACM_PACE_NGINX_CERT	
- /flh/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /ops/internal/WDS_NGINX_INTERNAL_CERTIFICATE_KEY	 (RSA)
- /shared/INTERNAL_CERT	
- /shared/INTERNAL_CERT_CHAIN	

### Potential conditional
> has "ACM_PACE_NGINX_CERT" or is "/shared/INTERNAL_CERT_CHAIN" or is "/shared/INTERNAL_CERT"

### Valid SSM certs
- /flh/shared/ACM_PACE_NGINX_CERT	
- /flh/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /shared/INTERNAL_CERT	
- /shared/INTERNAL_CERT_CHAIN	

### IAM
- flh.healthcare.gov-20221126 = 2022-11-26
- flh_api_lower_20220729 = 2022-07-29
- flh_api_lower_20230819 = 2023-08-19

## ECWS
- /learn-preview/shared/ACM_PACE_NGINX_CERT	
- /learn-preview/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /ops/internal/WDS_NGINX_INTERNAL_CERTIFICATE_KEY	 (RSA)
- /shared/INTERNAL_CERT	
- /shared/INTERNAL_CERT_CHAIN	

### Potential conditional
> has "ACM_PACE_NGINX_CERT" or is "/shared/INTERNAL_CERT_CHAIN" or is "/shared/INTERNAL_CERT"

### Valid SSM certs
- /learn-preview/shared/ACM_PACE_NGINX_CERT	
- /learn-preview/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /shared/INTERNAL_CERT	
- /shared/INTERNAL_CERT_CHAIN	

### IAM
> ecws has none

# Final conditional
> = "CERT" != base64 != idp != session != saml_sp_cert != KEY



# Always return something useful for SSM
> all valid certs in ezapp ssm

"/app2/shared/ACM_PACE_NGINX_CERT_CHAIN",
"/app3/shared/ACM_PACE_NGINX_CERT",
"/app3/shared/ACM_PACE_NGINX_CERT_CHAIN",
"/mymedicare-sls/shared/ACM_PACE_NGINX_CERT",
"/shared/INTERNAL_CERT_CHAIN",
"/sls/shared/ACM_PACE_NGINX_CERT_CHAIN",
"/slsgw/shared/ACM_PACE_NGINX_CERT",
"/urr/shared/ACM_PACE_NGINX_CERT",
"/mymedicare-sls/shared/ACM_PACE_NGINX_CERT_CHAIN",
"/shared/INTERNAL_CERT"
"/sls/shared/ACM_PACE_NGINX_CERT",
"/slsgw/shared/ACM_PACE_NGINX_CERT_CHAIN",
"/urr/shared/ACM_PACE_NGINX_CERT_CHAIN",
"/app2/shared/ACM_PACE_NGINX_CERT"

> each chain has a connected cert with info on it
/app2/shared/ACM_PACE_NGINX_CERT_CHAIN (1) [14]
/app3/shared/ACM_PACE_NGINX_CERT_CHAIN (3) [2]
/mymedicare-sls/shared/ACM_PACE_NGINX_CERT_CHAIN (9) [4]
/shared/INTERNAL_CERT_CHAIN (5) [10]
/sls/shared/ACM_PACE_NGINX_CERT_CHAIN (6) [11]
/slsgw/shared/ACM_PACE_NGINX_CERT_CHAIN (12) [7]
/urr/shared/ACM_PACE_NGINX_CERT_CHAIN (13) [8]

