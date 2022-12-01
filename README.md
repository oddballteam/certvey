# EZAPP Bug
> Ezapp is missing these 6 parameters when they should show for some reason
- /mymedicare-sls/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /shared/INTERNAL_CERT	
- /sls/shared/ACM_PACE_NGINX_CERT	
- /slsgw/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /urr/shared/ACM_PACE_NGINX_CERT_CHAIN	
- /app2/shared/ACM_PACE_NGINX_CERT	

### Flags
- help [-h --help]
- --profile [-p]
- --verbose [-v]
- -vv
- --version [-V]
- --debug [-d]
- --file [-f]

### potential
--output
--config

# DOCKER CMD
docker build --tag certvey . && docker run \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN \
  certvey --profile flh

# 📝 Dev Notes
## CLI 
- aws acm describe-certificate --certificate-arn
- aws acm get-certificate --certificate-arn
- aws acm list-certificates
- aws iam list-server-certificates | jq -r '.ServerCertificateMetadataList[].ServerCertificateName'
- aws iam get-server-certificate --server-certificate-name pet-elb.healthcare.gov-20230116
- aws acm list-certificates | jq -r  '.CertificateSummaryList[].CertificateArn'
- aws acm describe-certificate --certificate-arn ARN
- aws acm describe-certificate --certificate-arn ARN | jq '.Certificate.InUseBy'
- aws elb describe-load-balancers --load-balancer-names LB_NAME | jq -r ".LoadBalancerDescriptions[].DNSName"
- aws ssm get-parameter --with-decryption --parameter-filter Key=Name,Option=Contains,Values=cert --name NAME  | jq -r '.Parameter.Value' | openssl x509 -noout -text
- aws acm describe-certificate --certificate-arn ARN | jq '.Certificate.InUseBy'
- aws elbv2 describe-load-balancers --names "marketplace-prod-coverage-nlb" | jq '.LoadBalancers[].DNSName'
- aws elbv2 describe-load-balancers --load-balancer-arns ARNS | jq '.LoadBalancers[].DNSName'

### Junk Notes
- if an el has /net/ or /app/ in its arn it's v2

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