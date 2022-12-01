package main

import (
	"fmt"
	"context"
	"strings"
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmType "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmType "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"

	// CLI
	"github.com/urfave/cli/v2"

	// Logging
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var ASCII_ART string = `  ___  ____  ____  ____  _  _  ____  _  _ 
 / __)(  __)(  _ \(_  _)/ )( \(  __)( \/ )
( (__  ) _)  )   /  )(  \ \/ / ) _)  )  / 
 \___)(____)(__\_) (__)  \__/ (____)(__/`

var (
	version, region, profile string
	verbosePrints            bool
	cfg                      aws.Config
)

type cert struct {
	Name  string
	LB []string
	DNS []string
	CertArn string
	Expires time.Time
	Issued time.Time
	NotBefore time.Time
	UploadDate time.Time
	Status acmType.CertificateStatus // PENDING_VALIDATION | FAILED | VALIDATION_TIMED_OUT | ISSUED
	RenewalEligibility acmType.RenewalEligibility // ELIGIBLE | INELIGIBLE
	ValidationStatus acmType.DomainStatus // PENDING_VALIDATION | SUCCESS | FAILED
}


func typeof(v interface{}) string {
	return fmt.Sprintf("%T", v)
}

func chunkArr[T any](items []T, chunkSize int) (chunks [][]T) {
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}
	return append(chunks, items)
}

func check(err error) {
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
}

func buildLogger(c *cli.Context) {
	// 4 FTL log.Fatal().Err(err).Msg("")
	// 3 ERR log.Error().Err(err).Msg("")
	// 2 WRN log.Warn().Msg("")
	// 1 INF log.Info().Msg("")
	// 0 DBG log.Print("")
	// - TRC log.Trace().Msg("")
	var logLevel zerolog.Level = zerolog.WarnLevel

	if c.Bool("verbose") {
		logLevel = zerolog.InfoLevel
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else if c.Bool("vv") {
		logLevel = zerolog.TraceLevel
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}
	if c.Bool("quiet") {
		logLevel = zerolog.FatalLevel
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	}
	if c.Bool("debug") {
		var exclude []string
		var showTime bool = false
		var showLine bool = false
		if !showTime {
			exclude = append(exclude, zerolog.TimestampFieldName) 
		}
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out: os.Stderr,
			PartsExclude: exclude,
			FormatCaller: func(i interface{}) string {
				line := strings.Split(fmt.Sprintf("%s", i), ":")
				if showLine {
					return "@" + line[len(line) - 1]
				}
				return ""
			},
		}).Level(logLevel).With().Caller().Logger()
	}
	if !c.Bool("quiet") {
		fmt.Println(ASCII_ART)
	}

	zerolog.SetGlobalLevel(logLevel)
}

func setup(c *cli.Context) error {
	var err error
	buildLogger(c)
	cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-east-1"))
	check(err)
	return nil
}

func main() {
	// Using the Python method of capital V for version
	// and lowercase v for verbose logging
	cli.VersionFlag = &cli.BoolFlag{
		Name:    "version",
		Aliases: []string{"V"},
		Usage:   "print certvey version",
	}
	app := &cli.App{
		Name:    "certvey",
		Usage:   "AWS Certificate survey",
		Version: "v0.1.0",
		Compiled: time.Now(),
		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Example Human",
				Email: "human@example.com",
			},
		},
		Before:  func(c *cli.Context) error { return setup(c) },
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "profile",
				Value:       "pet",
				Usage:       "AWS profile to use",
				EnvVars:     []string{"AWS_PROFILE"},
				Aliases:     []string{"p"},
				Destination: &profile,
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Verbose mode",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:    "vv",
				Usage:   "Very verbose mode",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "Quiet mode",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:    "debug",
				Aliases: []string{"d"},
				Usage:   "Debug mode",
				Value:   false,
			},
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Usage:   "file directory and name to output cert data to",
				Required: true,
			},
		},
		Action: func(c *cli.Context) error {
			var certs []cert
			iamCerts := iamSearch()
			log.Info().Interface("certs", iamCerts).Int("num", len(iamCerts)).Send()
			acmCerts := acmSearch()
			log.Info().Interface("certs", acmCerts).Int("num", len(acmCerts)).Send()
			ssmCerts := ssmSearch()
			log.Info().Interface("certs", ssmCerts).Int("num", len(ssmCerts)).Send()

			certs = append(certs, iamCerts...)
			certs = append(certs, acmCerts...)
			certs = append(certs, ssmCerts...)
			log.Info().Interface("certs", certs).Send()

			// write to a file
			file, err := os.OpenFile(c.String("file"), os.O_CREATE, os.ModePerm) 
			check(err)
			defer file.Close()  
			encoder := json.NewEncoder(file) 
			encoder.Encode(certs)

			return nil
		},
	}
	err := app.Run(os.Args)
	check(err)
}

func iamSearch() []cert {
	log.Info().Msg("\n============= IAM =============")
	clientIAM := iam.NewFromConfig(cfg)
	iamCerts, err := clientIAM.ListServerCertificates(context.TODO(), &iam.ListServerCertificatesInput{})
	check(err)
	if len(iamCerts.ServerCertificateMetadataList) < 1 {
		log.Info().Msg("Could not find any server certificates")
	}
	
	var arns []string
	for _, metadata := range iamCerts.ServerCertificateMetadataList {
		arns = append(arns, *metadata.Arn)
	}

	inUseLB := inUseBy(arns)
	
	// add LB info
	var certs []cert
	for _, c := range iamCerts.ServerCertificateMetadataList {
		tempCert := cert{}
		for _, lb := range inUseLB {
			if lb.CertArn == *c.Arn {
				tempCert = cert{
					LB: []string{lb.Name},
					DNS: lb.DNS,
				}
				
			}
		}
		
		if tempCert.DNS != nil {
			log.Info().Strs("LB", tempCert.LB).
				Strs("DNS", tempCert.DNS).
				Time("Expires", *c.Expiration).
				Time("Issued", *c.UploadDate).
				Msg(*c.ServerCertificateName)
			cert := cert{
				LB: tempCert.LB,
				DNS: tempCert.DNS,
				Expires: *c.Expiration,
				UploadDate: *c.UploadDate,
				Name: *c.ServerCertificateName,
			}
			certs = append(certs, cert)
		} else {
			log.Info().Time("Expires", *c.Expiration).
				Time("Issued", *c.UploadDate).
				Msg(*c.ServerCertificateName)
			certs = append(certs, cert{
				Expires: *c.Expiration,
				UploadDate: *c.UploadDate,
				Name: *c.ServerCertificateName,
			})
		}
	}
	return certs
}

func inUseBy(arns []string) []cert {
	clientELB := elasticloadbalancing.NewFromConfig(cfg)
	describeResult, err := clientELB.DescribeLoadBalancers(
		context.TODO(),
		&elasticloadbalancing.DescribeLoadBalancersInput{}, // PageSize 400 default
	)
	check(err)
	var lbs []cert 
	for _, lb := range describeResult.LoadBalancerDescriptions {
		if len(lb.ListenerDescriptions) > 0 {
			if lb.ListenerDescriptions[0].Listener.SSLCertificateId != nil {
				
				log.Trace().Str("Arn", *lb.ListenerDescriptions[0].Listener.SSLCertificateId).
					Msg("load balancer found with a cert")

				for _, arnInput := range arns {
					if *lb.ListenerDescriptions[0].Listener.SSLCertificateId == arnInput {
						log.Trace().Msg("Found matching ARNs")
						lbs = append(lbs, cert{CertArn: arnInput, DNS: []string{*lb.DNSName}, Name: *lb.LoadBalancerName})
					}
				}
			}
		}
	}
	return lbs
}

func acmSearch() []cert {
	log.Info().Msg("\n============= ACM + ELB =============")
	clientACM := acm.NewFromConfig(cfg)
	clientELB := elasticloadbalancing.NewFromConfig(cfg)
	result, err := clientACM.ListCertificates(context.TODO(), &acm.ListCertificatesInput{})
	check(err)
	var certificatesArn []*string
	for _, r := range result.CertificateSummaryList {
		certificatesArn = append(certificatesArn, r.CertificateArn)
	}

	var certs []cert
	for _, c := range certificatesArn {
		input := &acm.DescribeCertificateInput{
			CertificateArn: c,
		}
		result, err := clientACM.DescribeCertificate(context.TODO(), input)
		check(err)
		log.Trace().Msg(*result.Certificate.DomainName)

		// ELB GET DNS NAME
		var lbs []string
		cert := cert{Name: *result.Certificate.DomainName} 
		for _, value := range result.Certificate.InUseBy {

			if strings.Contains(value, "/app/") || strings.Contains(value, "/net/") {
				log.Warn().Str(" ❌ skipping due to being a v2 elb", value).Send()
			} else {
				split := strings.Split(value, "/")
				log.Trace().Msg(fmt.Sprintf("        %v | expires: %v", result.Certificate.NotAfter.String(), split[len(split) - 1]))
				lbs = append(lbs, split[len(split) - 1])
				cert.Expires = *result.Certificate.NotAfter
				cert.Issued = *result.Certificate.IssuedAt
			}
		}

		cert.LB = lbs
		cert.Status = result.Certificate.Status
		cert.RenewalEligibility = result.Certificate.RenewalEligibility
		cert.ValidationStatus = result.Certificate.DomainValidationOptions[0].ValidationStatus

		describeResult, err := clientELB.DescribeLoadBalancers(
			context.TODO(),
			&elasticloadbalancing.DescribeLoadBalancersInput{
				LoadBalancerNames: lbs,
			},
		)
		check(err)
		var dns []string
		for _, value := range describeResult.LoadBalancerDescriptions {
			log.Trace().Msg(fmt.Sprintf("        - ELB: %v", *value.DNSName))
			dns = append(dns, *value.DNSName)
		}
		cert.DNS = dns

		log.Info().Strs("LB", cert.LB).
			Str("validationStatus", fmt.Sprintf("%v", cert.ValidationStatus)).
			Str("renewalEligibility", fmt.Sprintf("%v", cert.RenewalEligibility)).
			Str("status", fmt.Sprintf("%v", cert.Status)).
			Strs("DNS", cert.DNS).
			Time("Expires", cert.Expires).
			Time("Issued", cert.Issued).
			Msg(cert.Name)

		certs = append(certs, cert)
	}
	return certs
}

func account() string {
	clientSTS := sts.NewFromConfig(cfg)
	id, _ := clientSTS.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	return *id.Account
}

func ssmSearch() []cert {	
	log.Info().Msg("\n============= SSM =============")
	
	var certs []cert
	var secrets []string
	var resp *ssm.DescribeParametersOutput
	var err error
	var nextToken string = "first run" 
	var pageSize int32 = 50
	
	clientSSM := ssm.NewFromConfig(cfg)
	filter := []ssmType.ParameterStringFilter{{
		Key:    aws.String("Name"),
		Option: aws.String("Contains"),
		Values: []string{"cert"},
	}}

	for len(nextToken) > 1 {
		if resp == nil {
			resp, err = clientSSM.DescribeParameters(context.TODO(), &ssm.DescribeParametersInput{
				MaxResults:       aws.Int32(pageSize),
				ParameterFilters: filter,
			})
		} else {
			resp, err = clientSSM.DescribeParameters(context.TODO(), &ssm.DescribeParametersInput{
				MaxResults:       aws.Int32(pageSize),
				ParameterFilters: filter,
				NextToken: aws.String(nextToken),
			})
		}
		check(err)
		if len(resp.Parameters) == 0 {
			log.Trace().Msg("There are 0 results in this request, breaking loop")
			break
		} else {
			log.Trace().Msg(fmt.Sprintf("DescribeParameters found %v parameters, applying additional filters now...", len(resp.Parameters)))
			for _, value := range resp.Parameters {
				if strings.Contains(*value.Name, "BASE64") || 
				   strings.Contains(*value.Name, "idp") ||
				   strings.Contains(*value.Name, "_DIR") ||
				   strings.Contains(*value.Name, "_PATH") ||
					 strings.Contains(*value.Name, "session") ||
					 strings.Contains(*value.Name, "saml_sp_cert") ||
					 strings.Contains(*value.Name, "_KEY") ||
					 strings.Contains(*value.Name, "key") {
					log.Trace().Str("❌", *value.Name).Msg("Filtered out Param")
				} else {
					log.Trace().Str("✅", *value.Name).Msg("Adding Param")
					secrets = append(secrets, *value.Name)
				}
			}
			if nextToken == "first run" && len(resp.Parameters) < int(pageSize) {
				log.Trace().Msg("First run and below max results size. Breaking loop")
				break
			}
			nextToken = *resp.NextToken
		}
	}


	// EZAPP bug where these 6 parameters do not show in DescribeParameters
	// /mymedicare-sls/shared/ACM_PACE_NGINX_CERT_CHAIN	(only if contains is removed)
	// /shared/INTERNAL_CERT (if selected exactly)
	// /sls/shared/ACM_PACE_NGINX_CERT (if selected exactly)
	// /slsgw/shared/ACM_PACE_NGINX_CERT_CHAIN (only if contains is removed)
	// /urr/shared/ACM_PACE_NGINX_CERT_CHAIN (only if contains is removed)
	// /app2/shared/ACM_PACE_NGINX_CERT (if selected exactly)
	awsAccount := account()
	if awsAccount == "074424520335" {
		secrets = append(secrets, "/mymedicare-sls/shared/ACM_PACE_NGINX_CERT_CHAIN")
		secrets = append(secrets, "/shared/INTERNAL_CERT")
		secrets = append(secrets, "/sls/shared/ACM_PACE_NGINX_CERT")
		secrets = append(secrets, "/slsgw/shared/ACM_PACE_NGINX_CERT_CHAIN")
		secrets = append(secrets, "/urr/shared/ACM_PACE_NGINX_CERT_CHAIN")
		secrets = append(secrets, "/app2/shared/ACM_PACE_NGINX_CERT")
	}

	log.Trace().Msg(fmt.Sprintf("found %d valid certs", len(secrets)))
	
	if len(secrets) > 0 {
		chunkedSecrets := chunkArr(secrets, 10)
		for _, tenSecrets := range chunkedSecrets {
			log.Trace().Strs("certs", tenSecrets).Send()
			out, err := clientSSM.GetParameters(context.TODO(), &ssm.GetParametersInput{
				Names: tenSecrets,
				WithDecryption: aws.Bool(true),
			})
			check(err)
			
			for _, value := range out.Parameters {
				cert := cert{Name: *value.Name}
				certPEMBlock := []byte(*value.Value)
				var certDERBlock *pem.Block
				for {
					certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
					if certDERBlock == nil {
						break
					}
					if certDERBlock.Type == "CERTIFICATE" {
						certi, err := x509.ParseCertificate(certDERBlock.Bytes)
						check(err)

						if !cert.Expires.IsZero() {
							// Additional Cert chain block, set the closer expiration
							if cert.Expires.After(certi.NotAfter) {
								log.Trace().Msg(fmt.Sprintf("%v after %v setting closer expiration", cert.Expires, certi.NotAfter))
								cert.Expires = certi.NotAfter
							}
						} else {
							// Set expiration from first block
							cert.Expires = certi.NotAfter
							cert.NotBefore = certi.NotBefore
						}

						cert.Name = *value.Name

						if strings.Contains(certi.Subject.String(), ".") {
							splitComma := strings.Split(certi.Subject.String(), ",")
							split := strings.Split(splitComma[0], "=")
							cert.DNS = []string{split[len(split) - 1]}
						}

						if len(certi.PermittedDNSDomains) > 0 {
							cert.DNS = certi.PermittedDNSDomains
						}

						if len(certi.DNSNames) > 0 {
							cert.DNS = certi.DNSNames
						}
					}
				}
				certs = append(certs, cert)
				log.Info().Strs("DNS", cert.DNS).
					Time("Expires", cert.Expires).
					Time("NotBefore", cert.NotBefore).
					Msg(cert.Name)
			}
		}
	}
	return certs
}
