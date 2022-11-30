package main

import (
	"fmt"
	"context"
	"strings"
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"
	// "encoding/json"

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

func typeof(v interface{}) string {
	return fmt.Sprintf("%T", v)
}

func chunkArr[T any](items []T, chunkSize int) (chunks [][]T) {
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}
	return append(chunks, items)
}

func prettyLogging(c *cli.Context) {
	// Fatal FTL 4 log.Fatal().Err(err).Msg("")
	// Error ERR 3 log.Error().Err(err).Msg("")
	// Warn WRN 2
	// Info INF 1
	// Debug DBG 0 log.Print("hi")
	var exclude []string
	var showTime bool = false
	var showLine bool = false
	// TODO: change this
	// var logLevel zerolog.Level = zerolog.ErrorLevel
	var logLevel zerolog.Level = zerolog.InfoLevel


	if c.Bool("v") {
		logLevel = zerolog.InfoLevel
	} else if c.Bool("vv") {
		logLevel = zerolog.DebugLevel
	} else if c.Bool("vvv") {
		logLevel = zerolog.TraceLevel
	}
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

func setup(c *cli.Context) error {
	var err error
	// TODO: remove true
	if c.Bool("v") || c.Bool("vv") || c.Bool("vvv") || true {
		fmt.Println(ASCII_ART)
		prettyLogging(c)
	}
	cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-east-1"))
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
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
				Name:    "vvv",
				Usage:   "Very very verbose mode",
				Value:   false,
			},
		},
		Action: func(c *cli.Context) error {
			if err := iamSearch(); err != nil {
				log.Fatal().Err(err).Msg("")
			}
			if err := acmSearch(); err != nil {
				log.Fatal().Err(err).Msg("")
			}
			if err := ssmSearch(); err != nil {
				log.Fatal().Err(err).Msg("")
			}
			return nil
		},
	}
	err := app.Run(os.Args); if err != nil {
		log.Fatal().Err(err).Msg("")
	}
}

func iamSearch() error {
	log.Info().Msg("\n============= IAM =============")
	// fmt.Println("\n\n============= IAM =============")
	clientIAM := iam.NewFromConfig(cfg)
	iamCerts, err := clientIAM.ListServerCertificates(context.TODO(), &iam.ListServerCertificatesInput{})
	if err != nil {
		return err
	}
	if len(iamCerts.ServerCertificateMetadataList) < 1 {
		log.Info().Msg("Could not find any server certificates")
	}
	for _, metadata := range iamCerts.ServerCertificateMetadataList {
		log.Info().Time("Expires", *metadata.Expiration).
			Time("Issued", *metadata.UploadDate).
			Msg(*metadata.ServerCertificateName)
	}
	return nil
}

func acmSearch() error {
	log.Info().Msg("\n============= ACM + ELB =============")
	clientACM := acm.NewFromConfig(cfg)
	clientELB := elasticloadbalancing.NewFromConfig(cfg)
	result, err := clientACM.ListCertificates(context.TODO(), &acm.ListCertificatesInput{})
	if err != nil {
		return err
	}
	var certificatesArn []*string
	for _, r := range result.CertificateSummaryList {
		certificatesArn = append(certificatesArn, r.CertificateArn)
	}
	for _, c := range certificatesArn {
		input := &acm.DescribeCertificateInput{
			CertificateArn: c,
		}
		result, err := clientACM.DescribeCertificate(context.TODO(), input)
		if err != nil {
			return err
		}
		log.Print(*result.Certificate.DomainName)

		// ELB GET DNS NAME
		var elb []string
		type cert struct {
			acm  string
			name []string
			dns []string
			expires time.Time
			issued time.Time
			status acmType.CertificateStatus // PENDING_VALIDATION | FAILED | VALIDATION_TIMED_OUT | ISSUED
			renewalEligibility acmType.RenewalEligibility // ELIGIBLE | INELIGIBLE
			validationStatus acmType.DomainStatus // PENDING_VALIDATION | SUCCESS | FAILED
		}
		temp := cert {acm: *result.Certificate.DomainName} 
		for _, value := range result.Certificate.InUseBy {

			if strings.Contains(value, "/app/") || strings.Contains(value, "/net/") {
				log.Warn().Str(" ❌ skipping due to being a v2 elb", value).Send()
			} else {
				split := strings.Split(value, "/")
				log.Print("        " + split[len(split) - 1], "| expires: ", result.Certificate.NotAfter.String())
				elb = append(elb, split[len(split) - 1])
				temp.expires = *result.Certificate.NotAfter
				temp.issued = *result.Certificate.IssuedAt
			}
		}

		temp.name = elb
		temp.status = result.Certificate.Status
		temp.renewalEligibility = result.Certificate.RenewalEligibility
		temp.validationStatus = result.Certificate.DomainValidationOptions[0].ValidationStatus

		describeResult, err := clientELB.DescribeLoadBalancers(
			context.TODO(),
			&elasticloadbalancing.DescribeLoadBalancersInput{
				LoadBalancerNames: elb,
			},
		)
		if err != nil {
			return err
		}

		var dns []string
		for _, value := range describeResult.LoadBalancerDescriptions {
			log.Print("        - ELB: " + *value.DNSName)
			dns = append(dns, *value.DNSName)
		}
		temp.dns = dns

		log.Info().Strs("LB", temp.name).
			Str("validationStatus", fmt.Sprintf("%v", temp.validationStatus)).
			Str("renewalEligibility", fmt.Sprintf("%v", temp.renewalEligibility)).
			Str("status", fmt.Sprintf("%v", temp.status)).
			Strs("DNS", temp.dns).
			Time("Expires", temp.expires).
			Time("Issued", temp.issued).
			Msg(temp.acm)
	}
	return nil
}

func account() string {
	clientSTS := sts.NewFromConfig(cfg)
	id, _ := clientSTS.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	return *id.Account
}

func ssmSearch() error {	
	fmt.Println("\n\n============= SSM =============")
	
	var certs []string
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
		if err != nil {
			return err
		}
		if len(resp.Parameters) == 0 {
			log.Info().Msg("There are 0 results in this request, breaking loop")
			break
		} else {
			log.Info().Msg(fmt.Sprintf("DescribeParameters found %v parameters, applying additional filters now...", len(resp.Parameters)))
			for _, value := range resp.Parameters {
				if strings.Contains(*value.Name, "BASE64") || 
				   strings.Contains(*value.Name, "idp") ||
				   strings.Contains(*value.Name, "_DIR") ||
				   strings.Contains(*value.Name, "_PATH") ||
					 strings.Contains(*value.Name, "session") ||
					 strings.Contains(*value.Name, "saml_sp_cert") ||
					 strings.Contains(*value.Name, "_KEY") ||
					 strings.Contains(*value.Name, "key") {
					// fmt.Println(" ❌", *value.Name)
				} else {
					// fmt.Println(" ✅", *value.Name)
					certs = append(certs, *value.Name)
				}


			}
			if nextToken == "first run" && len(resp.Parameters) < int(pageSize) {
				// fmt.Println("First run and below max results size. Breaking loop")
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
		certs = append(certs, "/mymedicare-sls/shared/ACM_PACE_NGINX_CERT_CHAIN")
		certs = append(certs, "/shared/INTERNAL_CERT")
		certs = append(certs, "/sls/shared/ACM_PACE_NGINX_CERT")
		certs = append(certs, "/slsgw/shared/ACM_PACE_NGINX_CERT_CHAIN")
		certs = append(certs, "/urr/shared/ACM_PACE_NGINX_CERT_CHAIN")
		certs = append(certs, "/app2/shared/ACM_PACE_NGINX_CERT")
	}

	log.Info().Msg(fmt.Sprintf("found %d valid certs", len(certs)))
	
	if len(certs) > 0 {
		chunkedCerts := chunkArr(certs, 10)
		for _, nextCerts := range chunkedCerts {
			log.Info().Strs("certs", nextCerts).Send()
			out, err := clientSSM.GetParameters(context.TODO(), &ssm.GetParametersInput{
				Names: nextCerts,
				WithDecryption: aws.Bool(true),
			})
			if err != nil {
				return err
			}
			// var lastName string = ""
			for _, value := range out.Parameters {


				// check if this is another cert chain
				// /app2/shared/ACM_PACE_NGINX_CERT_CHAIN
				// log.Print(*value.Name)
				// log.Print("last name ", lastName)
				// if *value.Name == lastName {
				// 	log.Print("repeat name", *value.Name, " contain chain = ", strings.Contains(*value.Name, "CHAIN"))
				// }
				// if strings.Contains(*value.Name, "CHAIN") && *value.Name == lastName {
				// 	log.Print("duplicate!!!")
				// }
				// lastName = *value.Name

				certPEMBlock := []byte(*value.Value)
				var certDERBlock *pem.Block
				for {
					certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
					if certDERBlock == nil {
						break
					}
					if certDERBlock.Type == "CERTIFICATE" {
						certi, err := x509.ParseCertificate(certDERBlock.Bytes)
						if err != nil {
							return err
						}
						// var cn string
						if strings.Contains(certi.Subject.String(), ".") {
							// Splits will return original string if not present
							splitComma := strings.Split(certi.Subject.String(), ",")
							split := strings.Split(splitComma[0], "=")

							// log.Warn().Str("subject ", split[len(split) - 1]).Send()
							// cn = split[len(split) - 1]

							log.Info().Str("CN", split[len(split) - 1]).
								Time("Expires", certi.NotAfter).
								Time("NotBefore", certi.NotBefore).
								Msg(fmt.Sprintf("%s", *value.Name))
						} else if len(certi.PermittedDNSDomains) > 0 {
							// log.Print("PermittedDNSDomains ", certi.PermittedDNSDomains)

							log.Info().Strs("PermittedDNSDomains", certi.PermittedDNSDomains).
								Time("Expires", certi.NotAfter).
								Time("NotBefore", certi.NotBefore).
								Msg(fmt.Sprintf("%s", *value.Name))
						} else {
							if len(certi.DNSNames) > 0 {
								log.Info().Strs("DNSNames", certi.DNSNames).
									Time("Expires", certi.NotAfter).
									Time("NotBefore", certi.NotBefore).
									Msg(fmt.Sprintf("%s", *value.Name))
							} else {
								log.Error().Str("Could not find anything useful for", *value.Name).Send()
							}
						}
					}
				}
			}
		}
	}
	return nil
}
