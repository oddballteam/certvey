package main

import (
	"fmt"
	"context"
	"strings"
	"crypto/x509"
	"encoding/pem"
	"os"
	"log"
	// "time"
	// "encoding/json"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/credentials"

	// CLI
	"github.com/urfave/cli/v2"
)

var ASCII_ART string = `  ___  ____  ____  ____  _  _  ____  _  _ 
 / __)(  __)(  _ \(_  _)/ )( \(  __)( \/ )
( (__  ) _)  )   /  )(  \ \/ / ) _)  )  / 
 \___)(____)(__\_) (__)  \__/ (____)(__/  
`

var (
	version, region, profile string
	awsSession               aws.Config
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

func setup() error {
	var err error
	fmt.Println(ASCII_ART)
	awsSession, err = config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), os.Getenv("AWS_SESSION_TOKEN"))),
		config.WithRegion("us-east-1"),
	)
	if err != nil {
		panic(err)
	}
	return nil
}

func main() {
	app := &cli.App{
		Name:    "certvey",
		Usage:   "AWS Certificate survey",
		Version: "v0.1.0",
		Before:  func(c *cli.Context) error { return setup() },
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "profile",
				Value:       "default",
				Usage:       "AWS profile to use",
				EnvVars:     []string{"AWS_PROFILE"},
				Destination: &profile,
			},
		},
		Action: func(*cli.Context) error {
			var err error
			if err = iamSearch(); err != nil {
				return err
			}
			if err = acmSearch(); err != nil {
				return err
			}
			if err = ssmSearch(); err != nil {
				return err
			}
			return nil
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func iamSearch() error {
	fmt.Println("\n\n============= IAM =============")
	clientIAM := iam.NewFromConfig(awsSession)
	iamCerts, err := clientIAM.ListServerCertificates(context.TODO(), &iam.ListServerCertificatesInput{})
	if err != nil {
		return err
	}
	if len(iamCerts.ServerCertificateMetadataList) < 1 {
		fmt.Println("Could not find any server certificates")
	}
	for _, metadata := range iamCerts.ServerCertificateMetadataList {
		fmt.Println("Expiration:           " + (*metadata.Expiration).Format("2006-01-02 15:04:05 Monday"))
		fmt.Println("ServerCertificateName " + *metadata.ServerCertificateName)
		fmt.Println("UploadDate:           " + (*metadata.UploadDate).Format("2006-01-02 15:04:05 Monday"))
		fmt.Println("")
	}
	return nil
}

func acmSearch() error {
	fmt.Println("\n============= ACM + ELB =============")
	clientACM := acm.NewFromConfig(awsSession)
	clientELB := elasticloadbalancing.NewFromConfig(awsSession)
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
			fmt.Println(err)
		}
		fmt.Println(*result.Certificate.DomainName)
		// fmt.Println("NotAfter", *result.Certificate.NotAfter)
		// fmt.Println("IssuedAt", *result.Certificate.IssuedAt)

		// ELB GET DNS NAME
		var elb []string
		for _, value := range result.Certificate.InUseBy {

			if strings.Contains(value, "/app/") || strings.Contains(value, "/net/") {
				fmt.Println(" ❌ skipping due to being a v2 elb", value)
			} else {
				split := strings.Split(value, "/")
				fmt.Println("        " + split[len(split) - 1], "| expires: ", result.Certificate.NotAfter.String())
				elb = append(elb, split[len(split) - 1])
			}
		}
		fmt.Println("     Relevant ELB DNS Names:")
		// fmt.Println("DEBUG:", elb)
		describeResult, err := clientELB.DescribeLoadBalancers(
			context.TODO(),
			&elasticloadbalancing.DescribeLoadBalancersInput{
				LoadBalancerNames: elb,
			},
		)
		if err != nil {
			return err
		}
		for _, value := range describeResult.LoadBalancerDescriptions {
			fmt.Println("        - ELB: " + *value.DNSName)
		}
	}
	return nil
}

func account() string {
	clientSTS := sts.NewFromConfig(awsSession)
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
	
	clientSSM := ssm.NewFromConfig(awsSession)
	filter := []types.ParameterStringFilter{{
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
			fmt.Println("There are 0 results in this request, breaking loop")
			break
		} else {
			fmt.Println("Request returned", len(resp.Parameters), "parameters, applying additional filters now...")
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

	fmt.Println(len(certs), "are valid certs")
	
	
	if len(certs) > 0 {
		chunkedCerts := chunkArr(certs, 10)
		for _, nextCerts := range chunkedCerts {
			out, err := clientSSM.GetParameters(context.TODO(), &ssm.GetParametersInput{
				Names: nextCerts,
				WithDecryption: aws.Bool(true),
			})
			if err != nil {
				return err
			}
			for _, value := range out.Parameters {
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
						fmt.Println(*value.Name, certi.DNSNames, certi.NotAfter)
					}
				}
			}
		}
	}
	return nil
}
