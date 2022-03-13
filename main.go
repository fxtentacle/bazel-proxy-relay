package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/elazarl/goproxy"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	Verbose                   bool
	ListenServerPort          string
	MitmCaCertificate         string
	MitmCaKey                 string
	RemoteProxyURL            string
	SkipProxyCertificateCheck bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:  "proxygate",
		Args: cobra.ExactArgs(0),
		RunE: run,
	}
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&ListenServerPort, "listen", "l", "127.0.0.1:3128", "bind HTTP proxy to ip:port")
	rootCmd.PersistentFlags().StringVarP(&MitmCaCertificate, "ca-cert", "c", "rootCA.pem", "CA certificate for proxying SSL")
	rootCmd.PersistentFlags().StringVarP(&MitmCaKey, "ca-key", "k", "rootCA-key.pem", "CA private key for proxying SSL")
	rootCmd.PersistentFlags().StringVarP(&RemoteProxyURL, "remote", "r", "https://user:pass@127.0.0.1/proxy/", "remote proxy URL prefix")
	rootCmd.PersistentFlags().BoolVar(&SkipProxyCertificateCheck, "skip-proxy-certificate-check", false, "do not verify that remote proxy has a valid SSL certificate")
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

const explain = `
Consider using https://github.com/FiloSottile/mkcert 
to create a trusted proxy CA. Run 
mkcert -CAROOT 
to get the path of the root CA files.
openssl x509 -in rootCA.pem -inform pem -outform der -out rootCA.der 
to convert it. And then import it into your Java keystore, 
because the bazel http_archive download is implemented in Java:
keytool -importcert -alias bazel-proxy-relay -keystore <path here>/cacerts \
 -storepass changeit -file rootCA.der
Then set the HTTP_PROXY and HTTPS_PROXY variables
and bazel shutdown to make sure it'll restart with the new configuration.
Afterwards, all Bazel downloads will be proxied through this 
local (unsecured) HTTP proxy which MITMs SSL connections 
so that it can rewrite all of the downloads 
to go through the remote (secure) HTTPS proxy.`

func run(cmd *cobra.Command, args []string) error {
	ca_cert, err := ioutil.ReadFile(MitmCaCertificate)
	if os.IsNotExist(err) {
		log.Fatalf("Could not read CA certificate from %s. %s", MitmCaCertificate, explain)
	}
	ca_key, err := ioutil.ReadFile(MitmCaKey)
	if os.IsNotExist(err) {
		log.Fatalf("Could not read CA private key from %s. %s", MitmCaKey, explain)
	}
	goproxy.GoproxyCa, err = tls.X509KeyPair(ca_cert, ca_key)
	if err != nil {
		return err
	}
	if goproxy.GoproxyCa.Leaf, err = x509.ParseCertificate(goproxy.GoproxyCa.Certificate[0]); err != nil {
		log.Fatalf("Error parsing CA: %v", err)
	}
	fmt.Println("Forwarding requests to", RemoteProxyURL)
	httpproxy := goproxy.NewProxyHttpServer()
	httpproxy.Verbose = Verbose
	httpproxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	httpproxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		new_url := strings.Join([]string{RemoteProxyURL, req.URL.Scheme, req.URL.Hostname(), req.URL.Path}, "/")
		if Verbose {
			fmt.Println("REWRITE", req.URL, "=>", new_url)
		}
		var err error
		req.URL, err = url.Parse(new_url)
		if Verbose {
			fmt.Println("PARSED INTO", req.URL, req.URL.Host, req.URL.User.Username(), req.URL.User.String())
		}
		if err != nil {
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, 500, fmt.Sprintf("Error parsing \"%s\".", new_url))
		}
		req.Host = req.URL.Host
		req.RequestURI = ""
		if SkipProxyCertificateCheck {
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			if Verbose {
				fmt.Println("ERROR %v", err)
			}
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, 500, fmt.Sprintf("Error downloading from remote proxy: %v", err))
		}
		return req, resp
	})
	fmt.Println("Listening on", ListenServerPort)
	fmt.Println("Configure Bazel with:", fmt.Sprintf("HTTP_PROXY=http://%s HTTPS_PROXY=http://%s", ListenServerPort, ListenServerPort))
	return http.ListenAndServe(ListenServerPort, httpproxy)
}
