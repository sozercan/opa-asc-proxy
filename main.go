package main

import (
	//"bytes"
	"context"
	"encoding/json"
	//"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	//"os/exec"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

var (
	debug      = pflag.Bool("debug", true, "sets log to debug level")
	server *Server
	ctx      context.Context
)
const (
	prefixHTTPS           = "https://"
	manifestTagFetchCount = 100
)
// LogHook is used to setup custom hooks
type LogHook struct {
	Writer    io.Writer
	Loglevels []log.Level
}
// BaseClient is the base client for Acr.
type BaseClient struct {
	autorest.Client
	LoginURI string
}
// The AcrCLIClient is the struct that will be in charge of doing the http requests to the registry.
// it implements the AcrCLIClientInterface.
type AcrCLIClient struct {
	AutorestClient BaseClient
	// manifestTagFetchCount refers to how many tags or manifests can be retrieved in a single http request.
	manifestTagFetchCount int32
	loginURI              string
	// token refers to an ACR access token for use with bearer authentication.
	token *adal.Token
	// accessTokenExp refers to the expiration time for the access token, it is in a unix time format represented by a
	// 64 bit integer.
	accessTokenExp int64
}
// Manifest returns the requested manifest file
type Manifest struct {
	autorest.Response `json:"-"`
	// SchemaVersion - Schema version
	SchemaVersion *int32 `json:"schemaVersion,omitempty"`
	// MediaType - Media type usually application/vnd.docker.distribution.manifest.v2+json if this is in the accept header
	MediaType *string `json:"mediaType,omitempty"`
	// Config - V2 image config descriptor
	Config *V2Descriptor `json:"config,omitempty"`
	// Layers - List of V2 image layer information
	Layers *[]V2Descriptor `json:"layers,omitempty"`
	// Architecture - CPU architecture
	Architecture *string `json:"architecture,omitempty"`
	// Name - Image name
	Name *string `json:"name,omitempty"`
	// Tag - Image tag
	Tag *string `json:"tag,omitempty"`
}
// V2Descriptor docker V2 image layer descriptor including config and layers
type V2Descriptor struct {
	// MediaType - Layer media type
	MediaType *string `json:"mediaType,omitempty"`
	// Size - Layer size
	Size *int64 `json:"size,omitempty"`
	// Digest - Layer digest
	Digest *string `json:"digest,omitempty"`
}
func main() {
	//pflag.Parse()

	var err error

	setupLogger()

	ctx = context.Background()
	server, err = NewServer()
	if err != nil {
		log.Fatalf("[error] : %v", err)
	}
	http.HandleFunc("/process", handle)
	http.ListenAndServe(":8090", nil)

	os.Exit(0)
}

func handle(w http.ResponseWriter, req *http.Request) { 
	w.Header().Set("Content-Type", "application/json")
	
	image := req.URL.Query().Get("image") // e.g. : oss/kubernetes/aks/etcd-operator
	if image == "" {
		log.Info("Failed to provide image to query")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(nil)
	}
	registry := req.URL.Query().Get("registry") // e.g. : upstream.azurecr.io
	if registry == "" {
		log.Info("Failed to provide registry to query")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(nil)
	}
	
	// registry := "upstream.azurecr.io"
	// repo := "oss/kubernetes/ingress/nginx-ingress-controller"
	// tag := "0.16.2"
	repo := image
	tag := "latest"
	if strings.Contains(image, ":") {
		repo = strings.Split(image, ":")[0]
		tag = strings.Split(image, ":")[1]
	}
	
	// getImageShaBinary := "getimagesha.sh"
	// dir, err := os.Getwd()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	
	// cmd := exec.Command(
	// 	"sh",
	// 	getImageShaBinary,
	// 	registry,
	// 	repo,
	// 	tag,
	// )
	// log.Infof("cmd: %v", cmd)
	// cmd.Dir = dir
	// stdout := &bytes.Buffer{}
	// stderr := &bytes.Buffer{}
	// cmd.Stderr, cmd.Stdout = stderr, stdout

	// err = cmd.Run()
	// output := stdout.String()
	// log.Infof("output: %s",output)
	// if err != nil {
	// 	log.Errorf("error invoking cmd, err: %v, output: %v", err, stderr.String())
	// }

	username := os.Getenv("CLIENT_ID")
	password := os.Getenv("CLIENT_SECRET")
	acrClient := newAcrCLIClientWithBasicAuth("upstream.azurecr.io", username, password)
	manifestListBytes, err := acrClient.GetManifest(ctx, repo, tag)
	if err != nil {
	}
	if output == "null\n" {
		log.Infof("[error] : could not find valid digest %s", output)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(nil)
	} else {
		digest := strings.TrimSuffix(output, "\n")
		log.Infof("digest: %s",digest)
	
		data, err := server.Process(ctx, digest)
		if err != nil {
			log.Infof("[error] : %s", err)
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(data)
		} else {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(data)
		}
	}
}

// setupLogger sets up hooks to redirect stdout and stderr
func setupLogger() {
	log.SetOutput(ioutil.Discard)

	// set log level
	log.SetLevel(log.InfoLevel)
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	// add hook to send info, debug, warn level logs to stdout
	log.AddHook(&LogHook{
		Writer: os.Stdout,
		Loglevels: []log.Level{
			log.InfoLevel,
			log.DebugLevel,
			log.WarnLevel,
		},
	})

	// add hook to send panic, fatal, error logs to stderr
	log.AddHook(&LogHook{
		Writer: os.Stderr,
		Loglevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
			log.ErrorLevel,
		},
	})
}

// Fire is called when logging function with current hook is called
// write to appropriate writer based on log level
func (hook *LogHook) Fire(entry *log.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	_, err = hook.Writer.Write([]byte(line))
	return err
}

// Levels defines log levels at which hook is triggered
func (hook *LogHook) Levels() []log.Level {
	return hook.Loglevels
}
// LoginURLWithPrefix return the hostname of a registry.
func LoginURLWithPrefix(loginURL string) string {
	urlWithPrefix := loginURL
	if !strings.HasPrefix(loginURL, prefixHTTPS) {
		urlWithPrefix = prefixHTTPS + loginURL
	}
	return urlWithPrefix
}
// newAcrCLIClient creates a client that does not have any authentication.
func newAcrCLIClient(loginURL string) AcrCLIClient {
	loginURLPrefix := LoginURLWithPrefix(loginURL)
	return AcrCLIClient{
		AutorestClient: BaseClient{
			Client:   autorest.NewClientWithUserAgent(UserAgent()),
			LoginURI: loginURLPrefix,
		},
		// The manifestTagFetchCount is set to the default which is 100
		manifestTagFetchCount: manifestTagFetchCount,
		loginURI:              loginURL,
	}
}
// newAcrCLIClientWithBasicAuth creates a client that uses basic authentication.
func newAcrCLIClientWithBasicAuth(loginURL string, username string, password string) AcrCLIClient {
	newAcrCLIClient := newAcrCLIClient(loginURL)
	newAcrCLIClient.AutorestClient.Authorizer = autorest.NewBasicAuthorizer(username, password)
	return newAcrCLIClient
}
// UserAgent returns the UserAgent string to use when sending http.Requests.
func UserAgent() string {
	return "opa-asc-proxy"
}

// GetManifest pulls the image manifest file associated with the specified name and reference. Reference may be a tag
// or a digest
// Parameters:
// name - name of the image (including the namespace)
// reference - a tag or a digest, pointing to a specific image
// accept - accept header string delimited by comma. For example,
// application/vnd.docker.distribution.manifest.v2+json
func (client BaseClient) GetManifest(ctx context.Context, name string, reference string, accept string) (result Manifest, err error) {
	req, err := client.GetManifestPreparer(ctx, name, reference, accept)
	if err != nil {
		err = autorest.NewErrorWithError(err, "acr.BaseClient", "GetManifest", nil, "Failure preparing request")
		return
	}

	resp, err := client.GetManifestSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "acr.BaseClient", "GetManifest", resp, "Failure sending request")
		return
	}

	result, err = client.GetManifestResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "acr.BaseClient", "GetManifest", resp, "Failure responding to request")
	}

	return
}
// GetManifestPreparer prepares the GetManifest request.
func (client BaseClient) GetManifestPreparer(ctx context.Context, name string, reference string, accept string) (*http.Request, error) {
	urlParameters := map[string]interface{}{
		"url": client.LoginURI,
	}

	pathParameters := map[string]interface{}{
		"name":      autorest.Encode("path", name),
		"reference": autorest.Encode("path", reference),
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithCustomBaseURL("{url}", urlParameters),
		autorest.WithPathParameters("/v2/{name}/manifests/{reference}", pathParameters))
	if len(accept) > 0 {
		preparer = autorest.DecoratePreparer(preparer,
			autorest.WithHeader("accept", autorest.String(accept)))
	}
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// GetManifestSender sends the GetManifest request. The method will close the
// http.Response Body if it receives an error.
func (client BaseClient) GetManifestSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client, req,
		autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
}

// GetManifestResponder handles the response to the GetManifest request. The method always
// closes the http.Response Body.
func (client BaseClient) GetManifestResponder(resp *http.Response) (result Manifest, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}