package opc_ua

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/errors"
	uatest "github.com/gopcua/opcua/tests/python"
	"github.com/gopcua/opcua/ua"
	"github.com/robfig/cron/v3"
	"github.com/rulego/rulego/api/types"
	endpointApi "github.com/rulego/rulego/api/types/endpoint"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/endpoint"
	"github.com/rulego/rulego/endpoint/impl"
	"github.com/rulego/rulego/utils/maps"
)

const Type = types.EndpointTypePrefix + "opcua"
const MsgType = "OPC_UA_DATA"

// Endpoint 别名
type Endpoint = OpcUa

var _ endpointApi.Endpoint = (*Endpoint)(nil)

// 注册组件
func init() {
	_ = endpoint.Registry.Register(&Endpoint{})
}

type Data struct {
	DisplayName string      `json:"displayName"`
	NodeId      string      `json:"nodeId"`
	RecordTime  time.Time   `json:"recordTime"`
	SourceTime  time.Time   `json:"sourceTime"`
	Value       interface{} `json:"value"`
	Quality     uint32      `json:"quality"`
	FloatValue  float64     `json:"floatValue"`
	Timestamp   time.Time   `json:"timestamp"`
}

type RequestMessage struct {
	headers    textproto.MIMEHeader
	body       []byte
	data       []Data
	msg        *types.RuleMsg
	statusCode int
	err        error
}

func (r *RequestMessage) Body() []byte {
	b, err := json.Marshal(r.data)
	if err != nil {
		log.Println(err)
	}
	return b
}

func (r *RequestMessage) Headers() textproto.MIMEHeader {
	if r.headers == nil {
		r.headers = make(map[string][]string)
	}
	return r.headers
}

func (r *RequestMessage) From() string {
	return ""
}

// GetParam 不提供获取参数
func (r *RequestMessage) GetParam(key string) string {
	return ""
}

func (r *RequestMessage) SetMsg(msg *types.RuleMsg) {
	r.msg = msg
}
func (r *RequestMessage) GetMsg() *types.RuleMsg {
	if r.msg == nil {
		//默认指定是JSON格式，如果不是该类型，请在process函数中修改
		ruleMsg := types.NewMsg(0, MsgType, types.JSON, types.NewMetadata(), string(r.Body()))
		//ruleMsg.Metadata.PutValue(KeyRequestTopic, r.From())
		r.msg = &ruleMsg
	}
	return r.msg
}

func (r *RequestMessage) SetStatusCode(statusCode int) {
	r.statusCode = statusCode
}
func (r *RequestMessage) SetBody(body []byte) {
	r.body = body
}

// SetError set error
func (r *RequestMessage) SetError(err error) {

}

// GetError get error
func (r *RequestMessage) GetError() error {
	return r.err
}

type ResponseMessage struct {
	headers    textproto.MIMEHeader
	body       []byte
	data       []Data
	msg        *types.RuleMsg
	statusCode int
	err        error
}

func (r *ResponseMessage) Body() []byte {
	b, err := json.Marshal(r.body)
	if err != nil {
		log.Println(err)
	}
	return b
}

func (r *ResponseMessage) Headers() textproto.MIMEHeader {
	if r.headers == nil {
		r.headers = make(map[string][]string)
	}
	return r.headers
}

func (r *ResponseMessage) From() string {
	return ""
}

// GetParam 不提供获取参数
func (r *ResponseMessage) GetParam(key string) string {
	return ""
}

func (r *ResponseMessage) SetMsg(msg *types.RuleMsg) {
	r.msg = msg
}
func (r *ResponseMessage) GetMsg() *types.RuleMsg {
	if r.msg == nil {
		//默认指定是JSON格式，如果不是该类型，请在process函数中修改
		ruleMsg := types.NewMsg(0, MsgType, types.JSON, types.NewMetadata(), string(r.Body()))
		//ruleMsg.Metadata.PutValue(KeyRequestTopic, r.From())
		r.msg = &ruleMsg
	}
	return r.msg
}

func (r *ResponseMessage) SetStatusCode(statusCode int) {
	r.statusCode = statusCode
}
func (r *ResponseMessage) SetBody(body []byte) {
	r.body = body
}
func (r *ResponseMessage) getBody() []byte {
	return r.body
}

// SetError set error
func (r *ResponseMessage) SetError(err error) {

}

// GetError get error
func (r *ResponseMessage) GetError() error {
	return r.err
}

type OpcUaConfig struct {
	Server      string
	CertFile    string
	CertKeyFile string
	GenCert     bool
	AppUri      string

	Policy string
	Mode   string

	Auth     string
	Username string
	Password string

	Interval string
	NodeIds  []string
}

type OpcUa struct {
	impl.BaseEndpoint
	base.SharedNode[*opcua.Client]
	RuleConfig types.Config
	Config     OpcUaConfig
	client     *opcua.Client
	tasks      map[string]cron.EntryID
	CronTask   *cron.Cron
}

// Type 组件类型
func (x *OpcUa) Type() string {
	return Type
}

func (x *OpcUa) New() types.Node {
	return &OpcUa{
		Config: OpcUaConfig{
			Server: "127.0.0.1:1883",
		},
		CronTask: cron.New(
			cron.WithChain(cron.Recover(cron.DefaultLogger)), cron.WithLogger(cron.DefaultLogger))}
}

// Init 初始化
func (x *OpcUa) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	x.RuleConfig = ruleConfig
	_ = x.SharedNode.Init(x.RuleConfig, x.Type(), x.Config.Server, true, func() (*opcua.Client, error) {
		return x.initClient()
	})
	return err
}

// Destroy 销毁
func (x *OpcUa) Destroy() {
	_ = x.Close()
}

func (x *OpcUa) Close() error {
	if x.tasks != nil {
		for routeId, taskId := range x.tasks {
			delete(x.tasks, routeId)
			x.CronTask.Remove(taskId)
		}
		x.tasks = nil
	}
	if x.client != nil {
		x.client.Close(context.Background())
		x.client = nil
	}
	return nil
}

func (x *OpcUa) Id() string {
	return x.Config.Server
}

func (x *OpcUa) AddRouter(router endpointApi.Router, params ...interface{}) (string, error) {
	if router == nil {
		return "", errors.New("router cannot be nil")
	}
	routerId := router.GetId()
	if routerId == "" {
		routerId = router.GetFrom().ToString()
		router.SetId(routerId)
	}
	if x.tasks == nil {
		x.tasks = make(map[string]cron.EntryID)
	}
	x.Lock()
	defer x.Unlock()
	task := cron.New(
		cron.WithChain(cron.Recover(cron.DefaultLogger)), cron.WithLogger(cron.DefaultLogger))
	eid, err := task.AddFunc(fmt.Sprintf("@every %s", x.Config.Interval), func() {
		x.readNodes(router)
	})
	if err != nil {
		return "", err
	}
	task.Start()
	x.tasks[routerId] = eid
	return router.GetId(), nil
}

func (x *OpcUa) readNodes(router endpointApi.Router) error {
	ctx, cancel := context.WithTimeout(context.TODO(), 2*time.Second)
	defer func() {
		cancel()
	}()
	allIds := make([]*ua.ReadValueID, 0)
	data := make([]Data, 0)
	client, err := x.SharedNode.Get()
	if err != nil {
		x.Printf("get shared client error %v ", err)
		return err
	}
	for _, nodeId := range x.Config.NodeIds {
		id, err := ua.ParseNodeID(nodeId)
		if err != nil {
			x.Printf("parse node id error %v ", err)
			return err
		} else {
			allIds = append(allIds, &ua.ReadValueID{NodeID: id})
		}
		n := client.Node(id)
		lt, err := n.DisplayName(ctx)
		if err != nil {
			x.Printf("fetch node displayname error : %v ,nodeid : %v  ", err, nodeId)
			return err
		}
		data = append(data, Data{NodeId: id.String(), DisplayName: lt.Text})
	}

	req := &ua.ReadRequest{
		MaxAge:             1000,
		NodesToRead:        allIds,
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	}
	var resp *ua.ReadResponse
	resp, err = client.Read(ctx, req)
	if err != nil {
		x.Printf("point read error", err)
		return err
	} else {
		for i, result := range resp.Results {
			if result != nil && result.Status != ua.StatusOK {
				x.Printf("read node with bad status : %v  ", result.Status)
			} else {
				d := Data{
					DisplayName: data[i].DisplayName,
					NodeId:      data[i].NodeId,
					RecordTime:  result.ServerTimestamp,
					SourceTime:  result.SourceTimestamp,
					Value:       result.Value.Value(),
					Quality:     uint32(result.Status),
					Timestamp:   time.Now(),
				}
				d.ParseValue()
				data[i] = d
			}
		}
	}
	exchange := &endpoint.Exchange{
		In: &RequestMessage{data: data},
		Out: &ResponseMessage{
			data: data,
		}}
	x.DoProcess(ctx, router, exchange)
	return nil
}

func (d *Data) ParseValue() (*Data, error) {
	var err error
	if d != nil && d.Value != nil {
		switch d.Value.(type) {
		case int:
			d.FloatValue = float64(d.Value.(int))
		case int16:
			d.FloatValue = float64(d.Value.(int16))
		case int32:
			d.FloatValue = float64(d.Value.(int32))
		case int64:
			d.FloatValue = float64(d.Value.(int64))
		case uint16:
			d.FloatValue = float64(d.Value.(uint16))
		case uint32:
			d.FloatValue = float64(d.Value.(uint32))
		case float32:
			d.FloatValue = float64(d.Value.(float32))
		case float64:
			d.FloatValue = d.Value.(float64)
		case byte:
			s := string(d.Value.(byte))
			parseBool, err := strconv.ParseBool(s)
			if err == nil {
				if parseBool {
					d.FloatValue = 1
				} else {
					d.FloatValue = 0
				}
			}
		case bool:
			if d.Value.(bool) {
				d.FloatValue = 1
			} else {
				d.FloatValue = 0
			}
		default:
			return nil, errors.New(fmt.Sprintf("Type conversion is not supported : %v", d))
		}
	} else {
		err = errors.New("Data value is nil")
	}
	if err != nil {
		return d, err
	}
	return d, nil
}

func (x *OpcUa) RemoveRouter(routerId string, params ...interface{}) error {
	x.Lock()
	defer x.Unlock()
	if x.tasks != nil {
		if task, ok := x.tasks[routerId]; ok {
			delete(x.tasks, routerId)
			x.CronTask.Remove(task)
		} else {
			return fmt.Errorf("router: %s not found", routerId)
		}
	}
	return nil
}

func (x *OpcUa) Start() error {
	if !x.SharedNode.IsInit() {
		return x.SharedNode.Init(x.RuleConfig, x.Type(), x.Config.Server, true, func() (*opcua.Client, error) {
			return x.initClient()
		})
	}
	return nil
}

func (x *OpcUa) Printf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Printf(format, v...)
	}
}

// initClient 初始化客户端
func (x *OpcUa) initClient() (*opcua.Client, error) {
	if x.client != nil {
		return x.client, nil
	} else {
		ctx, cancel := context.WithTimeout(context.TODO(), 4*time.Second)
		x.Lock()
		defer func() {
			cancel()
			x.Unlock()
		}()
		if x.client != nil {
			return x.client, nil
		}
		var err error
		x.client, err = x.newOpcUaClient(ctx)
		return x.client, err
	}
}

func (x *OpcUa) newOpcUaClient(ctx context.Context) (*opcua.Client, error) {
	// Get a list of the endpoints for our target server
	endpoints, err := opcua.GetEndpoints(ctx, x.Config.Server)
	if err != nil {
		x.Printf("opcua get endpoints error : %v ", err)
		return nil, err
	}
	// Get the options to pass into the client based on the flags passed into the executable
	opts := x.createOptions(endpoints)
	// Create a Client with the selected options
	c, err := opcua.NewClient(x.Config.Server, opts...)
	if err != nil {
		x.Printf("opcua new client error : %v ", err)
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		x.Printf("connect opcua client error : %v ", err)
		return nil, err
	}
	return c, nil
}

func (x *OpcUa) createOptions(endpoints []*ua.EndpointDescription) []opcua.Option {

	opts := []opcua.Option{}

	// ApplicationURI is automatically read from the cert so is not required if a cert if provided
	if x.Config.CertFile == "" && !x.Config.GenCert {
		opts = append(opts, opcua.ApplicationURI(x.Config.AppUri))
	}

	var cert []byte
	var privateKey *rsa.PrivateKey
	if x.Config.GenCert || (x.Config.CertFile != "" && x.Config.CertKeyFile != "") {
		if x.Config.GenCert {
			certPEM, keyPEM, err := uatest.GenerateCert(x.Config.AppUri, 2048, 365*24*time.Hour)
			if err != nil {
				x.Printf("failed to generate cert: %v", err)
			}
			if err := os.WriteFile(x.Config.CertFile, certPEM, 0644); err != nil {
				x.Printf("failed to write %s: %v", err)
			}
			if err := os.WriteFile(x.Config.CertKeyFile, keyPEM, 0644); err != nil {
				x.Printf("failed to write %s: %v", err)
			}
		}
		x.Printf("Loading cert/key from %s/%s", x.Config.CertFile, x.Config.CertKeyFile)
		c, err := tls.LoadX509KeyPair(x.Config.CertFile, x.Config.CertKeyFile)
		if err != nil {
			x.Printf("Failed to load certificate: %v", err)
		} else {
			pk, ok := c.PrivateKey.(*rsa.PrivateKey)
			if !ok {
				x.Printf("Invalid private key")
			}
			cert = c.Certificate[0]
			privateKey = pk
			opts = append(opts, opcua.PrivateKey(pk), opcua.Certificate(cert))
		}
	}

	var secPolicy string
	switch {
	case x.Config.Policy == "auto":
		// set it later
	case strings.HasPrefix(x.Config.Policy, ua.SecurityPolicyURIPrefix):
		secPolicy = x.Config.Policy
	case x.Config.Policy == "None" || x.Config.Policy == "Basic128Rsa15" || x.Config.Policy == "Basic256" || x.Config.Policy == "Basic256Sha256" || x.Config.Policy == "Aes128_Sha256_RsaOaep" || x.Config.Policy == "Aes256_Sha256_RsaPss":
		secPolicy = ua.SecurityPolicyURIPrefix + x.Config.Policy
	default:
		x.Printf("Invalid security policy: %s", x.Config.Policy)
	}

	// Select the most appropriate authentication mode from server capabilities and user input
	authMode, authOptions := x.authOption(cert, privateKey)
	opts = append(opts, authOptions...)

	var secMode ua.MessageSecurityMode
	switch strings.ToLower(x.Config.Mode) {
	case "auto":
	case "none":
		secMode = ua.MessageSecurityModeNone
	case "sign":
		secMode = ua.MessageSecurityModeSign
	case "signandencrypt":
		secMode = ua.MessageSecurityModeSignAndEncrypt
	default:
		x.Printf("Invalid security mode: %s", x.Config.Mode)
	}

	// Allow input of only one of sec-mode,sec-policy when choosing 'None'
	if secMode == ua.MessageSecurityModeNone || secPolicy == ua.SecurityPolicyURINone {
		secMode = ua.MessageSecurityModeNone
		secPolicy = ua.SecurityPolicyURINone
	}

	// Find the best endpoint based on our input and server recommendation (highest SecurityMode+SecurityLevel)
	var serverEndpoint *ua.EndpointDescription
	switch {
	case x.Config.Mode == "auto" && x.Config.Policy == "auto": // No user selection, choose best
		for _, e := range endpoints {
			if serverEndpoint == nil || (e.SecurityMode >= serverEndpoint.SecurityMode && e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}

	case x.Config.Mode != "auto" && x.Config.Policy == "auto": // User only cares about mode, select highest securitylevel with that mode
		for _, e := range endpoints {
			if e.SecurityMode == secMode && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}

	case x.Config.Mode == "auto" && x.Config.Policy != "auto": // User only cares about policy, select highest securitylevel with that policy
		for _, e := range endpoints {
			if e.SecurityPolicyURI == secPolicy && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}

	default: // User cares about both
		fmt.Println("secMode: ", secMode, "secPolicy:", secPolicy)
		for _, e := range endpoints {
			if e.SecurityPolicyURI == secPolicy && e.SecurityMode == secMode && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}
	}

	if serverEndpoint == nil { // Didn't find an endpoint with matching policy and mode.
		x.Printf("unable to find suitable server endpoint with selected sec-policy and sec-mode")
		x.printEndpointOptions(endpoints)
		x.Printf("quitting")
	}

	secPolicy = serverEndpoint.SecurityPolicyURI
	secMode = serverEndpoint.SecurityMode

	// Check that the selected endpoint is a valid combo
	err := x.validateEndpointConfig(endpoints, secPolicy, secMode, authMode)
	if err != nil {
		x.Printf("error validating input: %s", err)
	}

	opts = append(opts, opcua.SecurityFromEndpoint(serverEndpoint, authMode))

	x.Printf("Using config:\nEndpoint: %s\nSecurity mode: %s, %s\nAuth mode : %s\n", serverEndpoint.EndpointURL, serverEndpoint.SecurityPolicyURI, serverEndpoint.SecurityMode, authMode)
	return opts
}

func (x *OpcUa) authOption(cert []byte, pk *rsa.PrivateKey) (ua.UserTokenType, []opcua.Option) {

	var authMode ua.UserTokenType
	var authOptions []opcua.Option
	switch strings.ToLower(x.Config.Auth) {
	case "anonymous":
		authMode = ua.UserTokenTypeAnonymous
		authOptions = append(authOptions, opcua.AuthAnonymous())

	case "username":
		authMode = ua.UserTokenTypeUserName
		authOptions = append(authOptions, opcua.AuthUsername(x.Config.Username, x.Config.Password))

	case "certificate":
		authMode = ua.UserTokenTypeCertificate
		// Note: You should still use these two Config options to load the auth certificate and private key
		// separately from the secure channel configuration even if the same certificate is used for both purposes
		authOptions = append(authOptions, opcua.AuthCertificate(cert))
		authOptions = append(authOptions, opcua.AuthPrivateKey(pk))

	case "issuedtoken":
		// todo: this is unsupported, fail here or fail in the opcua package?
		authMode = ua.UserTokenTypeIssuedToken
		authOptions = append(authOptions, opcua.AuthIssuedToken([]byte(nil)))

	default:
		x.Printf("unknown auth-mode, defaulting to Anonymous")
		authMode = ua.UserTokenTypeAnonymous
		authOptions = append(authOptions, opcua.AuthAnonymous())

	}

	return authMode, authOptions
}

func (x *OpcUa) validateEndpointConfig(endpoints []*ua.EndpointDescription, secPolicy string, secMode ua.MessageSecurityMode, authMode ua.UserTokenType) error {
	for _, e := range endpoints {
		if e.SecurityMode == secMode && e.SecurityPolicyURI == secPolicy {
			for _, t := range e.UserIdentityTokens {
				if t.TokenType == authMode {
					return nil
				}
			}
		}
	}

	err := errors.Errorf("server does not support an endpoint with security : %s , %s, %s", secPolicy, secMode, authMode)
	x.printEndpointOptions(endpoints)
	return err
}

func (x *OpcUa) printEndpointOptions(endpoints []*ua.EndpointDescription) {
	x.Printf("Valid options for the endpoint are:")
	x.Printf("         sec-policy    |    sec-mode     |      auth-modes\n")
	x.Printf("-----------------------|-----------------|---------------------------\n")
	for _, e := range endpoints {
		p := strings.TrimPrefix(e.SecurityPolicyURI, "http://opcfoundation.org/UA/SecurityPolicy#")
		m := strings.TrimPrefix(e.SecurityMode.String(), "MessageSecurityMode")
		var tt []string
		for _, t := range e.UserIdentityTokens {
			tok := strings.TrimPrefix(t.TokenType.String(), "UserTokenType")

			// Just show one entry if a server has multiple varieties of one TokenType (eg. different algorithms)
			dup := false
			for _, v := range tt {
				if tok == v {
					dup = true
					break
				}
			}
			if !dup {
				tt = append(tt, tok)
			}
		}
		x.Printf("%22s | %-15s | (%s)", p, m, strings.Join(tt, ","))
	}
}
