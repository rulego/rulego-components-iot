/*
 * Copyright 2026 The RuleGo Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package influxdb

import (
	"encoding/json"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/el"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&QueryNode{})
}

// QueryConfig InfluxDB query configuration (connection fields same as WriteConfig, plus extra Query).
type QueryConfig struct {
	URL    string `json:"url" label:"URL" desc:"InfluxDB server URL, format: http://host:port" required:"true" ref:"primary"`
	Bucket string `json:"bucket" label:"Bucket" desc:"Bucket name" required:"true"`
	Org    string `json:"org" label:"Org" desc:"Organization name" required:"true"`
	Token  string `json:"token" label:"Token" desc:"Authentication token" required:"true" ref:"shared"`
	Query  string `json:"query" label:"Query" desc:"Flux query, supports ${metadata.key} and ${msg.key} substitution" required:"true"`
}

// QueryNode executes Flux query, results written as generic QueryResult (columns + rows) to msg.Data.
// Connection reuses WriteNode's SharedNode client.
type QueryNode struct {
	*WriteNode
	Config        QueryConfig
	queryTemplate el.Template
	queryHasVar   bool
}

func (x *QueryNode) New() types.Node {
	return &QueryNode{
		Config: QueryConfig{
			URL:    "http://127.0.0.1:8086",
			Bucket: "bucket0",
			Org:    "org0",
			Query:  `from(bucket: "bucket0") |> range(start: -1h) |> filter(fn: (r) => r._measurement == "cpu_load")`,
		},
	}
}

func (x *QueryNode) Type() string {
	return "x/influxdbQuery"
}

func (x *QueryNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	// Reuse WriteNode to establish connection
	x.WriteNode = &WriteNode{}
	if err := x.WriteNode.Init(ruleConfig, configuration); err != nil {
		return err
	}
	x.queryTemplate, _ = el.NewTemplate(x.Config.Query)
	x.queryHasVar = x.queryTemplate.HasVar()
	return nil
}

func (x *QueryNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	bucket := x.Config.Bucket
	org := x.Config.Org
	query := x.Config.Query
	if x.bucketTemplate.HasVar() || x.orgTemplate.HasVar() || x.queryHasVar {
		env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
		bucket = x.bucketTemplate.ExecuteAsString(env)
		org = x.orgTemplate.ExecuteAsString(env)
		query = x.queryTemplate.ExecuteAsString(env)
	}
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	res, err := newDriver(client, org, bucket).Query(ctx.GetContext(), org, query)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	data, _ := json.Marshal(res)
	msg.DataType = types.JSON
	msg.SetData(string(data))
	ctx.TellSuccess(msg)
}

func (x *QueryNode) Destroy() {
	_ = x.SharedNode.Close()
}

func (x *QueryNode) Desc() string {
	return "InfluxDB client for querying time-series data. Routes to Success/Failure"
}
