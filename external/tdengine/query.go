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

package tdengine

import (
	"encoding/json"

	_ "github.com/taosdata/driver-go/v3/taosRestful"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/el"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&QueryNode{})
}

// QueryConfig TDengine query configuration.
type QueryConfig struct {
	DSN   string `json:"dsn" label:"DSN" desc:"TDengine DSN, format: root:taosdata@http(localhost:6041)/" required:"true" ref:"primary"`
	DB    string `json:"db" label:"DB" desc:"Database name" required:"true"`
	Query string `json:"query" label:"Query" desc:"SQL query, supports ${metadata.key} and ${msg.key} substitution" required:"true"`
}

// QueryNode executes SQL query on TDengine.
type QueryNode struct {
	*WriteNode
	Config        QueryConfig
	queryTemplate el.Template
	queryHasVar   bool
}

func (x *QueryNode) New() types.Node {
	return &QueryNode{
		Config: QueryConfig{
			DSN:   "root:taosdata@http(localhost:6041)/",
			DB:    "db0",
			Query: "SELECT * FROM cpu_load",
		},
	}
}

func (x *QueryNode) Type() string {
	return "x/tdengineQuery"
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
	db := x.Config.DB
	query := x.Config.Query
	if x.dbTemplate.HasVar() || x.queryHasVar {
		env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
		db = x.dbTemplate.ExecuteAsString(env)
		query = x.queryTemplate.ExecuteAsString(env)
	}
	dbConn, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	res, err := newDriver(dbConn).Query(ctx.GetContext(), db, query)
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
	return "TDengine client for querying time-series data. Routes to Success/Failure"
}
