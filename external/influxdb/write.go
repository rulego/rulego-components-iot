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

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/el"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&WriteNode{})
}

// WriteConfig InfluxDB write connection configuration.
type WriteConfig struct {
	URL    string `json:"url" label:"URL" desc:"InfluxDB server URL, format: http://host:port" required:"true" ref:"primary"`
	Bucket string `json:"bucket" label:"Bucket" desc:"Bucket name" required:"true"`
	Org    string `json:"org" label:"Org" desc:"Organization name" required:"true"`
	Token  string `json:"token" label:"Token" desc:"Authentication token" required:"true" ref:"shared"`
	// Acquisition point array → SeriesPoint optional mapping (after configuring measurement, directly receive x/iotRead output)
	tsdb.AcquisitionMapping `json:",squash"`
}

// WriteNode receives msg.Data (JSON SeriesPoint array or line protocol text) and writes to InfluxDB.
type WriteNode struct {
	base.SharedNode[influxdb2.Client]
	Config         WriteConfig
	bucketTemplate el.Template
	orgTemplate    el.Template
}

func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: WriteConfig{
			URL:    "http://127.0.0.1:8086",
			Bucket: "bucket0",
			Org:    "org0",
		},
	}
}

func (x *WriteNode) Type() string {
	return "x/influxdbWrite"
}

func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	x.bucketTemplate, _ = el.NewTemplate(x.Config.Bucket)
	x.orgTemplate, _ = el.NewTemplate(x.Config.Org)
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.URL, ruleConfig.NodeClientInitNow, func() (influxdb2.Client, error) {
		return influxdb2.NewClient(x.Config.URL, x.Config.Token), nil
	}, func(client influxdb2.Client) error {
		client.Close()
		return nil
	})
	return nil
}

func (x *WriteNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	bucket := x.Config.Bucket
	org := x.Config.Org
	env := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	if x.bucketTemplate.HasVar() || x.orgTemplate.HasVar() {
		bucket = x.bucketTemplate.ExecuteAsString(env)
		org = x.orgTemplate.ExecuteAsString(env)
	}
	if mapped, ok := x.Config.MapData(msg.GetData(), env); ok {
		msg.SetDataType(types.JSON)
		msg.SetData(mapped)
	}
	points, err := tsdb.ParsePoints(msg.GetData(), msg.DataType == types.JSON)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	if err = newDriver(client, org, bucket).WritePoints(ctx.GetContext(), bucket, points); err != nil {
		ctx.TellFailure(msg, err)
	} else {
		ctx.TellSuccess(msg)
	}
}

func (x *WriteNode) GetInstance() (interface{}, error) {
	return x.SharedNode.GetInstance()
}

func (x *WriteNode) Destroy() {
	_ = x.SharedNode.Close()
}

func (x *WriteNode) Desc() string {
	return "InfluxDB client for writing time-series data. Routes to Success/Failure"
}
