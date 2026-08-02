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

package promremote

import (

	"github.com/castai/promwrite"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/tsdb"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
)

func init() {
	_ = rulego.Registry.Register(&WriteNode{})
}

// WriteConfig PromRemote write connection configuration.
type WriteConfig struct {
	URL string `json:"url" label:"URL" desc:"Prometheus Remote Write endpoint URL (e.g., http://localhost:9090/api/v1/write)" required:"true" ref:"primary"`
	// Acquisition point array → SeriesPoint optional mapping (after configuring measurement, directly receive x/iotRead output)
	tsdb.AcquisitionMapping `json:",squash"`
}

// WriteNode receives msg.Data (JSON SeriesPoint array or line protocol text) and writes to Prometheus Remote Write (supports Prometheus, VictoriaMetrics, QuestDB).
type WriteNode struct {
	base.SharedNode[*promwrite.Client]
	Config WriteConfig
	logger types.Logger
}

func (x *WriteNode) New() types.Node {
	return &WriteNode{
		Config: WriteConfig{
			URL: "http://localhost:9090/api/v1/write",
		},
	}
}

func (x *WriteNode) Type() string {
	return "x/promremoteWrite"
}

func (x *WriteNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	if err := maps.Map2Struct(configuration, &x.Config); err != nil {
		return err
	}
	x.logger = ruleConfig.Logger
	_ = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.URL, ruleConfig.NodeClientInitNow, func() (*promwrite.Client, error) {
		client := promwrite.NewClient(x.Config.URL)
		return client, nil
	}, func(client *promwrite.Client) error {
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
	if mapped, ok := x.Config.MapData(msg.GetData(), base.NodeUtils.GetEvnAndMetadata(ctx, msg)); ok {
		msg.SetDataType(types.JSON)
		msg.SetData(mapped)
	}
	points, err := tsdb.ParsePoints(msg.GetData(), msg.DataType == types.JSON)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}
	if err = newDriver(client, x.logger).WritePoints(ctx.GetContext(), "", points); err != nil {
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
	return "Prometheus Remote Write client (supports Prometheus, VictoriaMetrics, QuestDB). Routes to Success/Failure"
}
