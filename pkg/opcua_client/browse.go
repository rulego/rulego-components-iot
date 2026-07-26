package opcuaClient

import (
	"context"
	"fmt"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
)

// BrowseNode 地址空间浏览结果节点
type BrowseNode struct {
	NodeID    string       `json:"nodeId"`
	Name      string       `json:"name"`
	NodeClass string       `json:"nodeClass"`
	Children  []BrowseNode `json:"children,omitempty"`
}

const (
	// defaultBrowseNodeID 默认浏览起始节点（Objects 文件夹）
	defaultBrowseNodeID = "i=85"
	// defaultBrowseDepth 默认浏览深度
	defaultBrowseDepth = 2
	// maxBrowseNodes 单次浏览返回的节点总数上限
	maxBrowseNodes = 500
	// idHierarchicalReferences OPC UA 标准层级引用类型 NodeId
	idHierarchicalReferences = 33
	// browseResultMask 只请求消费的属性(NodeClass/BrowseName/DisplayName)
	browseResultMask = ua.BrowseResultMaskNodeClass | ua.BrowseResultMaskBrowseName | ua.BrowseResultMaskDisplayName
)

// Browse 递归浏览 OPC UA 地址空间，返回节点树（nodeID 空=Objects，depth<=0=默认 2 层）
func Browse(ctx context.Context, client *opcua.Client, nodeID string, depth int) ([]BrowseNode, error) {
	if nodeID == "" {
		nodeID = defaultBrowseNodeID
	}
	if depth <= 0 {
		depth = defaultBrowseDepth
	}
	id, err := ua.ParseNodeID(nodeID)
	if err != nil {
		return nil, err
	}
	count := 0
	return browseLevel(ctx, client, id, depth, &count)
}

// browseLevel 浏览单层节点(自动翻页消费 ContinuationPoint)，按剩余深度递归子节点
func browseLevel(ctx context.Context, client *opcua.Client, id *ua.NodeID, depth int, count *int) ([]BrowseNode, error) {
	req := &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          id,
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, idHierarchicalReferences),
			ResultMask:      uint32(browseResultMask),
		}},
	}
	resp, err := client.Browse(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.Results) == 0 {
		return nil, nil
	}
	result := resp.Results[0]
	if result.StatusCode != ua.StatusOK {
		return nil, fmt.Errorf("browse node %s failed: %s", id.String(), result.StatusCode)
	}
	var nodes []BrowseNode
	refs := result.References
	cp := result.ContinuationPoint
	for {
		for _, ref := range refs {
			if ref == nil || ref.NodeID == nil || ref.NodeID.NodeID == nil {
				continue
			}
			if *count >= maxBrowseNodes {
				releaseContinuationPoint(ctx, client, cp)
				return nodes, nil
			}
			*count++
			name := ""
			if ref.DisplayName != nil {
				name = ref.DisplayName.Text
			}
			if name == "" && ref.BrowseName != nil {
				name = ref.BrowseName.Name
			}
			node := BrowseNode{
				NodeID:    ref.NodeID.NodeID.String(),
				Name:      name,
				NodeClass: ref.NodeClass.String(),
			}
			if depth > 1 {
				if children, err := browseLevel(ctx, client, ref.NodeID.NodeID, depth-1, count); err == nil {
					node.Children = children
				}
			}
			nodes = append(nodes, node)
		}
		if len(cp) == 0 {
			break
		}
		// 取下一页
		nextResp, err := client.BrowseNext(ctx, &ua.BrowseNextRequest{ContinuationPoints: [][]byte{cp}})
		if err != nil || len(nextResp.Results) == 0 || nextResp.Results[0].StatusCode != ua.StatusOK {
			break
		}
		refs = nextResp.Results[0].References
		cp = nextResp.Results[0].ContinuationPoint
	}
	return nodes, nil
}

// releaseContinuationPoint 释放未消费完的分页上下文
func releaseContinuationPoint(ctx context.Context, client *opcua.Client, cp []byte) {
	if len(cp) == 0 {
		return
	}
	_, _ = client.BrowseNext(ctx, &ua.BrowseNextRequest{
		ReleaseContinuationPoints: true,
		ContinuationPoints:        [][]byte{cp},
	})
}
