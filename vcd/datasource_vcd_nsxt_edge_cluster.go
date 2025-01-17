package vcd

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func datasourceVcdNsxtEdgeCluster() *schema.Resource {
	return &schema.Resource{
		ReadContext: datasourceNsxtEdgeCluster,
		Schema: map[string]*schema.Schema{
			"org": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The name of organization to use, optional if defined at provider " +
					"level. Useful when connected as sysadmin working across different organizations",
			},
			"vdc": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of VDC to use, optional if defined at provider level",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of NSX-T Edge Cluster",
			},
			"description": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Description of NSX-T Edge Cluster",
			},
			"node_count": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Number of nodes in NSX-T Edge Cluster",
			},
			"node_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Node type of NSX-T Edge Cluster",
			},
			"deployment_type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Deployment type of NSX-T Edge Cluster",
			},
		},
	}
}

func datasourceNsxtEdgeCluster(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	vcdClient := meta.(*VCDClient)
	nsxtEdgeClusterName := d.Get("name").(string)

	_, vdc, err := vcdClient.GetOrgAndVdcFromResource(d)
	if err != nil {
		return diag.Errorf(errorRetrievingOrgAndVdc, err)
	}

	nsxtEdgeCluster, err := vdc.GetNsxtEdgeClusterByName(nsxtEdgeClusterName)
	if err != nil {
		return diag.Errorf("could not find NSX-T Edge Cluster by name '%s': %s", nsxtEdgeClusterName, err)
	}

	dSet(d, "description", nsxtEdgeCluster.NsxtEdgeCluster.Description)
	dSet(d, "node_count", nsxtEdgeCluster.NsxtEdgeCluster.NodeCount)
	dSet(d, "node_type", nsxtEdgeCluster.NsxtEdgeCluster.NodeType)
	dSet(d, "deployment_type", nsxtEdgeCluster.NsxtEdgeCluster.DeploymentType)

	d.SetId(nsxtEdgeCluster.NsxtEdgeCluster.ID)

	return nil
}
