package licensing

import (
	"github.com/grafana/grafana/pkg/api/dtos"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/hooks"
	"github.com/grafana/grafana/pkg/services/navtree"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	openSource = "Open Source"
)

type OSSLicensingService struct {
	Cfg          *setting.Cfg
	HooksService *hooks.HooksService
}

func (*OSSLicensingService) Expiry() int64 {
	return 0
}

func (*OSSLicensingService) Edition() string {
	return openSource
}

func (*OSSLicensingService) StateInfo() string {
	return ""
}

func (*OSSLicensingService) ContentDeliveryPrefix() string {
	return "grafana-oss"
}

func (l *OSSLicensingService) LicenseURL(showAdminLicensingPage bool) string {
	if showAdminLicensingPage {
		return l.Cfg.AppSubURL + "/admin/upgrading"
	}

	return "https://grafana.com/oss/grafana?utm_source=grafana_footer"
}

// Fork: per-datasource permissions are enforced, so Viewers no longer get query access to every datasource;
// "accesscontrol" turns on the role pickers in the users, teams and service accounts UI (backed by customroles).
var ossEnabledFeatures = map[string]bool{"dspermissions.enforcement": true, "accesscontrol": true}

func (*OSSLicensingService) EnabledFeatures() map[string]bool {
	return ossEnabledFeatures
}

func (*OSSLicensingService) FeatureEnabled(feature string) bool {
	return ossEnabledFeatures[feature]
}

func ProvideService(cfg *setting.Cfg, hooksService *hooks.HooksService) *OSSLicensingService {
	l := &OSSLicensingService{
		Cfg:          cfg,
		HooksService: hooksService,
	}
	l.HooksService.AddIndexDataHook(func(indexData *dtos.IndexViewData, req *contextmodel.ReqContext) {
		if !req.IsGrafanaAdmin {
			return
		}

		if adminNode := indexData.NavTree.FindById(navtree.NavIDCfgGeneral); adminNode != nil {
			adminNode.Children = append(adminNode.Children, &navtree.NavLink{
				Text:       "Stats",
				Id:         "upgrading",
				Url:        l.LicenseURL(req.IsGrafanaAdmin),
				Icon:       "unlock",
				SortWeight: -1,
			})
		}
	})

	return l
}
