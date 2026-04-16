package libiamlive

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/clbanning/mxj/v2"
)

//go:embed iam_definition.json
var bIAMSAR []byte

//go:embed map.json
var bIAMMap []byte

type ServiceStructure struct {
	Required     []string                    `json:"required"`
	Shape        string                      `json:"shape"`
	Type         string                      `json:"type"`
	Member       *ServiceStructure           `json:"member"`
	Members      map[string]ServiceStructure `json:"members"`
	LocationName string                      `json:"locationName"`
	QueryName    string                      `json:"queryName"`
	Streaming    bool                        `json:"streaming"`
}

type ServiceDefinitionMetadata struct {
	APIVersion          string `json:"apiVersion"`
	EndpointPrefix      string `json:"endpointPrefix"`
	JSONVersion         string `json:"jsonVersion"`
	Protocol            string `json:"protocol"`
	ServiceFullName     string `json:"serviceFullName"`
	ServiceAbbreviation string `json:"serviceAbbreviation"`
	ServiceID           string `json:"serviceId"`
	SignatureVersion    string `json:"signatureVersion"`
	TargetPrefix        string `json:"targetPrefix"`
	UID                 string `json:"uid"`
}

type ServiceHttp struct {
	Method       string `json:"method"`
	RequestURI   string `json:"requestUri"`
	ResponseCode int    `json:"responseCode"`
}

type ServiceOperation struct {
	Http   ServiceHttp      `json:"http"`
	Input  ServiceStructure `json:"input"`
	Output ServiceStructure `json:"output"`
}

type ServiceDefinition struct {
	Version    string                      `json:"version"`
	Metadata   ServiceDefinitionMetadata   `json:"metadata"`
	Operations map[string]ServiceOperation `json:"operations"`
	Shapes     map[string]ServiceStructure `json:"shapes"`
}

type ActionCandidate struct {
	Path      string
	Action    string
	URIParams map[string]string
	Params    map[string][]string
	Operation ServiceOperation
	Service   string
}

// Entry is a single CSM entry
type Entry struct {
	Region              string `json:"Region"`
	Type                string `json:"Type"`
	Service             string `json:"Service"`
	Method              string `json:"Api"`
	Parameters          map[string][]string
	URIParameters       map[string]string
	FinalHTTPStatusCode int    `json:"FinalHttpStatusCode"`
	AccessKey           string `json:"AccessKey"`
	SessionToken        string `json:"SessionToken"`
	Host                string `json:"_Host"`
}

// Statement is a single statement within an IAM policy
type Statement struct {
	Effect   string      `json:"Effect"`
	Action   []string    `json:"Action"`
	Resource interface{} `json:"Resource"`
}

// IAMPolicy is a full IAM policy
type IAMPolicy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type iamMapArnOverride struct {
	Template string `json:"template"`
}

type iamMapResMapItem struct {
	Template string `json:"template"`
}

type iamMapMethod struct {
	Action              string                      `json:"action"`
	ResourceMappings    map[string]iamMapResMapItem `json:"resource_mappings"`
	ResourceARNMappings map[string]string           `json:"resourcearn_mappings"`
	ArnOverride         iamMapArnOverride           `json:"arn_override"`
}

type iamMapBase struct {
	SDKMethodIAMMappings     map[string][]iamMapMethod `json:"sdk_method_iam_mappings"`
	SDKServiceMappings       map[string]string         `json:"sdk_service_mappings"`
	SDKPermissionlessActions []string                  `json:"sdk_permissionless_actions"`
}

var iamMap iamMapBase

func resolveSpecials(arn string, call Entry, mandatory bool, resourceArnTemplate *string) []string {
	startIndex := strings.Index(arn, "%%")
	endIndex := strings.LastIndex(arn, "%%")

	if startIndex > -1 && endIndex != startIndex {
		parts := strings.Split(arn[startIndex+2:endIndex], "%")

		if len(parts) < 2 {
			return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
		}

		switch parts[0] {
		case "iftruthy":
			if len(parts) == 3 { // weird bug for empty string false values
				parts = append(parts, "")
			}

			if len(parts) != 4 {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}

			fullyResolved, arns := subARNParameters(parts[1], call, true)

			if len(arns) < 1 || arns[0] == "" || !fullyResolved {
				if parts[3] == "" {
					if mandatory {
						return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
					}
					return []string{arn[0:startIndex] + arn[endIndex+2:]}
				}
				return []string{arn[0:startIndex] + parts[3] + arn[endIndex+2:]}
			}

			if parts[2] == "" && mandatory {
				if mandatory {
					return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
				}
				return []string{arn[0:startIndex] + arn[endIndex+2:]}
			}
			return []string{arn[0:startIndex] + parts[2] + arn[endIndex+2:]}
		case "urlencode":
			if len(parts) != 2 {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}

			fullyResolved, arns := subARNParameters(parts[1], call, true)
			if len(arns) < 1 || arns[0] == "" || !fullyResolved {
				if mandatory {
					return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
				}
				return []string{arn[0:startIndex] + arn[endIndex+2:]}
			}

			return []string{arn[0:startIndex] + url.QueryEscape(arns[0]) + arn[endIndex+2:]}
		case "iftemplatematch":
			if len(parts) != 2 || resourceArnTemplate == nil {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}

			fullyResolved, arns := subARNParameters(parts[1], call, true)
			if len(arns) < 1 || arns[0] == "" || !fullyResolved {
				return []string{arn[0:startIndex] + arn[endIndex+2:]}
			}

			template := regexp.MustCompile(`\\\$\\\{.+?\\\}`).ReplaceAllString(regexp.QuoteMeta(*resourceArnTemplate), ".*?")

			if regexp.MustCompile(template).MatchString(arns[0]) {
				return []string{arn[0:startIndex] + arns[0] + arn[endIndex+2:]}
			}

			return []string{arn[0:startIndex] + arn[endIndex+2:]}
		case "many":
			manyParts := []string{}

			for _, part := range parts[1:] {
				fullyResolved, arns := subARNParameters(part, call, true)
				if len(arns) < 1 || arns[0] == "" || !fullyResolved {
					if mandatory {
						return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
					}
					return []string{arn[0:startIndex] + arn[endIndex+2:]}
				}

				manyParts = append(manyParts, arns[0])
			}

			return manyParts
		case "regex":
			if len(parts) != 3 {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}

			fullyResolved, arns := subARNParameters(parts[1], call, true)

			if len(arns) < 1 || arns[0] == "" || !fullyResolved {
				if mandatory {
					return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
				}
				return []string{arn[0:startIndex] + arn[endIndex+2:]}
			}

			if parts[2][0] == '/' {
				parts[2] = parts[2][1 : len(parts[2])-2]
			}

			r := regexp.MustCompile(parts[2])
			groups := r.FindStringSubmatch(strings.ReplaceAll(arns[0], `$`, `$$`))

			if len(groups) < 2 || groups[1] == "" {
				if mandatory {
					return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
				}
				return []string{arn[0:startIndex] + arn[endIndex+2:]}
			}

			return []string{arn[0:startIndex] + groups[1] + arn[endIndex+2:]}
		default: // unknown function
			return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
		}
	}

	return []string{arn}
}

type uniqueStringList struct {
	list []string
	set  map[string]bool
}

func newUniqueStringList() *uniqueStringList {
	return &uniqueStringList{set: map[string]bool{}}
}
func (s *uniqueStringList) add(newArn string) {
	if _, ok := s.set[newArn]; !ok {
		s.list = append(s.list, newArn)
		s.set[newArn] = true
	}
}
func (s *uniqueStringList) addParam(arns []string, paramVarName, param string) {
	for _, arn := range arns {
		newArn := regexp.MustCompile(`\$\{`+strings.ReplaceAll(strings.ReplaceAll(paramVarName, "[", "\\["), "]", "\\]")+`\}`).ReplaceAllString(arn, param)
		s.add(newArn)
	}
}

func subARNParameters(arn string, call Entry, specialsOnly bool) (bool, []string) {
	arns := []string{arn}
	// parameter substitution
	for paramVarName, params := range call.Parameters {
		newArns := newUniqueStringList()
		for _, param := range params {
			newArns.addParam(arns, paramVarName, param)
		}
		arns = newArns.list
	}

	// URI parameter substitution
	for paramVarName, param := range call.URIParameters {
		newArns := newUniqueStringList()
		newArns.addParam(arns, paramVarName, param)
		arns = newArns.list
	}

	if specialsOnly {
		anyMatched := false
		for _, arn := range arns {
			matched, _ := regexp.Match(`\$\{.+?\}`, []byte(arn))
			if matched {
				anyMatched = true
			}
		}

		return !anyMatched, arns
	}

	var account string

	region := call.Region

	partition := "aws"
	if strings.HasPrefix(region, "cn") {
		partition = "aws-cn"
	}
	if strings.HasPrefix(region, "us-gov") {
		partition = "aws-us-gov"
	}

	anyUnresolved := false
	result := []string{}
	for _, arn := range arns {
		arn = regexp.MustCompile(`\$\{Partition\}`).ReplaceAllString(arn, partition)
		arn = regexp.MustCompile(`\$\{Region\}`).ReplaceAllString(arn, region)
		arn = regexp.MustCompile(`\$\{Account\}`).ReplaceAllString(arn, account)
		unresolvedArn := arn
		arn = regexp.MustCompile(`\$\{.+?\}`).ReplaceAllString(arn, "*") // TODO: preserve ${aws:*} variables
		if unresolvedArn != arn {
			anyUnresolved = true
		}
		result = append(result, arn)
	}

	return !anyUnresolved, result
}

type iamDefResource struct {
	Resource string `json:"resource"`
	Arn      string `json:"arn"`
}

type iamDefResourceType struct {
	DependentActions []string `json:"dependent_actions"`
	ResourceType     string   `json:"resource_type"`
}

type iamDefService struct {
	Prefix     string            `json:"prefix"`
	Privileges []iamDefPrivilege `json:"privileges"`
	Resources  []iamDefResource  `json:"resources"`
}

type iamDefPrivilege struct {
	Privilege     string               `json:"privilege"`
	ResourceTypes []iamDefResourceType `json:"resource_types"`
	Description   string               `json:"description"`
}

var iamDef []iamDefService

//go:embed apis/*
var serviceFiles embed.FS

func init() {
	if err := json.Unmarshal(bIAMSAR, &iamDef); err != nil {
		panic(err)
	}

	if err := json.Unmarshal(bIAMMap, &iamMap); err != nil {
		panic(err)
	}

	serviceDirs, err := serviceFiles.ReadDir("apis")
	if err != nil {
		panic(err)
	}

	for _, serviceEntry := range serviceDirs {
		versionDirs, err := serviceFiles.ReadDir("apis/" + serviceEntry.Name())
		if err != nil {
			panic(err)
		}

		latestDir := ""
		for _, versionEntry := range versionDirs {
			if latestDir == "" || versionEntry.Name() > latestDir {
				latestDir = versionEntry.Name()
			}
		}

		file, err := serviceFiles.Open("apis/" + serviceEntry.Name() + "/" + latestDir + "/api-2.json")
		if err != nil {
			panic(err)
		}

		data, err := io.ReadAll(file)
		if err != nil {
			panic(err)
		}

		var def ServiceDefinition
		if json.Unmarshal(data, &def) != nil {
			panic(err)
		}

		serviceDefinitions = append(serviceDefinitions, def)
	}
}

func getStatementsForProxyCall(call Entry) (statements []Statement) {
	lowerPriv := strings.ToLower(fmt.Sprintf("%s.%s", call.Service, call.Method))

	for iamMapMethodName, iamMapMethods := range iamMap.SDKMethodIAMMappings {
		if strings.ToLower(iamMapMethodName) == lowerPriv {
			for mappedPrivIndex, mappedPriv := range iamMapMethods {
				// special handling for S3 express
				if strings.HasPrefix(mappedPriv.Action, "s3express:") && len(iamMapMethods) > 1 && !strings.HasPrefix(call.Host, "s3express-control.") {
					continue
				}
				if strings.HasPrefix(mappedPriv.Action, "s3:") && len(iamMapMethods) > 1 && strings.HasPrefix(call.Host, "s3express-control.") {
					continue
				}
				if strings.HasPrefix(mappedPriv.Action, "s3:") && strings.Contains(call.Host, ".s3express-") {
					continue // Zonal API actions
				}

				resources := []string{}

				// arn_override
				if mappedPriv.ArnOverride.Template != "" {
					arns := resolveSpecials(mappedPriv.ArnOverride.Template, call, false, nil)

					if len(arns) == 0 || len(arns) > 1 || arns[0] != "" { // skip if empty after resolving specials
						for _, arn := range arns {
							fullyResolved, subbedArns := subARNParameters(arn, call, false)
							for _, subbedArn := range subbedArns {
								if mappedPrivIndex == 0 || fullyResolved {
									resources = append(resources, subbedArn) // sub full parameters and add to resources
								}
							}
						}
					}

					if len(resources) == 0 && len(mappedPriv.ResourceMappings) == 0 {
						continue
					}
				}

				// resourcearn_mappings
				if len(mappedPriv.ResourceARNMappings) > 0 {
					for _, service := range iamDef { // in the SAR
						if service.Prefix == strings.ToLower(strings.Split(mappedPriv.Action, ":")[0]) { // find the service for the call
							for _, servicePrivilege := range service.Privileges {
								if strings.ToLower(strings.Split(mappedPriv.Action, ":")[1]) == strings.ToLower(servicePrivilege.Privilege) { // find the method for the call
									for _, resourceType := range servicePrivilege.ResourceTypes { // get all resource types for the privilege
										resourceArnTemplate := ""
										for _, resource := range service.Resources { // go through the service resources
											if resource.Resource == strings.Replace(resourceType.ResourceType, "*", "", -1) && resource.Resource != "" { // match the resource type (doesn't matter if mandatory)
												resourceArnTemplate = resource.Arn
											}
										}
										for mapResType, mapResTemplate := range mappedPriv.ResourceARNMappings {
											if strings.Replace(resourceType.ResourceType, "*", "", -1) == mapResType {
												mandatory := strings.HasSuffix(resourceType.ResourceType, "*")

												resARNMappingTemplates := resolveSpecials(mapResTemplate, call, false, &resourceArnTemplate)
												if len(resARNMappingTemplates) == 1 && resARNMappingTemplates[0] == "" {
													continue
												}

												if len(resARNMappingTemplates) == 0 && mandatory && len(mappedPriv.ResourceMappings) == 0 {
													resARNMappingTemplates = []string{"*"}
												}

												for _, resARNMappingTemplate := range resARNMappingTemplates {
													fullyResolved, subbedArns := subARNParameters(resARNMappingTemplate, call, false)
													if mandatory || fullyResolved { // check if mandatory or fully resolved
														resources = append(resources, subbedArns...) // sub full parameters and add to resources
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

				// resource_mappings
				if len(resources) == 0 {
					for _, service := range iamDef { // in the SAR
						if service.Prefix == strings.ToLower(strings.Split(mappedPriv.Action, ":")[0]) { // find the service for the call
							for _, servicePrivilege := range service.Privileges {
								if strings.ToLower(strings.Split(mappedPriv.Action, ":")[1]) == strings.ToLower(servicePrivilege.Privilege) { // find the method for the call
									for _, resourceType := range servicePrivilege.ResourceTypes { // get all resource types for the privilege
										for _, resource := range service.Resources { // go through the service resources
											if resource.Resource == strings.Replace(resourceType.ResourceType, "*", "", -1) && resource.Resource != "" { // match the resource type (doesn't matter if mandatory)
												arns := []string{resource.Arn} // the base ARN template, matrix init
												newArns := []string{}
												mandatory := strings.HasSuffix(resourceType.ResourceType, "*")

												// substitute the resource_mappings
												for resMappingVar, resMapping := range mappedPriv.ResourceMappings { // for each mapping
													resMappingTemplates := resolveSpecials(resMapping.Template, call, false, &resource.Arn) // get a list of resolved template strings

													if len(resMappingTemplates) == 1 && resMappingTemplates[0] == "" {
														continue
													}

													for _, arn := range arns { // for each of the arn list
														newArns = []string{}

														for _, resMappingTemplate := range resMappingTemplates {
															variableReplaced := regexp.MustCompile(`\$\{`+resMappingVar+`\}`).ReplaceAllString(arn, strings.ReplaceAll(resMappingTemplate, `$`, `$$`)) // escape $ for regexp
															newArns = append(newArns, variableReplaced)
														}
													}
													arns = newArns
												}

												if len(arns) == 0 && mandatory {
													arns = []string{"*"}
												}

												for _, arn := range arns {
													fullyResolved, subbedArns := subARNParameters(arn, call, false)
													if mandatory || fullyResolved { // check if mandatory or fully resolved
														resources = append(resources, subbedArns...) // sub full parameters and add to resources
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

				// default (last ditch)
				if len(resources) == 0 {
					if len(mappedPriv.ResourceARNMappings) > 0 { // skip if resourcearn_mapping was specified and didn't hit
						continue
					}
					resources = []string{"*"}
				}

				statements = append(statements, Statement{
					Effect:   "Allow",
					Resource: resources,
					Action:   []string{mappedPriv.Action},
				})
			}
		}
	}

	return statements
}

func uniqueSlice(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func removeStatementItem(slice []Statement, i int) []Statement {
	copy(slice[i:], slice[i+1:])
	return slice[:len(slice)-1]
}

func aggregatePolicy(policy IAMPolicy) IAMPolicy {
	for i := 0; i < len(policy.Statement); i++ {
		sort.Strings(policy.Statement[i].Resource.([]string))
		for j := i + 1; j < len(policy.Statement); j++ {
			sort.Strings(policy.Statement[j].Resource.([]string))

			if reflect.DeepEqual(policy.Statement[i].Resource.([]string), policy.Statement[j].Resource.([]string)) {
				policy.Statement[i].Action = append(policy.Statement[i].Action, policy.Statement[j].Action...) // combine
				policy.Statement = removeStatementItem(policy.Statement, j)                                    // remove dupe
				j--
			}
		}

		actions := uniqueSlice(policy.Statement[i].Action)

		policy.Statement[i].Action = actions
		policy.Statement[i].Resource = uniqueSlice(policy.Statement[i].Resource.([]string))
	}

	return policy
}

func GetPolicyDocument(callLog []Entry) ([]byte, error) {
	policy := IAMPolicy{
		Version:   "2012-10-17",
		Statement: []Statement{},
	}

	for _, entry := range callLog {
		policy.Statement = append(policy.Statement, getStatementsForProxyCall(entry)...)
	}

	policy = aggregatePolicy(policy)

	for i := 0; i < len(policy.Statement); i++ { // make any single wildcard resource a non-array
		resource := policy.Statement[i].Resource.([]string)
		if len(resource) == 1 {
			policy.Statement[i].Resource = resource[0]
		}
	}

	return json.MarshalIndent(policy, "", "    ")
}

func flatten(top bool, flatMap map[string][]string, nested interface{}, prefix string) error {
	assign := func(newKey string, v interface{}) error {
		switch v.(type) {
		case map[string]interface{}, []interface{}:
			if err := flatten(false, flatMap, v, newKey); err != nil {
				return err
			}
		default:
			flatMap[newKey] = append(flatMap[newKey], fmt.Sprintf("%v", v))
		}

		return nil
	}

	switch nested.(type) {
	case map[string]interface{}:
		for k, v := range nested.(map[string]interface{}) {
			if top {
				assign(k, v)
			} else {
				assign(prefix+"."+k, v)
			}
		}
	case []interface{}:
		for _, v := range nested.([]interface{}) {
			assign(prefix+"[]", v)
		}
	default:
		return fmt.Errorf("invalid object type")
	}

	return nil
}

var serviceDefinitions []ServiceDefinition

func resolvePropertyName(obj ServiceStructure, searchProp string, path string, locationPath string, shapes map[string]ServiceStructure) (ret string) {
	if searchProp[len(searchProp)-2:] == "[]" { // trim trailing []
		searchProp = searchProp[:len(searchProp)-2]
	}

	if obj.Shape != "" {
		locationName := obj.LocationName
		queryName := obj.QueryName
		obj = shapes[obj.Shape]
		obj.LocationName = locationName
		obj.QueryName = queryName
	}

	switch obj.Type { // TODO: Exhaustive check for other types
	case "boolean", "timestamp", "blob", "map":
		return ""
	case "structure":
		for k, v := range obj.Members {
			newPath := fmt.Sprintf("%s.%s", path, k)
			if path == "" {
				newPath = k
			}

			newLocationPath := locationPath + "." + k
			if v.QueryName != "" {
				newLocationPath = locationPath + "." + v.QueryName
			} else if v.LocationName != "" {
				newLocationPath = locationPath + "." + v.LocationName
			}

			ret = resolvePropertyName(v, searchProp, newPath, newLocationPath, shapes)
			if ret != "" {
				return ret
			}
		}
	case "long", "float", "integer", "", "string":
		if len(locationPath) > 2 && locationPath[len(locationPath)-2:] == "[]" { // trim trailing []
			locationPath = locationPath[:len(locationPath)-2]
		}
		if len(locationPath) > 0 && locationPath[0] == '.' { // trim leading .
			locationPath = locationPath[1:]
		}

		if strings.ToLower(locationPath) == strings.ToLower(searchProp) {
			return path
		}
	case "list":
		newPath := fmt.Sprintf("%s[]", path)
		newLocationPath := fmt.Sprintf("%s[]", locationPath)

		if strings.Count(newLocationPath, ".") > 10 { // prevent infinite recursion
			return ""
		}

		ret = resolvePropertyName(*obj.Member, searchProp, newPath, newLocationPath, shapes)
		if ret != "" {
			return ret
		}
	}

	return ""
}

func Parse(req *http.Request, body []byte, respCode int, entry *Entry) error {
	host := req.Host
	host = strings.TrimSuffix(host, ".cn")
	uri := req.URL.RequestURI()

	var endpointUriPrefix string
	var service string

	var serviceDef ServiceDefinition
	endpointPrefix, _, _ := strings.Cut(host, ".")

	uriparams := make(map[string]string)
	params := make(map[string][]string)
	action := ""
	actionMatch := false
	var selectedCandidate ActionCandidate

	for _, serviceDefinition := range serviceDefinitions {
		if serviceDefinition.Metadata.EndpointPrefix == endpointPrefix { // TODO: Ensure latest version
			serviceDef = serviceDefinition

			// Doc: https://github.com/aws/aws-sdk-js/blob/54f8555bd94d33a1754a44a35286f1d9e31c28a3/lib/model/api.js#L41
			service = serviceDef.Metadata.ServiceAbbreviation
			if service == "" {
				service = serviceDef.Metadata.ServiceFullName
			}
			service = regexp.MustCompile(`(^Amazon|AWS\s*|\(.*|\s+|\W+)`).ReplaceAllString(service, "")
			if service == "ElasticLoadBalancing" || service == "ElasticLoadBalancingv2" {
				service = "ELB"
			}
			if service == "CognitoIdentityProvider" {
				service = "CognitoIdentityServiceProvider"
			}
			if service == "AgentsforAmazonBedrockRuntime" {
				service = "BedrockAgentRuntime"
			}

			if serviceDef.Metadata.Protocol == "json" {
				// JSON schema
				var bodyJSON interface{}
				err := json.Unmarshal(body, &bodyJSON)

				if err == nil {
					amzTargetHeader := req.Header.Get("X-Amz-Target")
					if amzTargetHeader != "" {
						action = strings.Split(amzTargetHeader, ".")[1]
						flatten(true, params, bodyJSON, "")
					} else {
						return errors.New("no X-Amz-Target header")
					}
				} else {
					return fmt.Errorf("failed to unmarshal json body: %w", err)
				}
			} else if serviceDef.Metadata.Protocol == "ec2" || serviceDef.Metadata.Protocol == "query" {
				// URL param schema in body
				vals, err := url.ParseQuery(string(body))
				if err != nil {
					return fmt.Errorf("failed to parse query: %w", err)
				}

				if len(vals["Action"]) != 1 || len(vals["Version"]) != 1 {
					return errors.New("missing Action or Version")
				}
				action = vals["Action"][0]
				if service == "ELB" && vals["Version"][0] != "2012-06-01" { // exception
					service = "ELBv2"
					for _, serviceDefinition := range serviceDefinitions {
						if serviceDefinition.Metadata.ServiceAbbreviation == "Elastic Load Balancing v2" {
							serviceDef = serviceDefinition
						}
					}
				}

				if serviceDef.Operations[action].Input.Type == "structure" {
					for k, v := range vals {
						if k != "Action" && k != "Version" {
							normalizedK := regexp.MustCompile(`\.member\.[0-9]+`).ReplaceAllString(k, "[]")
							normalizedK = regexp.MustCompile(`\.[0-9]+`).ReplaceAllString(normalizedK, "[]")

							resolvedPropertyName := resolvePropertyName(serviceDef.Operations[action].Input, normalizedK, "", "", serviceDef.Shapes)
							if resolvedPropertyName != "" {
								normalizedK = resolvedPropertyName
							}

							if len(params[normalizedK]) > 0 {
								params[normalizedK] = append(params[normalizedK], v...)
							} else {
								params[normalizedK] = v
							}
						}
					}
				}
			} else if serviceDef.Metadata.Protocol == "rest-json" || serviceDef.Metadata.Protocol == "rest-xml" {
				// URL param schema
				urlobj, err := url.ParseRequestURI(uri)
				if err != nil {
					return fmt.Errorf("failed to parse uri: %w", err)
				}
				vals := urlobj.Query()

				actionCandidates := []ActionCandidate{}

				// path part
			OperationLoop:
				for operationName, operation := range serviceDef.Operations {
					path := urlobj.Path
					if serviceDef.Metadata.EndpointPrefix == "s3" && strings.HasPrefix(operation.Http.RequestURI, "/{Bucket}") && endpointUriPrefix != "" { // https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html#VirtualHostingSpecifyBucket
						if len(urlobj.Path) > 1 {
							path = "/" + endpointUriPrefix + "/" + urlobj.Path[1:]
						} else {
							path = "/" + endpointUriPrefix
						}
					}
					if operation.Http.RequestURI == "" || operation.Http.RequestURI[0] != '/' {
						operation.Http.RequestURI = "/" + operation.Http.RequestURI
					}

					if strings.Contains(operation.Http.RequestURI, "?") {
						path += "?"

						operationurlobj, err := url.ParseRequestURI(operation.Http.RequestURI)
						if err != nil {
							continue
						}

						operationquery := operationurlobj.Query()
						for operationquerykey, operationqueryvalue := range operationquery {
							if _, ok := vals[operationquerykey]; ok {
								if operationqueryvalue[0] == "" {
									path += operationquerykey + "&"
								} else if len(vals[operationquerykey]) > 0 {
									path += operationquerykey + "=" + vals[operationquerykey][0] + "&"
								} else {
									continue OperationLoop
								}
							} else {
								continue OperationLoop
							}
						}

						if path[len(path)-1] == '&' {
							path = path[:len(path)-1]
						}
					}

					templateMatches := regexp.MustCompile(`{([^}]+?)\+?}`).FindAllStringSubmatch(operation.Http.RequestURI, -1)
					regexStr := regexp.MustCompile(`\\{([^}]+?\\\+)\\}`).ReplaceAllString(regexp.QuoteMeta(operation.Http.RequestURI), `([^?]+)`) // {Key+}
					regexStr = fmt.Sprintf("^%s$", regexp.MustCompile(`\\{(.+?)\\}`).ReplaceAllString(regexStr, `([^/?]+?)`))                     // {Bucket}
					pathMatchSuccess := regexp.MustCompile(regexStr).Match([]byte(path))

					if operation.Http.Method == "" {
						operation.Http.Method = "POST"
					}

					if operation.Http.Method == req.Method && pathMatchSuccess {
						action = operationName
						uriparams = map[string]string{}

						pathMatches := regexp.MustCompile(regexStr).FindAllStringSubmatch(path, -1)

						if len(pathMatches) > 0 && len(templateMatches) > 0 && len(templateMatches) == len(pathMatches[0])-1 {
							for i := 0; i < len(templateMatches); i++ {
								uriparams[templateMatches[i][1]] = pathMatches[0][1:][i]
							}
						}

						// query part
						for k, v := range vals {
							normalizedK := regexp.MustCompile(`\.member\.[0-9]+`).ReplaceAllString(k, "[]")
							normalizedK = regexp.MustCompile(`\.[0-9]+`).ReplaceAllString(normalizedK, "[]")

							resolvedPropertyName := resolvePropertyName(serviceDef.Operations[action].Input, normalizedK, "", "", serviceDef.Shapes)
							if resolvedPropertyName != "" {
								normalizedK = resolvedPropertyName
							} else {
								// continue // Skipping just in case
							}

							if len(params[normalizedK]) > 0 {
								params[normalizedK] = append(params[normalizedK], v...)
							} else {
								params[normalizedK] = v
							}
						}

						// header part
						for k, v := range req.Header {
							resolvedPropertyName := resolvePropertyName(serviceDef.Operations[action].Input, k, "", "", serviceDef.Shapes)
							if resolvedPropertyName != "" {
								k = resolvedPropertyName
							} else {
								continue
							}

							if len(params[k]) > 0 {
								params[k] = append(params[k], v...)
							} else {
								params[k] = v
							}
						}

						// body part
						if len(body) > 0 {
							inputDef := serviceDef.Shapes[serviceDef.Operations[action].Input.Shape]

							if bodyDef, ok := inputDef.Members["Body"]; ok && !bodyDef.Streaming {
								if serviceDef.Metadata.Protocol == "rest-json" {
									var bodyJSON interface{}
									err := json.Unmarshal(body, &bodyJSON)
									if err != nil {
										return fmt.Errorf("failed to unmarshal rest-json response: %w", err)
									}
									flatten(true, params, bodyJSON, "")
								} else if serviceDef.Metadata.Protocol == "rest-xml" {
									mxjXML, err := mxj.NewMapXml(body)
									bodyXML := map[string]interface{}(mxjXML)
									if err != nil {
										return fmt.Errorf("failed to unmarshal rest-xml response: %w", err)
									}
									flatten(true, params, bodyXML, "")
								} else {
									return fmt.Errorf("unknown protocol: %q", serviceDef.Metadata.Protocol)
								}
							}
						}

						actionCandidates = append(actionCandidates, ActionCandidate{
							Path:      path,
							Action:    action,
							Params:    params,
							URIParams: uriparams,
							Operation: operation,
							Service:   service,
						})
					}
				}

				// select candidate
				var selectedActionCandidate ActionCandidate
			ActionCandidateLoop:
				for _, actionCandidate := range actionCandidates {
				RequiredParamLoop:
					for _, requiredParam := range actionCandidate.Operation.Input.Required { // check input requirements
						for k := range actionCandidate.Params {
							if k == requiredParam || (len(k) >= len(requiredParam)+2 && k[:len(requiredParam)+2] == requiredParam+"[]") || (len(k) >= len(requiredParam)+1 && k[:len(requiredParam)+1] == requiredParam+".") { // equals, or is array, or is map
								continue RequiredParamLoop
							}
						}
						for k := range actionCandidate.URIParams {
							if k == requiredParam || (len(k) >= len(requiredParam)+2 && k[:len(requiredParam)+2] == requiredParam+"[]") || (len(k) >= len(requiredParam)+1 && k[:len(requiredParam)+1] == requiredParam+".") { // equals, or is array, or is map
								continue RequiredParamLoop
							}
						}
						continue ActionCandidateLoop // requirements not met
					}
					if selectedActionCandidate.Action == "" { // first one
						selectedActionCandidate = actionCandidate
						continue
					}
					if len(actionCandidate.Path) > len(selectedActionCandidate.Path) { // longer path wins
						selectedActionCandidate = actionCandidate
						continue
					}
					if len(actionCandidate.Operation.Input.Required) > len(selectedActionCandidate.Operation.Input.Required) { // more requirements wins
						selectedActionCandidate = actionCandidate
						continue
					}
				}

				if !actionMatch && selectedActionCandidate.Action != "" {
					selectedCandidate = selectedActionCandidate
					actionMatch = true
				}
			}
		}
	}

	if action == "" {
		return errors.New("no action")
	}
	if service == "" {
		return errors.New("no service")
	}

	region := "us-east-1"
	re, _ := regexp.Compile(`\.([^.]+)\.amazonaws\.com(?:\.cn)?$`)
	matches := re.FindStringSubmatch(host)
	if len(matches) == 2 {
		if matches[1] != "s3" { // https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html#VirtualHostingBackwardsCompatibility
			region = matches[1]
		}
	}

	// attempt to determine access key and/or session token from auth header
	accessKey := ""
	sessionToken := ""
	authHeader := req.Header.Get("Authorization")
	credOffset := strings.Index(authHeader, "Credential=")
	if credOffset > 0 {
		endOfKey := strings.Index(authHeader[credOffset:], "/")
		if endOfKey > 0 {
			accessKey = authHeader[credOffset+len("Credential=") : credOffset+endOfKey]
		}
	}

	sessionTokenHeader := req.Header.Get("X-Amz-Security-Token")
	sessionTokenQuery := req.URL.Query().Get("X-Amz-Security-Token")
	if sessionTokenHeader != "" {
		sessionToken = sessionTokenHeader
	} else if sessionTokenQuery != "" {
		sessionToken = sessionTokenQuery
	}

	if selectedCandidate.Action != "" {
		action = selectedCandidate.Action
		params = selectedCandidate.Params
		uriparams = selectedCandidate.URIParams
		service = selectedCandidate.Service
	}

	*entry = Entry{
		Region:              region,
		Type:                "ProxyCall",
		Service:             service,
		Method:              action,
		Parameters:          params,
		URIParameters:       uriparams,
		FinalHTTPStatusCode: respCode,
		AccessKey:           accessKey,
		SessionToken:        sessionToken,
		Host:                host,
	}

	return nil
}
