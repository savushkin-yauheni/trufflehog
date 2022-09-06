package engine

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/abbysale"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/abuseipdb"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/accuweather"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/adafruitio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/adzuna"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aeroworkflow"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/agora"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aha"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/airbrakeprojectkey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/airbrakeuserkey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/airship"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/airtableapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/airvisual"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aiven"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/alchemy"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/alegra"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aletheiaapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/algoliaadminkey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/alibaba"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/alienvault"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/allsports"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/amadeus"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ambee"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/amplitudeapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/anthropic"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/anypoint"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/apacta"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/api2cart"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/apideck"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/apiflash"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/apifonica"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/apify"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/apilayer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/apimatic"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/apiscience"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/apitemplate"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/appcues"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/appfollow"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/appointedd"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/appoptics"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/appsynergy"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/apptivo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/artsy"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/asanaoauth"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/asanapersonalaccesstoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/assemblyai"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/atera"
	atlassianv1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/atlassian/v1"
	atlassianv2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/atlassian/v2"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/audd"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/auth0managementapitoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/autodesk"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/autoklose"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/autopilot"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/avazapersonalaccesstoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aviationstack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aws"
	awssessionkey "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/awssessionkeys"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/axonaut"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aylien"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ayrshare"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azurebatch"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azurecontainerregistry"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azuredevopspersonalaccesstoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azuresearchadminkey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azuresearchquerykey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azurestorage"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bannerbear"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/baremetrics"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/beamer"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/beebole"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/besnappy"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/besttime"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/betterstack"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/billomat"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bitbar"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bitcoinaverage"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bitfinex"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bitlyaccesstoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bitmex"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/blazemeter"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/blitapp"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/blocknative"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/blogger"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bombbomb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/boostnote"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/borgbase"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/braintreepayments"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/brandfetch"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/browserstack"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/browshot"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bscscan"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/buddyns"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/budibase"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bugherd"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bugsnag"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/buildkite"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/buildkitev2"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bulbul"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bulksms"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/buttercms"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/caflou"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/calendarific"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/calendlyapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/calorieninja"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/campayn"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cannyio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/capsulecrm"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/captaindata"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/carboninterface"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cashboard"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/caspio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/censys"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/centralstationcrm"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cexio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/chartmogul"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/chatbot"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/chatfule"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/checio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/checklyhq"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/checkout"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/checkvist"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cicero"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/circleci"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/clarifai"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/clearbit"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/clickhelp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/clicksendsms"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/clickuppersonaltoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cliengo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/clinchpad"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/clockify"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/clockworksms"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/closecrm"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudconvert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudelements"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudflareapitoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudflarecakey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudflareglobalapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudimage"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudmersive"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudplan"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudsmith"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloverly"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloze"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/clustdoc"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/coda"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/codacy"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/codeclimate"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/codemagic"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/codequiry"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/coinapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/coinbase"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/coinbase_waas"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/coinlayer"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/coinlib"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/collect2"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/column"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/commercejs"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/commodities"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/companyhub"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/confluent"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/contentfulpersonalaccesstoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/conversiontools"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/convertapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/convertkit"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/convier"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/copper"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/couchbase"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/countrylayer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/courier"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/coveralls"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/craftmypdf"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/crowdin"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cryptocompare"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/currencycloud"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/currencyfreaks"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/currencylayer"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/currencyscoop"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/currentsapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/customerguru"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/customerio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/d7network"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dandelion"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dareboost"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/databox"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/databrickstoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/datadogtoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/datagov"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/deepai"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/deepgram"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/delighted"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/demio"
	denodeploy "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/deno"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/deputy"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/detectify"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/detectlanguage"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dfuse"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/diffbot"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/diggernaut"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/digitaloceantoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/digitaloceanv2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/discordbottoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/discordwebhook"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/disqus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ditto"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dnscheck"
	dockerhubv1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dockerhub/v1"
	dockerhubv2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dockerhub/v2"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/docparser"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/documo"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/docusign"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/doppler"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dotmailer"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dovico"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dronahq"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/droneci"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dropbox"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/duply"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dwolla"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dynalist"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dyspatch"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/eagleeyenetworks"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/easyinsight"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ecostruxureit"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/edamam"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/edenai"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/eightxeight"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/elasticemail"
	// elevenlabsv1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/elevenlabs/v1"
	// elevenlabsv2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/elevenlabs/v2"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/enablex"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/endorlabs"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/enigma"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/envoyapikey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/eraser"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/etherscan"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ethplorer"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/eventbrite"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/everhour"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/exchangerateapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/exchangeratesapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/exportsdk"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/extractorapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/facebookoauth"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/faceplusplus"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fastforex"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fastlypersonaltoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/feedier"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fetchrss"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fibery"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/figmapersonalaccesstoken/v1"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/figmapersonalaccesstoken/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fileio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/finage"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/financialmodelingprep"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/findl"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/finnhub"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fixerio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/flatio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fleetbase"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/flickr"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/flightapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/flightlabs"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/flightstats"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/float"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/flowflu"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/flutterwave"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fmfw"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/formbucket"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/formcraft"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/formio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/formsite"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/foursquare"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/frameio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/freshbooks"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/freshdesk"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/front"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ftp"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fulcrum"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fullstory/v1"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fullstory/v2"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/fxmarket"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gcp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gcpapplicationdefaultcredentials"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/geckoboard"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gemini"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gengo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/geoapify"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/geocode"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/geocodify"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/geocodio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/geoipifi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/getgeoapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/getgist"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/getresponse"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/getsandbox"
	githubv1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/github/v1"
	githubv2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/github/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/github_oauth2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/githubapp"
	gitlabv1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gitlab/v1"
	gitlabv2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gitlab/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gitter"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/glassnode"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gocanvas"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gocardless"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/goodday"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/googleoauth2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/grafana"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/grafanaserviceaccount"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/graphcms"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/graphhopper"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/groovehq"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/groq"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gtmetrix"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/guardianapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gumroad"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gyazo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/happyscribe"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/harvest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/firebaseopensignup"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/hellosign"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/helpcrunch"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/helpscout"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/hereapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/heroku"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/hiveage"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/holidayapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/holistic"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/honeycomb"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/host"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/html2pdf"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/hubspotapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/huggingface"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/humanity"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/hunter"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/hybiscus"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/hypertrack"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/iconfinder"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/iexapis"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/iexcloud"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/imagekit"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/imagga"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/impala"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/infura"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/insightly"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/instabot"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/instamojo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/intercom"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/interseller"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/intra42"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/intrinio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/invoiceocean"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ip2location"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ipapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ipgeolocation"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ipinfodb"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ipquality"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ipstack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/jdbc"
	jiratokenv1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/jiratoken/v1"
	jiratokenv2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/jiratoken/v2"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/jotform"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/jumpcloud"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/jupiterone"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/juro"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/kanban"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/kanbantool"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/karmacrm"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/keenio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/kickbox"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/klaviyo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/klipfolio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/knapsackpro"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/kontent"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/kraken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/kucoin"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/kylas"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/languagelayer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/larksuite"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/larksuiteapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/launchdarkly"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ldap"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/leadfeeder"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/lemlist"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/lemonsqueezy"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/lendflow"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/lessannoyingcrm"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/lexigram"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/linearapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/linenotify"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/linkpreview"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/liveagent"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/livestorm"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/loadmill"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/locationiq"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/loggly"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/loginradius"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/logzio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/lokalisetoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/loyverse"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/lunchmoney"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/luno"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/madkudu"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/magicbell"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/magnetic"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mailboxlayer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mailchimp"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mailerlite"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mailgun"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mailjetbasicauth"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mailjetsms"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mailmodo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mailsac"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mandrill"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mapbox"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mapquest"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/marketstack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mattermostpersonaltoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mavenlink"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/maxmindlicense/v1"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/maxmindlicense/v2"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/meaningcloud"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mediastack"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/meistertask"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mesibo"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/messagebird"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/metaapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/metabase"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/metrilo"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/microsoftteamswebhook"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mindmeister"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/miro"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mite"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mixmax"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mockaroo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/moderation"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/monday"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mongodb"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/monkeylearn"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/moonclerk"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/moosend"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/moralis"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mrticktock"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/mux"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/myfreshworks"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/myintervals"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nethunt"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/netlify"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/netsuite"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/neutrinoapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/newrelicpersonalapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/newsapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/newscatcher"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nexmoapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nftport"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ngc"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ngrok"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nicereply"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nightfall"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nimble"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/noticeable"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/notion"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nozbeteams"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/npmtoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/npmtokenv2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nugetapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/numverify"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nutritionix"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nvapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/nylas"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/oanda"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/okta"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/omnisend"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/onedesk"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/onelogin"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/onepagecrm"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/onesignal"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/onfleet"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/oopspam"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/openai"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/opencagedata"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/openuv"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/openvpn"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/openweather"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/opsgenie"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/optimizely"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/overloop"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/owlbot"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/packagecloud"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pagarme"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pagerdutyapikey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pandadoc"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pandascore"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/paperform"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/paralleldots"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/parsehub"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/parsers"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/parseur"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/partnerstack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pastebin"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/paydirtapp"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/paymoapp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/paymongo"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/paypaloauth"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/paystack"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pdflayer"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pdfshift"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/peopledatalabs"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pepipost"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/percy"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pinata"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pipedream"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pipedrive"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pivotaltracker"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pixabay"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/planetscale"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/planetscaledb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/planviewleankit"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/planyo"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/plivo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/podio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pollsapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/poloniex"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/polygon"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/portainer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/portainertoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/positionstack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/postageapp"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/postbacks"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/postgres"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/posthog"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/postman"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/postmark"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/powrbot"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/prefect"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/privacy"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/privatekey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/prodpad"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/prospectcrm"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/protocolsio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/proxycrawl"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pubnubpublishkey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pubnubsubscriptionkey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pulumi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/purestake"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pushbulletapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pusherchannelkey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/pypi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/qase"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/qualaroo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/qubole"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rabbitmq"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/railwayapp"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ramp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rapidapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rawg"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/razorpay"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/reachmail"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/readme"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/reallysimplesystems"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rebrandly"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rechargepayments"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/redis"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/refiner"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rentman"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/repairshopr"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/replicate"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/replyio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/requestfinance"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/restpack"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/restpackhtmltopdfapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/restpackscreenshotapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/revampcrm"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ringcentral"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ritekit"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/roaring"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/robinhoodcrypto"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rocketreach"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rockset"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/roninapp"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/route4me"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rownd"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rubygems"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/runrunit"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/salesblink"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/salescookie"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/salesflare"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/salesforce"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/salesmate"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/satismeterprojectkey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/satismeterwritekey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/saucelabs"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/scalewaykey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/scalr"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/scrapeowl"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/scraperapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/scraperbox"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/scrapestack"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/scrapfly"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/scrapingant"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/scrapingbee"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/screenshotapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/screenshotlayer"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/scrutinizerci"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/securitytrails"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/segmentapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/selectpdf"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/semaphore"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sendbird"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sendbirdorganizationapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sendgrid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sendinbluev2"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sentrytoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/serphouse"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/serpstack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sheety"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sherpadesk"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/shipday"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/shodankey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/shopify"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/shortcut"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/shotstack"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/shutterstock"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/shutterstockoauth"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/signable"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/signalwire"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/signaturit"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/signupgenius"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sigopt"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/simfin"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/simplesat"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/simplynoted"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/simvoly"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sinchmessage"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sirv"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/siteleaf"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/skrappio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/skybiometry"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/slack"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/slackwebhook"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/smartsheets"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/smartystreets"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/smooch"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/snipcart"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/snowflake"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/snykkey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sonarcloud"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sourcegraph"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sourcegraphcody"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/speechtextai"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/splunkobservabilitytoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/spoonacular"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sportsmonk"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sqlserver"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/square"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/squareapp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/squarespace"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/squareup"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sslmate"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/statuscake"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/statuspage"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/statuspal"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/stitchdata"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/stockdata"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/storecove"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/stormboard"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/stormglass"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/storyblok"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/storychief"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/strava"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/streak"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/stripe"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/stripo"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/stytch"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sugester"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sumologickey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/supabasetoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/supernotesapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/surveyanyplace"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/surveybot"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/surveysparrow"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/survicate"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/swell"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/swiftype"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tailscale"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tallyfy"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tatumio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/taxjar"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/teamgate"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/teamworkcrm"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/teamworkdesk"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/teamworkspaces"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/technicalanalysisapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tefter"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/telegrambottoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/teletype"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/telnyx"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/terraformcloudpersonaltoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/testingbot"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/textmagic"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/theoddsapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/thinkific"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/thousandeyes"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ticketmaster"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tickettailor"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tiingo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/timecamp"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/timezoneapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tineswebhook"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tmetric"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/todoist"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tokeet"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tomorrowio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tomtom"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tradier"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/transferwise"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/travelpayouts"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/travisci"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/trelloapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/trufflehogenterprise"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/twelvedata"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/twilio"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/twist"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/twitch"
	twitterv1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/twitter/v1"
	twitterv2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/twitter/v2"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/twitterconsumerkey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tyntec"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/typeform"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/typetalk"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/ubidots"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/uclassify"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/unifyid"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/unplugg"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/unsplash"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/upcdatabase"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/uplead"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/uploadcare"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/uptimerobot"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/upwave"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/uri"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/urlscan"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/userflow"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/userstack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/vagrantcloudpersonaltoken"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/vatlayer"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/vbout"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/vercel"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/verifier"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/verimail"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/veriphone"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/versioneye"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/viewneo"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/virustotal"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/visualcrossing"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/voiceflow"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/voicegain"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/voodoosms"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/vouchery"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/vpnapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/vultrapikey"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/vyte"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/walkscore"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/weatherbit"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/weatherstack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/web3storage"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/webex"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/webflow"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/webscraper"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/webscraping"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/websitepulse"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/whoxy"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/wistia"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/wiz"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/worksnaps"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/workstack"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/worldcoinindex"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/worldweather"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/wrike"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/yandex"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/yelp"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/youneedabudget"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/yousign"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/youtubeapikey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zendeskapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zenkitapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zenrows"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zenscrape"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zenserp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zeplin"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zerobounce"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zerotier"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zipapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zipbooks"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zipcodeapi"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zipcodebase"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zonkafeedback"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/zulipchat"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/etherscan"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/infura"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/alchemy"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/blocknative"
	_ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/moralis"
    _ "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/bscscan"
)

func DefaultDetectors() []detectors.Detector {
	detectorList := []detectors.Detector{
		&heroku.Scanner{},
		&pypi.Scanner{},
		&linearapi.Scanner{},
		&alibaba.Scanner{},
		aws.New(),
		awssessionkey.New(),
		&slack.Scanner{}, // has 4 secret types
		&gitlabv1.Scanner{},
		&gitlabv2.Scanner{},
		&sendgrid.Scanner{},
		&mailchimp.Scanner{},
		// &okta.Scanner{},
		&onelogin.Scanner{},
		&dropbox.Scanner{},
		&stripe.Scanner{},
		&square.Scanner{},
		&squareapp.Scanner{},
		&pivotaltracker.Scanner{},
		&githubv1.Scanner{},
		&githubv2.Scanner{},
		&twilio.Scanner{},
		&gcp.Scanner{},
		&circleci.Scanner{},
		// &uri.Scanner{},
		&razorpay.Scanner{},
		&jdbc.Scanner{},
		&privatekey.Scanner{},
		// &maxmindlicensev1.Scanner{},
		// &maxmindlicensev2.Scanner{},
		&airtableapikey.Scanner{},
		&bitfinex.Scanner{},
		&telegrambottoken.Scanner{},
		// &clarifai.Scanner{},
		// &cloudflareapitoken.Scanner{},
		&cloudflarecakey.Scanner{},
		&cloudflareglobalapikey.Scanner{},
		&terraformcloudpersonaltoken.Scanner{},
		&asanapersonalaccesstoken.Scanner{},
		&trelloapikey.Scanner{},
		&mapbox.Scanner{},
		&mailgun.Scanner{},
		&mailjetbasicauth.Scanner{},
		&auth0managementapitoken.Scanner{},
		// &auth0oauth.Scanner{},
		&mailjetsms.Scanner{},
		&digitaloceantoken.Scanner{},
		&paystack.Scanner{},
		&contentfulpersonalaccesstoken.Scanner{},
		// &hunter.Scanner{},
		&sendinbluev2.Scanner{},
		&elasticemail.Scanner{},
		&messagebird.Scanner{},
		&microsoftteamswebhook.Scanner{},
		&plivo.Scanner{},
		&rapidapi.Scanner{},
		&discordbottoken.Scanner{},
		&netlify.Scanner{},
		// &hubspotapikey.Scanner{},
		&travisci.Scanner{},
		&scalewaykey.Scanner{},
		&fastlypersonaltoken.Scanner{},
		&snykkey.Scanner{},
		&postmark.Scanner{},
		// &figmapersonalaccesstokenv1.Scanner{},
		// &figmapersonalaccesstokenv2.Scanner{},
		// &webex.Scanner{},
		&segmentapikey.Scanner{},
		&vultrapikey.Scanner{},
		// &ibmclouduserkey.Scanner{},
		// &pepipost.Scanner{},
		&postman.Scanner{},
		&nexmoapikey.Scanner{},
		&newrelicpersonalapikey.Scanner{},
		&pushbulletapikey.Scanner{},
		&paypaloauth.Scanner{},
		&datadogtoken.Scanner{},
		&airbrakeuserkey.Scanner{},
		// &sumologickey.Scanner{},
		&pagerdutyapikey.Scanner{},
		&jiratokenv1.Scanner{},
		jiratokenv2.Scanner{},
		// &airbrakeprojectkey.Scanner{},
		&calendlyapikey.Scanner{},
		// &bitlyaccesstoken.Scanner{},
		// &youtubeapikey.Scanner{},
		&coinbase.Scanner{},
		&confluent.Scanner{},
		&zendeskapi.Scanner{},
		&facebookoauth.Scanner{},
		// &amplitudeapikey.Scanner{},
		// &pubnubpublishkey.Scanner{},
		// &sentrytoken.Scanner{},
		&githubapp.Scanner{},
		// &slackwebhook.Scanner{},
		// &spotifykey.Scanner{},
		&discordwebhook.Scanner{},
		// &zapierwebhook.Scanner{},
		// &pubnubsubscriptionkey.Scanner{},
		// &plaidkey.Scanner{},
		// &calendarific.Scanner{},
		&jumpcloud.Scanner{},
		&notion.Scanner{},
		&droneci.Scanner{},
		// &ipstack.Scanner{},
		// &adobeio.Scanner{},
		// &sslmate.Scanner{},
		&buildkite.Scanner{},
		// &shodankey.Scanner{},
		// &lokalisetoken.Scanner{},
		// &twelvedata.Scanner{},
		// &intercom.Scanner{},
		// &d7network.Scanner{},
		// &buttercms.Scanner{},
		// &taxjar.Scanner{},
		// &zerobounce.Scanner{},
		// &fixerio.Scanner{},
		// &verimail.Scanner{},
		&helpscout.Scanner{},
		// &beamer.Scanner{},
		&liveagent.Scanner{},
		&pipedrive.Scanner{},
		// &cannyio.Scanner{},
		&vercel.Scanner{},
		// &posthog.Scanner{},
		&mandrill.Scanner{},
		&mailmodo.Scanner{},
		// &flutterwave.Scanner{},
		&algoliaadminkey.Scanner{},
		&mattermostpersonaltoken.Scanner{},
		&splunkobservabilitytoken.Scanner{},
		&simvoly.Scanner{},
		// &surveysparrow.Scanner{},
		// &survicate.Scanner{},
		&omnisend.Scanner{},
		&getgist.Scanner{},
		// &groovehq.Scanner{},
		// &newsapi.Scanner{},
		// &helpcrunch.Scanner{},
		// &linemessaging.Scanner{},
		// &launchdarkly.Scanner{},
		// &salesflare.Scanner{},
		&chatbot.Scanner{},
		// &nftport.Scanner{},
		// &coveralls.Scanner{},
		&rubygems.Scanner{},
		&webflow.Scanner{},
		&graphcms.Scanner{},
		&anypoint.Scanner{},
		// &frameio.Scanner{},
		// &zonkafeedback.Scanner{},
		// &surveybot.Scanner{},
		// &mailerlite.Scanner{},
		// &qualaroo.Scanner{},
		// &simplesat.Scanner{},
		// &convertkit.Scanner{},
		// &clockworksms.Scanner{},
		// &apideck.Scanner{},
		&zeplin.Scanner{},
		// &myfreshworks.Scanner{},
		// &satismeterwritekey.Scanner{},
		&customerio.Scanner{},
		&clicksendsms.Scanner{},
		// &copper.Scanner{},
		// &skrappio.Scanner{},
		// &delighted.Scanner{},
		// &abbysale.Scanner{},
		// &feedier.Scanner{},
		// &powrbot.Scanner{},
		// &magnetic.Scanner{},
		&polygon.Scanner{},
		&smartsheets.Scanner{},
		// &wepay.Scanner{},
		// &artifactory.Scanner{},
		// &linenotify.Scanner{},
		// &float.Scanner{},
		&monday.Scanner{},
		// &debounce.Scanner{},
		// &guardianapi.Scanner{},
		&squarespace.Scanner{},
		// &wrike.Scanner{},
		// &storyblok.Scanner{},
		// &salesblink.Scanner{},
		// &campayn.Scanner{},
		// &clinchpad.Scanner{},
		// &companyhub.Scanner{},
		// &dyspatch.Scanner{},
		// &harvest.Scanner{},
		&firebaseopensignup.Scanner{},
		// &moosend.Scanner{},
		// &openweather.Scanner{},
		// &siteleaf.Scanner{},
		// &flowflu.Scanner{},
		// &nimble.Scanner{},
		// &lessannoyingcrm.Scanner{},
		// &nethunt.Scanner{},
		// &apptivo.Scanner{},
		// &capsulecrm.Scanner{},
		&insightly.Scanner{},
		// &kylas.Scanner{},
		&onepagecrm.Scanner{},
		// &reallysimplesystems.Scanner{},
		// &timezoneapi.Scanner{},
		// &everhour.Scanner{},
		// &jotform.Scanner{},
		&workstack.Scanner{},
		// &clockify.Scanner{},
		// &karmacrm.Scanner{},
		// &revampcrm.Scanner{},
		// &apollo.Scanner{},
		// &artsy.Scanner{},
		// &vpnapi.Scanner{},
		// &dnscheck.Scanner{},
		// &toggltrack.Scanner{},
		// &ethplorer.Scanner{},
		// &fulcrum.Scanner{},
		// &metrilo.Scanner{},
		// &salescookie.Scanner{},
		// &geoipifi.Scanner{},
		&yandex.Scanner{},
		&airship.Scanner{},
		// &refiner.Scanner{},
		&pandadoc.Scanner{},
		// &juro.Scanner{},
		// &documo.Scanner{},
		&docusign.Scanner{},
		// &roninapp.Scanner{},
		&doppler.Scanner{},
		// &codacy.Scanner{},
		&gocardless.Scanner{},
		// &alconost.Scanner{},
		// &rawg.Scanner{},
		// &accuweather.Scanner{},
		// &tomtom.Scanner{},
		// &teamgate.Scanner{},
		// &bulbul.Scanner{},
		// &centralstationcrm.Scanner{},
		// &tyntec.Scanner{},
		// &axonaut.Scanner{},
		&kraken.Scanner{},
		// &easyinsight.Scanner{},
		// &closecrm.Scanner{},
		// &customerguru.Scanner{},
		// &prospectcrm.Scanner{},
		// &surveyanyplace.Scanner{},
		// &ubidots.Scanner{},
		// &elevenlabsv1.Scanner{},
		// &elevenlabsv2.Scanner{},
		// sinchmessage.Scanner{},
		// ayrshare.Scanner{},
		// mailboxlayer.Scanner{},
		// satismeterprojectkey.Scanner{},
		// pusherchannelkey.Scanner{},
		// imagekit.Scanner{},
		asanaoauth.Scanner{},
		// getemail.Scanner{},
		// rocketreach.Scanner{},
		// raven.Scanner{},
		// kontent.Scanner{},
		cloudplan.Scanner{},
		// autoklose.Scanner{},
		// appcues.Scanner{},
		// getemails.Scanner{},
		// leadfeeder.Scanner{},
		// uplead.Scanner{},
		// audd.Scanner{},
		// bitbar.Scanner{},
		// abstract.Scanner{},
		// exchangerateapi.Scanner{},
		// currencycloud.Scanner{},
		// finage.Scanner{},
		adafruitio.Scanner{},
		// storychief.Scanner{},
		// tradier.Scanner{},
		hellosign.Scanner{},
		// dwolla.Scanner{},
		// voicegain.Scanner{},
		// ambee.Scanner{},
		// bannerbear.Scanner{},
		// hypertrack.Scanner{},
		// holidayapi.Scanner{},
		// currencylayer.Scanner{},
		// coinlib.Scanner{},
		// agora.Scanner{},
		// marketstack.Scanner{},
		// exchangeratesapi.Scanner{},
		// faceplusplus.Scanner{},
		// baremetrics.Scanner{},
		// getgeoapi.Scanner{},
		// alegra.Scanner{},
		// tatumio.Scanner{},
		// deepgram.Scanner{},
		// brandfetch.Scanner{},
		// typeform.Scanner{},
		// fxmarket.Scanner{},
		// ipapi.Scanner{},
		// clearbit.Scanner{},
		// spoonacular.Scanner{},
		// finnhub.Scanner{},
		checkout.Scanner{},
		// mixpanel.Scanner{},
		// ipgeolocation.Scanner{},
		// tmetric.Scanner{},
		// fullstoryv1.Scanner{},
		// fullstoryv2.Scanner{},
		// noticeable.Scanner{},
		// currencyscoop.Scanner{},
		// scrapingbee.Scanner{},
		// todoist.Scanner{},
		// owlbot.Scanner{},
		keenio.Scanner{},
		// dovico.Scanner{},
		html2pdf.Scanner{},
		yousign.Scanner{},
		// fleetbase.Scanner{},
		// cloudmersive.Scanner{},
		// imagga.Scanner{},
		// visualcrossing.Scanner{},
		bugsnag.Scanner{},
		runrunit.Scanner{},
		// assemblyai.Scanner{},
		loyverse.Scanner{},
		swell.Scanner{},
		// crowdin.Scanner{},
		// nutritionix.Scanner{},
		// mapquest.Scanner{},
		clickuppersonaltoken.Scanner{},
		// tiingo.Scanner{},
		// billomat.Scanner{},
		blogger.Scanner{},
		front.Scanner{},
		// apify.Scanner{},
		// dynalist.Scanner{},
		mavenlink.Scanner{},
		// sportsmonk.Scanner{},
		// bitcoinaverage.Scanner{},
		// zipcodeapi.Scanner{},
		gyazo.Scanner{},
		// sparkpost.Scanner{},
		// locationiq.Scanner{},
		saucelabs.Scanner{},
		enigma.Scanner{},
		clickhelp.Scanner{},
		// adzuna.Scanner{},
		// vouchery.Scanner{},
		// currentsapi.Scanner{},
		// flickr.Scanner{},
		// apiflash.Scanner{},
		// geocodio.Scanner{},
		// datagov.Scanner{},
		// tomorrowio.Scanner{},
		// lexigram.Scanner{},
		// securitytrails.Scanner{},
		// foursquare.Scanner{},
		// browshot.Scanner{},
		// edamam.Scanner{},
		// alienvault.Scanner{},
		// protocolsio.Scanner{},
		// coinlayer.Scanner{},
		commercejs.Scanner{},
		// detectlanguage.Scanner{},
		// worldcoinindex.Scanner{},
		// airvisual.Scanner{},
		sheety.Scanner{},
		// financialmodelingprep.Scanner{},
		// stormglass.Scanner{},
		// oopspam.Scanner{},
		// unsplash.Scanner{},
		// allsports.Scanner{},
		// amadeus.Scanner{},
		ringcentral.Scanner{},
		// pixabay.Scanner{},
		// youneedabudget.Scanner{},
		// languagelayer.Scanner{},
		// gengo.Scanner{},
		// aylien.Scanner{},
		// shutterstock.Scanner{},
		// hereapi.Scanner{},
		// readme.Scanner{},
		pastebin.Scanner{},
		// vatlayer.Scanner{},
		// verifier.Scanner{},
		// graphhopper.Scanner{},
		// scraperapi.Scanner{},
		// ritekit.Scanner{},
		// linkpreview.Scanner{},
		// dotmailer.Scanner{},
		// api2cart.Scanner{},
		// virustotal.Scanner{},
		// numverify.Scanner{},
		// pdflayer.Scanner{},
		// geocode.Scanner{},
		// iconfinder.Scanner{},
		// m3o.Scanner{},
		mesibo.Scanner{},
		impala.Scanner{},
		// besttime.Scanner{},
		// currencyfreaks.Scanner{},
		// humanity.Scanner{},
		loginradius.Scanner{},
		// stockdata.Scanner{},
		// flatio.Scanner{},
		// openuv.Scanner{},
		// snipcart.Scanner{},
		// screenshotapi.Scanner{},
		// cryptocompare.Scanner{},
		// happyscribe.Scanner{},
		// geocodify.Scanner{},
		// bombbomb.Scanner{},
		// serpstack.Scanner{},
		// zenserp.Scanner{},
		// restpackscreenshotapi.Scanner{},
		// shortcut.Scanner{},
		// nasdaqdatalink.Scanner{},
		neutrinoapi.Scanner{},
		bitmex.Scanner{},
		// deepai.Scanner{},
		// host.Scanner{},
		// pdfshift.Scanner{},
		// fetchrss.Scanner{},
		// proxycrawl.Scanner{},
		// storecove.Scanner{},
		fileio.Scanner{},
		// coinapi.Scanner{},
		stytch.Scanner{},
		signupgenius.Scanner{},
		streak.Scanner{},
		// route4me.Scanner{},
		// openai.Scanner{},
		// opencagedata.Scanner{},
		// positionstack.Scanner{},
		// upcdatabase.Scanner{},
		// commodities.Scanner{},
		// glassnode.Scanner{},
		optimizely.Scanner{},
		// censys.Scanner{},
		// scraperbox.Scanner{},
		// ticketmaster.Scanner{},
		// iexcloud.Scanner{},
		// partnerstack.Scanner{},
		// qubole.Scanner{},
		poloniex.Scanner{},
		// shipday.Scanner{},
		// stitchdata.Scanner{},
		// hiveage.Scanner{},
		// technicalanalysisapi.Scanner{},
		// smartystreets.Scanner{},
		// shutterstockoauth.Scanner{},
		// newscatcher.Scanner{},
		postageapp.Scanner{},
		// unplugg.Scanner{},
		paymongo.Scanner{},
		// flightapi.Scanner{},
		// countrylayer.Scanner{},
		// veriphone.Scanner{},
		// ipinfodb.Scanner{},
		// mediastack.Scanner{},
		// screenshotlayer.Scanner{},
		// userstack.Scanner{},
		// edenai.Scanner{},
		// urlscan.Scanner{},
		// zenscrape.Scanner{},
		// dailyco.Scanner{},
		// nicereply.Scanner{},
		// hive.Scanner{},
		// clustdoc.Scanner{},
		// scrapingant.Scanner{},
		// kickbox.Scanner{},
		// scrapeowl.Scanner{},
		// rebrandly.Scanner{},
		// dandelion.Scanner{},
		// purestake.Scanner{},
		// carboninterface.Scanner{},
		signaturit.Scanner{},
		// blitapp.Scanner{},
		// restpackhtmltopdfapi.Scanner{},
		// webscraping.Scanner{},
		// geoapify.Scanner{},
		// dfuse.Scanner{},
		gitter.Scanner{},
		// autopilot.Scanner{},
		// aletheiaapi.Scanner{},
		// intrinio.Scanner{},
		// aviationstack.Scanner{},
		// scrapestack.Scanner{},
		// restpack.Scanner{},
		// cloverly.Scanner{},
		// thinkific.Scanner{},
		// meaningcloud.Scanner{},
		// skybiometry.Scanner{},
		// appfollow.Scanner{},
		// abuseipdb.Scanner{},
		// squareup.Scanner{},
		// zipbooks.Scanner{},
		// roaring.Scanner{},
		// signalwire.Scanner{},
		// weatherbit.Scanner{},
		textmagic.Scanner{},
		// telnyx.Scanner{},
		// calorieninja.Scanner{},
		// vyte.Scanner{},
		// walkscore.Scanner{},
		// planyo.Scanner{},
		// zipapi.Scanner{},
		// mailsac.Scanner{},
		// unifyid.Scanner{},
		// worldweather.Scanner{},
		// strava.Scanner{},
		// autodesk.Scanner{},
		// serphouse.Scanner{},
		// paralleldots.Scanner{},
		// semaphore.Scanner{},
		// nylas.Scanner{},
		// weatherstack.Scanner{},
		// ipquality.Scanner{},
		// blazemeter.Scanner{},
		// cicero.Scanner{},
		onedesk.Scanner{},
		bugherd.Scanner{},
		// whoxy.Scanner{},
		// smooch.Scanner{},
		// apifonica.Scanner{},
		// goodday.Scanner{},
		// getsandbox.Scanner{},
		freshdesk.Scanner{},
		teamworkdesk.Scanner{},
		tallyfy.Scanner{},
		apimatic.Scanner{},
		// moonclerck.Scanner{},
		boostnote.Scanner{},
		// freshbooks.Scanner{},
		// cashboard.Scanner{},
		// thousandeyes.Scanner{},
		// zenkitapi.Scanner{},
		// sherpadesk.Scanner{},
		// shotstack.Scanner{},
		// luno.Scanner{},
		// apacta.Scanner{},
		// fmfw.Scanner{},
		courier.Scanner{},
		// checkvist.Scanner{},
		// invoiceocean.Scanner{},
		// travelpayouts.Scanner{},
		// mixmax.Scanner{},
		cloze.Scanner{},
		// supernotesapi.Scanner{},
		// fastforex.Scanner{},
		// sirv.Scanner{},
		teamworkcrm.Scanner{},
		geckoboard.Scanner{},
		// appsynergy.Scanner{},
		// findl.Scanner{},
		// simplynoted.Scanner{},
		// pandascore.Scanner{},
		// gocanvas.Scanner{},
		// formio.Scanner{},
		// livestorm.Scanner{},
		// manifest.Scanner{},
		// formbucket.Scanner{},
		// apiscience.Scanner{},
		dronahq.Scanner{},
		// webscraper.Scanner{},
		// versioneye.Scanner{},
		// rownd.Scanner{},
		// diffbot.Scanner{},
		nozbeteams.Scanner{},
		pipedream.Scanner{},
		// paymoapp.Scanner{},
		// peopledatalabs.Scanner{},
		// mite.Scanner{},
		// mindmeister.Scanner{},
		// deputy.Scanner{},
		// eagleeyenetworks.Scanner{},
		// sigopt.Scanner{},
		lendflow.Scanner{},
		// meistertask.Scanner{},
		// mrticktock.Scanner{},
		// beebole.Scanner{},
		// theoddsapi.Scanner{},
		// oanda.Scanner{},
		// scrapfly.Scanner{},
		kanban.Scanner{},
		// upwave.Scanner{},
		ditto.Scanner{},
		// buddyns.Scanner{},
		// checio.Scanner{},
		kucoin.Scanner{},
		// eightxeight.Scanner{},
		avazapersonalaccesstoken.Scanner{},
		// selectpdf.Scanner{},
		madkudu.Scanner{},
		borgbase.Scanner{},
		// cliengo.Scanner{},
		// swiftype.Scanner{},
		// viewneo.Scanner{},
		planviewleankit.Scanner{},
		// cloudimage.Scanner{},
		// worksnaps.Scanner{},
		caspio.Scanner{},
		// caflou.Scanner{},
		// enablex.Scanner{},
		// checklyhq.Scanner{},
		teamworkspaces.Scanner{},
		cloudelements.Scanner{},
		// captaindata.Scanner{},
		uploadcare.Scanner{},
		// moderation.Scanner{},
		// myintervals.Scanner{},
		// klipfolio.Scanner{},
		// flightstats.Scanner{},
		sendbird.Scanner{},
		cexio.Scanner{},
		// repairshopr.Scanner{},
		// metaapi.Scanner{},
		// aeroworkflow.Scanner{},
		// column.Scanner{},
		sugester.Scanner{},
		sendbirdorganizationapi.Scanner{},
		// chatfule.Scanner{},
		// convier.Scanner{},
		// loadmill.Scanner{},
		magicbell.Scanner{},
		// glitterlyapi.Scanner{},
		// knapsackpro.Scanner{},
		twitterv1.Scanner{},
		twitterv2.Scanner{},
		// timecamp.Scanner{},
		// signable.Scanner{},
		// teletype.Scanner{},
		// wistia.Scanner{},
		// hybiscus.Scanner{},
		miro.Scanner{},
		// moonclerk.Scanner{},
		// codequiry.Scanner{},
		qase.Scanner{},
		// extractorapi.Scanner{},
		// craftmypdf.Scanner{},
		// generic.Scanner{},
		// userflow.Scanner{},
		// mockaroo.Scanner{},
		// statuspage.Scanner{},
		// statuspal.Scanner{},
		// testingbot.Scanner{},
		// conversiontools.Scanner{},
		// parsers.Scanner{},
		// scrutinizerci.Scanner{},
		sonarcloud.Scanner{},
		// dareboost.Scanner{},
		// pinata.Scanner{},
		// exportsdk.Scanner{},
		rechargepayments.Scanner{},
		browserstack.Scanner{},
		// lunchmoney.Scanner{},
		atera.Scanner{},
		// parsehub.Scanner{},
		// voodoosms.Scanner{},
		// yelp.Scanner{},
		// podio.Scanner{},
		// rockset.Scanner{},
		// aha.Scanner{},
		packagecloud.Scanner{},
		cloudsmith.Scanner{},
		// nightfall.Scanner{},
		// mux.Scanner{},
		// statuscake.Scanner{},
		// formcraft.Scanner{},
		// paperform.Scanner{},
		// zulipchat.Scanner{},
		// iexapis.Scanner{},
		// detectify.Scanner{},
		reachmail.Scanner{},
		// gumroad.Scanner{},
		typetalk.Scanner{},
		// chartmogul.Scanner{},
		// fibery.Scanner{},
		// uptimerobot.Scanner{},
		// paydirtapp.Scanner{},
		disqus.Scanner{},
		bulksms.Scanner{},
		onesignal.Scanner{},
		// stormboard.Scanner{},
		// interseller.Scanner{},
		// tickettailor.Scanner{},
		twitch.Scanner{},
		// rentman.Scanner{},
		// tefter.Scanner{},
		// pollsapi.Scanner{},
		// diggernaut.Scanner{},
		// zenrows.Scanner{},
		// instabot.Scanner{},
		// simfin.Scanner{},
		// vbout.Scanner{},
		// besnappy.Scanner{},
		// convertapi.Scanner{},
		// cloudconvert.Scanner{},
		// zipcodebase.Scanner{},
		// speechtextai.Scanner{},
		// databox.Scanner{},
		// postbacks.Scanner{},
		postgres.Scanner{},
		// collect2.Scanner{},
		// uclassify.Scanner{},
		// holistic.Scanner{},
		// tokeet.Scanner{},
		// duply.Scanner{},
		// gtmetrix.Scanner{},
		braintreepayments.Scanner{},
		// docparser.Scanner{},
		// formsite.Scanner{},
		// flightlabs.Scanner{},
		// getresponse.Scanner{},
		// codeclimate.Scanner{},
		// apilayer.Scanner{},
		// monkeylearn.Scanner{},
		// parseur.Scanner{},
		// honeycomb.Scanner{},
		// demio.Scanner{},
		kanbantool.Scanner{},
		salesmate.Scanner{},
		// lemlist.Scanner{},
		// websitepulse.Scanner{},
		scalr.Scanner{},
		// ecostruxureit.Scanner{},
		// appointedd.Scanner{},
		// twist.Scanner{},
		// prodpad.Scanner{},
		// transferwise.Scanner{},
		codemagic.Scanner{},
		mongodb.Scanner{},
		// ngc.Scanner{},
		gemini.Scanner{},
		digitaloceanv2.Scanner{},
		npmtoken.Scanner{},
		npmtokenv2.Scanner{},
		sqlserver.Scanner{},
		redis.Scanner{},
		ftp.Scanner{},
		ldap.Scanner{},
		shopify.Scanner{},
		// etherscan.Scanner{},
		// infura.Scanner{},
		// alchemy.Scanner{},
		// blocknative.Scanner{},
		// moralis.Scanner{},
		// bscscan.Scanner{},
		percy.Scanner{},
		// tineswebhook.Scanner{},
		pulumi.Scanner{},
		databrickstoken.Scanner{},
		supabasetoken.Scanner{},
		nugetapikey.Scanner{},
		aiven.Scanner{},
		prefect.Scanner{},
		buildkitev2.Scanner{},
		opsgenie.Scanner{},
		dockerhubv1.Scanner{},
		couchbase.Scanner{},
		envoyapikey.Scanner{},
		github_oauth2.Scanner{},
		snowflake.Scanner{},
		// huggingface.Scanner{},
		// trufflehogenterprise.Scanner{},
		salesforce.Scanner{},
		sourcegraph.Scanner{},
		tailscale.Scanner{},
		loggly.Scanner{},
		web3storage.Scanner{},
		// &ramp.Scanner{},
		// &anthropic.Scanner{},
		&sourcegraphcody.Scanner{},
		// voiceflow.Scanner{},
		// ip2location.Scanner{},
		grafanaserviceaccount.Scanner{},
		vagrantcloudpersonaltoken.Scanner{},
		openvpn.Scanner{},
		&metabase.Scanner{},
		appoptics.Scanner{},
		// zerotier.Scanner{},
		// betterstack.Scanner{},
		coinbase_waas.Scanner{},
		// replyio.Scanner{},
		// stripo.Scanner{},
		// lemonsqueezy.Scanner{},
		denodeploy.Scanner{},
		// budibase.Scanner{},
		// requestfinance.Scanner{},
		coda.Scanner{},
		grafana.Scanner{},
		// logzio.Scanner{},
		// eventbrite.Scanner{},
		// &overloop.Scanner{},
		ngrok.Scanner{},
		// replicate.Scanner{},
		// privacy.Scanner{},
		// instamojo.Scanner{},
		// klaviyo.Scanner{},
		portainer.Scanner{},
		rabbitmq.Scanner{},
		planetscale.Scanner{},
		portainertoken.Scanner{},
		pagarme.Scanner{},
		planetscaledb.Scanner{},
		azure.Scanner{},
		azurestorage.Scanner{},
		azurecontainerregistry.Scanner{},
		azurebatch.Scanner{},
		// azurefunctionkey.Scanner{}, // detector is throwing some FPs
		azuredevopspersonalaccesstoken.Scanner{},
		azuresearchadminkey.Scanner{},
		azuresearchquerykey.Scanner{},
		googleoauth2.Scanner{},
		dockerhubv2.Scanner{},
		&jupiterone.Scanner{},
		gcpapplicationdefaultcredentials.Scanner{},
		wiz.Scanner{},
        // 		onfleet.Scanner{},
        // 		intra42.Scanner{},
        // 		groq.Scanner{},
		// twitterconsumerkey.Scanner{},
		eraser.Scanner{},
		larksuite.Scanner{},
		larksuiteapikey.Scanner{},
		endorlabs.Scanner{},
		atlassianv1.Scanner{},
		atlassianv2.Scanner{},
		netsuite.Scanner{},
		// robinhoodcrypto.Scanner{},
		// nvapi.Scanner{},
		railwayapp.Scanner{},
	}

	// Automatically initialize all detectors that implement
	// EndpointCustomizer and/or CloudProvider interfaces.
	for _, d := range detectorList {
		customizer, ok := d.(detectors.EndpointCustomizer)
		if !ok {
			continue
		}
		// Default to always use the cloud endpoints (if available) and the found endpoints.
		customizer.UseFoundEndpoints(true)
		customizer.UseCloudEndpoint(true)
		if cloudProvider, ok := d.(detectors.CloudProvider); ok {
			customizer.SetCloudEndpoint(cloudProvider.CloudEndpoint())
		}
	}

	return detectorList
}

func DefaultDetectorTypesImplementing[T any]() map[detectorspb.DetectorType]struct{} {
	out := make(map[detectorspb.DetectorType]struct{})
	for _, detector := range DefaultDetectors() {
		if _, ok := detector.(T); ok {
			out[detector.Type()] = struct{}{}
		}
	}
	return out
}
