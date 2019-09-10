package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "strconv"
    "strings"
    "syscall"
    "time"

    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/client"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/cloudwatch"
    "github.com/keur/cloudwatch-alarm-exporter/alertmanager"
    "github.com/keur/cloudwatch-alarm-exporter/collector"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/spf13/pflag"
)

func main() {
    portFlag := pflag.Int("port", 8080, "The HTTP `port` to listen to")
    regionFlag := pflag.String("region", "", "The AWS region to use, eg 'eu-west-1'")
    retriesFlag := pflag.Int("retries", 1, "The `number` of retries when fetching alarms")
    alertManagerFlag := pflag.String("alertmanager", "", "`URL` to alert manager")
    refreshIntervalFlag := pflag.Int("refresh", 10, "Time in `seconds` between refreshing alarms")
    tagsFlag := pflag.StringArray("tag", []string{}, "Key values for tags to export from AWS")
    pflag.Parse()

    if *regionFlag == "" {
        *regionFlag = os.Getenv("AWS_REGION")
    }

    sess, err := session.NewSession(&aws.Config{
        Region:     regionFlag,
        MaxRetries: retriesFlag,
        Retryer: client.DefaultRetryer{},
    })

    if err != nil {
        log.Fatalf("Unable to create session: %s", err)
    }

    cw := cloudwatch.New(sess)
    ca := CloudwatchAlarms{
        alarmDescriber: cw,
        tags:           *tagsFlag,
    }

    if *alertManagerFlag != "" {
        alertManagerURL, err := url.Parse(*alertManagerFlag)
        fmt.Println(alertManagerURL.ResolveReference(alertManagerURL))
        if true {
            return
        }
        if err != nil {
            log.Fatalf("not a valid AlertManger URL: %s", *alertManagerFlag)
        }
        alertmanager.New(*alertManagerURL, ca, time.Duration(*refreshIntervalFlag)*time.Second)
    }

    listener, err := net.ListenTCP("tcp", &net.TCPAddr{
        Port: *portFlag,
    })
    if err != nil {
        log.Fatalf("unable to create listener: %v", err)
    }

    prometheus.Unregister(prometheus.NewGoCollector())
    prometheus.Unregister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{PidFn: nil, Namespace: "", ReportErrors: true}))
    prometheus.MustRegister(collector.New(&ca))

    server := httpServer{
        listener:      listener,
        healthChecker: AlwaysHealthy{},
        alarmFetcher:  ca,
    }

    server.start()
    log.Printf("Service: online\n")

    wait(syscall.SIGINT, syscall.SIGTERM)

}

// wait unitl SIGINT or SIGTERM return
func wait(signals ...os.Signal) {
    terminate := make(chan os.Signal)
    signal.Notify(terminate, signals...)

    defer log.Printf("Caught signal: shutting down.\n")

    for {
        select {
        case <-terminate:
            return
        }
    }
}

// JSONError is used for formating errors in JSON format
type JSONError interface {
    error
    JSONHandler(http.ResponseWriter)
}

func newJSONError(err error) JSONError {
    if e, ok := err.(JSONError); ok {
        return e
    }

    return newHTTPError(http.StatusServiceUnavailable, err.Error())
}

// HTTPError is used for signaling back an error
type HTTPError struct {
    Code    int `json:"-"`
    Message string
}

func newHTTPError(code int, message string) *HTTPError {
    return &HTTPError{
        Code:    code,
        Message: message,
    }
}

func (he HTTPError) Error() string {
    return he.Message
}

// JSONHandler implements the HTTPErrorer interface
func (he HTTPError) JSONHandler(w http.ResponseWriter) {
    w.WriteHeader(he.Code)
    w.Header().Set("Content-Type", "application/json")
    encoder := json.NewEncoder(w)
    err := encoder.Encode(he)
    if err != nil {
        log.Fatalf("error encoding error: %v", err)
    }
}

type httpServer struct {
    listener      net.Listener
    healthChecker HealthChecker
    alarmFetcher  AlarmFetcher
}

func (hs *httpServer) listen() {
    handler := http.NewServeMux()
    handler.HandleFunc("/healthcheck", hs.healthcheck)
    handler.HandleFunc("/alarms", hs.activeAlarms)
    handler.HandleFunc("/", hs.root)
    handler.Handle("/metrics", promhttp.Handler())

    err := http.Serve(hs.listener, handler)

    if err != nil {
        if strings.HasSuffix(err.Error(), "use of closed network connection") {
            // this happens when Close() is called, and it's normal
            return
        }
        log.Fatalf("HTTP server exited: %v", err)
    }
}

func (hs *httpServer) start() {
    hs.listen()
}

func (hs *httpServer) stop() error {
    return hs.listener.Close()
}

func (hs *httpServer) healthcheck(w http.ResponseWriter, r *http.Request) {
    err := hs.healthChecker.Health()

    if err != nil {
        newJSONError(err).JSONHandler(w)
        return
    }
}

func (hs *httpServer) activeAlarms(w http.ResponseWriter, r *http.Request) {
    alarms, err := hs.alarmFetcher.Alarms()
    if err != nil {
        newJSONError(err)
    }
    jsonEncode(w, alarms)
}

func (hs *httpServer) root(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(`<html>
        <head><title>CloudWatch Alarm Exporter</title></head>
        <body>
        <h1>CloudWatch Alarm Exporter</h1>
        <p><a href="/metrics">Metrics</a></p>
        </body>
        </html>`))
}

func jsonEncode(w http.ResponseWriter, data interface{}) {
    encoder := json.NewEncoder(w)
    w.Header().Set("Content-Type", "application/json")
    err := encoder.Encode(data)
    if err != nil {
        newJSONError(err)
    }
}

// AlarmDescriber is used for describing the current CloudWatch alarms
type AlarmDescriber interface {
    DescribeAlarms(*cloudwatch.DescribeAlarmsInput) (*cloudwatch.DescribeAlarmsOutput, error)
    ListTagsForResource(*cloudwatch.ListTagsForResourceInput) (*cloudwatch.ListTagsForResourceOutput, error)
}

// AlarmFetcher is a highlevel interface to provide a nice abstraction when collecting
// alarms. For future improvement alarms could be streamed back through a channel, this
// could reduce the amount of memory needed.
type AlarmFetcher interface {
    Alarms() ([]*cloudwatch.MetricAlarm, error)
}

// CloudwatchAlarms implements the Alerter and AlarmFetcher interface
type CloudwatchAlarms struct {
    alarmDescriber AlarmDescriber
    tags           []string
}

// Alarms implements the collector alarmFethcer interface
func (ca CloudwatchAlarms) Alarms() ([]*cloudwatch.MetricAlarm, error) {
    return ca.fetchAlarms(nil)
}

func (ca CloudwatchAlarms) fetchAlarms(nextToken *string) ([]*cloudwatch.MetricAlarm, error) {
    var alarms []*cloudwatch.MetricAlarm
    describeAlarmsInput := &cloudwatch.DescribeAlarmsInput{
        NextToken: nextToken,
        // StateValue: aws.String(cloudwatch.StateValueAlarm),
    }
    alarmResponse, err := ca.alarmDescriber.DescribeAlarms(describeAlarmsInput)
    if err != nil {
        return alarms, err
    }
    alarms = append(alarms, alarmResponse.MetricAlarms...)

    if alarmResponse.NextToken != nil {
        nextAlarms, err := ca.fetchAlarms(alarmResponse.NextToken)
        alarms = append(alarms, nextAlarms...)
        return alarms, err
    }

    return alarms, nil
}

func (ca CloudwatchAlarms) TagsForAlarm(alarm *cloudwatch.MetricAlarm) (map[string]string, error) {
    tags := make(map[string]string)

    tagsResourceInput := &cloudwatch.ListTagsForResourceInput{ResourceARN: alarm.AlarmArn}
    tagResourceOutput, err := ca.alarmDescriber.ListTagsForResource(tagsResourceInput)

    if err != nil {
      for retry := 0; retry <= 9; retry++ {
        log.Printf("Retrying in %d ms...", (retry * 1000))
        time.Sleep(time.Duration(retry * 1000) * time.Millisecond)
        tagResourceOutput, err = ca.alarmDescriber.ListTagsForResource(tagsResourceInput)
        if err != nil {
          if retry == 9 {
            return nil, err
          }
        } else { break }
      }
    }
    for _, tag := range tagResourceOutput.Tags {
        for _, key := range ca.tags {
            if *tag.Key == key {
                tags[key] = *tag.Value
            }
        }
    }
    return tags, nil
}

func (ca CloudwatchAlarms) Tags() *[]string {
    return &ca.tags
}

// Alerts implements the alertmanager Alerter interface
func (ca CloudwatchAlarms) Alerts() alertmanager.Alerts {
    alarms, err := ca.Alarms()
    if err != nil {
        return alertmanager.Alerts{
            alertmanager.Alert{
                Labels:      alertmanager.Labels{"serverError": "internal"},
                Annotations: alertmanager.Annotations{"error": err.Error()},
            },
        }
    }
    var alerts alertmanager.Alerts
    for _, alarm := range alarms {
        alerts = append(alerts, alertmanager.Alert{
            Labels: alertmanager.Labels{
                "name":        *alarm.AlarmName,
                "description": *alarm.AlarmDescription,
                "arn":         *alarm.AlarmArn,
            },
            Annotations: alertmanager.Annotations{
                "statereson": *alarm.StateReason,
                "threshold":  strconv.FormatFloat(*alarm.Threshold, 'f', -1, 64),
            },
        })
    }
    return alerts
}
