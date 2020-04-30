package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"

	"bytes"
	"encoding/hex"
	"github.com/741369/go_utils/log/lager"
	"github.com/gin-gonic/gin"
	"golang.org/x/net/context"
	"math/rand"
	"net"
	"time"
)

const (
	//DEBUG is a constant of string type
	DEBUG = "DEBUG"
	INFO  = "INFO"
	WARN  = "WARN"
	ERROR = "ERROR"
	FATAL = "FATAL"
)

//Config is a struct which stores details for maintaining logs
type Config struct {
	LoggerLevel    string
	LoggerFile     string
	Writers        []string
	EnableRsyslog  bool
	RsyslogNetwork string
	RsyslogAddr    string

	LogFormatText bool
}

var config = DefaultConfig()
var m sync.RWMutex

//Writers is a map
var Writers = make(map[string]io.Writer)

//RegisterWriter is used to register a io writer
func RegisterWriter(name string, writer io.Writer) {
	m.Lock()
	Writers[name] = writer
	m.Unlock()
}

//DefaultConfig is a function which retuns config object with default configuration
func DefaultConfig() *Config {
	return &Config{
		LoggerLevel:    INFO,
		LoggerFile:     "",
		EnableRsyslog:  false,
		RsyslogNetwork: "udp",
		RsyslogAddr:    "127.0.0.1:5140",
		LogFormatText:  false,
	}
}

//Init is a function which initializes all config struct variables
func LagerInit(c Config) {
	if c.LoggerLevel != "" {
		config.LoggerLevel = c.LoggerLevel
	}

	if c.LoggerFile != "" {
		config.LoggerFile = c.LoggerFile
		config.Writers = append(config.Writers, "file")
	}

	if c.EnableRsyslog {
		config.EnableRsyslog = c.EnableRsyslog
	}

	if c.RsyslogNetwork != "" {
		config.RsyslogNetwork = c.RsyslogNetwork
	}

	if c.RsyslogAddr != "" {
		config.RsyslogAddr = c.RsyslogAddr
	}
	if len(c.Writers) == 0 {
		config.Writers = append(config.Writers, "stdout")

	} else {
		config.Writers = c.Writers
	}
	config.LogFormatText = c.LogFormatText
	RegisterWriter("stdout", os.Stdout)
	var file io.Writer
	var err error
	if config.LoggerFile != "" {
		file, err = os.OpenFile(config.LoggerFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			panic(err)
		}

	}
	for _, sink := range config.Writers {
		if sink == "file" {
			if file == nil {
				log.Panic("Must set file path")
			}
			RegisterWriter("file", file)
		}
	}
}

//NewLogger is a function
func NewLogger(component string) lager.Logger {
	return NewLoggerExt(component, component)
}

//NewLoggerExt is a function which is used to write new logs
func NewLoggerExt(component string, appGUID string) lager.Logger {
	var lagerLogLevel lager.LogLevel
	switch strings.ToUpper(config.LoggerLevel) {
	case DEBUG:
		lagerLogLevel = lager.DEBUG
	case INFO:
		lagerLogLevel = lager.INFO
	case WARN:
		lagerLogLevel = lager.WARN
	case ERROR:
		lagerLogLevel = lager.ERROR
	case FATAL:
		lagerLogLevel = lager.FATAL
	default:
		panic(fmt.Errorf("unknown logger level: %s", config.LoggerLevel))
	}
	logger := lager.NewLoggerExt(component, config.LogFormatText)
	for _, sink := range config.Writers {

		writer, ok := Writers[sink]
		if !ok {
			log.Panic("Unknow writer: ", sink)
		}
		sink := lager.NewReconfigurableSink(lager.NewWriterSink(sink, writer, lager.DEBUG), lagerLogLevel)
		logger.RegisterSink(sink)
	}

	return logger
}

func Debug2(action string, data ...lager.Data) {
	Logger.Debug(action, data...)
}

func Info3(action string, data ...lager.Data) {
	Logger.Info(action, data...)
}

func Warn(action string, data ...lager.Data) {
	Logger.Warn(action, data...)
}

func Error2(action string, err error, data ...lager.Data) {
	Logger.Error(action, err, data...)
}

func Fatal(action string, err error, data ...lager.Data) {
	Logger.Fatal(action, err, data...)
}

func Debugf2(format string, args ...interface{}) {
	Logger.Debugf(format, args...)
}

func Infof2(format string, args ...interface{}) {
	Logger.Infof(format, args...)
}

func Warnf(format string, args ...interface{}) {
	Logger.Warnf(format, args...)
}

func Errorf2(err error, format string, args ...interface{}) {
	Logger.Errorf(err, format, args...)
}

func Fatalf(err error, format string, args ...interface{}) {
	Logger.Fatalf(err, format, args...)
}

func Debug(ctx context.Context, action string, data ...lager.Data) {
	data = append(data, map[string]interface{}{"trace_id": GetTraceId(ctx)})
	Logger.Debug(action, data...)
}

func Debugf(ctx context.Context, format string, v ...interface{}) {
	data := map[string]interface{}{"trace_id": GetTraceId(ctx)}
	tmp := fmt.Sprintf(format, v...)
	Logger.Debug(tmp, data)
}

func Info2(ctx context.Context, action string, data ...interface{}) {
	if len(data) > 0 {
		Logger.Info(action, lager.Data{"trace_id": GetTraceId(ctx), "data": data})
	} else {
		Logger.Info(action, lager.Data{"trace_id": GetTraceId(ctx)})
	}
}

func Info4(ctx context.Context, action string, data ...lager.Data) {
	if len(data) > 0 {
		data[0]["trace_id"] = GetTraceId(ctx)
		Logger.Info(action, data...)
	} else {
		Logger.Info(action, lager.Data{"trace_id": GetTraceId(ctx)})
	}
}

func Info(ctx context.Context, action string, data ...lager.Data) {
	data = append(data, map[string]interface{}{"trace_id": GetTraceId(ctx)})
	Logger.Info(action, data...)
}

func Infof(ctx context.Context, format string, v ...interface{}) {
	data := map[string]interface{}{"trace_id": GetTraceId(ctx)}
	tmp := fmt.Sprintf(format, v...)
	Logger.Info(tmp, data)
}

func Error(ctx context.Context, action string, err error, data ...lager.Data) {
	data = append(data, map[string]interface{}{"trace_id": GetTraceId(ctx)})
	Logger.Error(action, err, data...)
}

func Errorf(ctx context.Context, err error, format string, v ...interface{}) {
	data := map[string]interface{}{"trace_id": GetTraceId(ctx)}
	tmp := fmt.Sprintf(format, v...)
	Logger.Error(tmp, err, data)
}

func GetTraceId(context context.Context) string {
	if ctx, ok := context.(*gin.Context); ok && ctx != nil {
		vipWebTraceid := ctx.GetString("X-Request-Id")
		if vipWebTraceid != "" {
			return vipWebTraceid
		}
	}
	return ""
}

func GetTraceId3(context context.Context) string {
	if ctx, ok := context.(*gin.Context); ok {
		vipWebTraceid, ok := ctx.Get("X-Request-Id")
		if !ok {
			return ""
		}
		if traceId, ok := vipWebTraceid.(string); ok {
			return traceId
		}
		return ""
	}
	return ""
}

var LocalIP = net.ParseIP("127.0.0.1")

func GetTraceId2(context *gin.Context) (traceId string) {
	ip := LocalIP.String()
	//if context != nil {
	//	ip = net.ParseIP(context.ClientIP()).String()
	//}
	//fmt.Println("======", ip)
	traceId = calcTraceId(ip)
	return
}

func calcTraceId(ip string) (traceId string) {
	now := time.Now()
	timestamp := uint32(now.Unix())
	timeNano := now.UnixNano()
	pid := os.Getpid()

	b := bytes.Buffer{}
	netIP := net.ParseIP(ip)
	if netIP == nil {
		b.WriteString("00000000")
	} else {
		b.WriteString(hex.EncodeToString(netIP.To4()))
	}
	b.WriteString(fmt.Sprintf("%08x", timestamp&0xffffffff))
	b.WriteString(fmt.Sprintf("%04x", timeNano&0xffff))
	b.WriteString(fmt.Sprintf("%04x", pid&0xffff))
	b.WriteString(fmt.Sprintf("%06x", rand.Int31n(1<<24)))
	b.WriteString("b0") // 末两位标记来源,b0为go

	return b.String()
}
